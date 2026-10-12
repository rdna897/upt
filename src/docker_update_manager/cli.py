from __future__ import annotations
import argparse, difflib, json, os, platform, shutil, signal, sys
from functools import partial
from pathlib import Path
import yaml
from . import __version__
from .component_version import MATCH, UNAVAILABLE, VERSION_MISMATCH_MESSAGE
from .compose import locate_image_source
from .config import Config
from .docker import compose_args, discover, resolve_service
from .lock import Lock
from .models import parse_image_ref
from .compose_namespace import require_mutation_safe
from .operations import do_restart, do_pin, do_pull, do_update, do_rollback, command_preview
from .registry import list_tags, scan_service_with_tracking
from .state import State
from .system import run, CommandError, human_size
from .progress import Reporter, NULL_REPORTER
from .conversion import generate_conversion, deploy_conversion, rollback_conversion, default_stack_path
from . import diskcli
from .diskdiag import fs_metrics, docker_df, container_logs, deleted_open, quick_snapshot
from .retention import inventory as retention_inventory, cleanup as retention_cleanup, rollback_points, canonical_image_id, CleanupState, cleanup_blocker
from .removal import remove_service
from .reconciliation import queue_agent_project_refresh, queue_agent_verification

EXIT_OK, EXIT_UPDATES, EXIT_PARTIAL, EXIT_FATAL = 0,10,20,30
MODIFYING={"update","pull","pin","rollback","restore-compose","restart","cleanup","ignore","unignore","convert","remove"}
ALIASES={"ls":"list","up":"update"}

class Parser(argparse.ArgumentParser):
    def error(self,message): raise ValueError(message)

class Formatter(argparse.RawDescriptionHelpFormatter): pass

COMMANDS={
"scan":"Check running containers for available updates", "list":"List discovered containers and services",
"status":"Show stack/service status", "outdated":"Show services with available updates",
"update":"Update services safely", "pull":"Pull an image without deploying it", "pin":"Pin mutable tags to running versions",
"inspect":"Inspect local and remote image information", "versions":"Show available versions", "rollback":"Roll back an update",
"history":"Show update history", "backups":"Show configuration backups", "restore-compose":"Restore a Compose backup",
"restart":"Restart a service safely", "logs":"Show service logs", "health":"Show container health",
"mutable":"Show mutable image tags", "pinned":"Show pinned images", "compose":"Show Compose source information",
"images":"Show image relationships", "cleanup":"Safely remove unused images", "disk":"Diagnose boot/root disk growth",
"remove":"Remove a container/service and optionally its unused images",
"convert":"Convert a standalone container to reversible Compose management",
"ignore":"Exclude a service", "unignore":"Remove an exclusion", "config":"Manage configuration",
"retention":"Show or clean expired UPT recovery artefacts",
"doctor":"Diagnose the installation", "web":"Manage the authenticated web interface", "help":"Show help"}

EPILOG="""Common workflows:
  Check for updates:       upt scan
  Only show updates:       upt outdated
  Inspect an update:       upt inspect sonarr
  Safely update and pin:   upt update sonarr --pin
  Preview pinning:         upt pin --all --dry-run
  Diagnose installation:  upt doctor
  Recover from an update: upt rollback sonarr

Safety: scans never deploy; modifying commands confirm by default, back up source
configuration, and support --dry-run. Dependencies and volumes are never removed."""

def parser():
    p=Parser(prog="upt",description="Docker Update Manager — safety-first Docker and Compose maintenance",epilog=EPILOG,formatter_class=Formatter)
    p.add_argument("--version",action="version",version=f"%(prog)s {__version__}")
    sp=p.add_subparsers(dest="command",metavar="COMMAND")
    def add(name, desc, epilog=""):
        q=sp.add_parser(name,help=desc,description=desc+"\n\nThis command "+("may modify Docker or files; use --dry-run to preview." if name in MODIFYING else "is read-only."),epilog=epilog,formatter_class=Formatter); return q
    q=add("scan",COMMANDS["scan"],"Example: upt scan --json\nExit: 0 no updates/untracked digests, 10 updates, 20 partial query failure or untracked digest, 30 fatal."); q.add_argument("--json",action="store_true"); progress_options(q,quiet=True)
    add("list",COMMANDS["list"])
    add("status",COMMANDS["status"])
    q=add("outdated",COMMANDS["outdated"]); q.add_argument("--json",action="store_true"); progress_options(q)
    q=add("update",COMMANDS["update"],"Bulk safety: --all and --stack first scan and deploy only UPDATE, DIGEST CHANGED, or PINNED UPDATE services. Digest-pinned services track their recorded tag/channel; UPT pulls the new exact digest, atomically advances the pin with backup and Compose validation, and preserves the old image for rollback.\n\nExamples:\n  upt update sonarr\n  upt update prowlarr --dry-run\n  upt update --stack media --dry-run\n  upt update --all --pin -y"); selection(q); modifying(q); progress_options(q); q.add_argument("--pin",action="store_true"); q.add_argument("--no-health",action="store_true")
    q=add("pull",COMMANDS["pull"],"Pulls but never recreates the running container."); q.add_argument("service"); dry(q); progress_options(q)
    q=add("pin",COMMANDS["pin"],"Uses the running image as source of truth. If version metadata is unavailable, use --digest."); selection(q); modifying(q); progress_options(q); q.add_argument("--digest",action="store_true")
    q=add("inspect",COMMANDS["inspect"]); q.add_argument("service"); progress_options(q)
    q=add("versions",COMMANDS["versions"],"Shows recent relevant Docker Hub tags; channels are not switched."); q.add_argument("service"); q.add_argument("--limit",type=int,default=10); q.add_argument("--all",action="store_true"); progress_options(q)
    q=add("rollback",COMMANDS["rollback"],"Restores recorded Compose sources and recreates only the selected service."); q.add_argument("service"); modifying(q); progress_options(q)
    q=add("history",COMMANDS["history"]); q.add_argument("service",nargs="?"); q.add_argument("--json",action="store_true")
    add("backups",COMMANDS["backups"])
    q=add("restore-compose",COMMANDS["restore-compose"]); q.add_argument("backup",nargs="?"); modifying(q); progress_options(q)
    q=add("restart",COMMANDS["restart"],"Restart only the selected service without dependencies. Namespace owners and consumers are refused, including in dry-run; there is no override."); q.add_argument("service",nargs="?"); q.add_argument("--stack"); modifying(q); progress_options(q)
    q=add("logs",COMMANDS["logs"]); q.add_argument("service"); q.add_argument("--tail",type=int,default=100); q.add_argument("--follow","-f",action="store_true")
    add("health",COMMANDS["health"]); add("mutable",COMMANDS["mutable"]); add("pinned",COMMANDS["pinned"])
    q=add("compose",COMMANDS["compose"]); q.add_argument("service")
    q=add("images",COMMANDS["images"]); progress_options(q)
    q=add("cleanup",COMMANDS["cleanup"],"Only dangling/unreferenced images are candidates; rollback images are protected. Images are matched by full ID and protection is rechecked before each removal. Nothing is removed if the UPT state database is missing or unreadable, or Docker returns an unrecognised image ID."); modifying(q); progress_options(q)
    q=add("remove",COMMANDS["remove"],"Removes one Compose service container or standalone container. Data and configuration are preserved by default. --images also removes eligible images. --purge-data permanently deletes only named volumes, root-filesystem bind paths, and Compose/config sources that UPT can establish are not shared; ambiguous or shared resources are skipped.\n\nExamples:\n  upt remove flaresolverr --dry-run\n  upt remove flaresolverr --images --dry-run\n  upt remove flaresolverr --purge-data --dry-run\n  upt remove flaresolverr --images --purge-data\n\n--purge-data creates no recovery copy and requires typing DELETE SERVICE unless --yes is supplied. Always run the dry-run first."); q.add_argument("service"); q.add_argument("--images",action="store_true",help="also remove unused current and rollback images belonging to SERVICE"); q.add_argument("--purge-data","--data",dest="purge_data",action="store_true",help="permanently delete eligible unshared named volumes, bind data, and Compose/config sources"); modifying(q); progress_options(q)
    q=add("convert",COMMANDS["convert"],"Converted stacks are created under /root/SERVICE-stack by default (configurable with conversion_root). Default conversion pins the exact running digest. --track-tag preserves the original mutable tag for future scans while adoption still uses the running image. --deploy stops and renames the original container but does not delete it.\n\nExamples:\n  upt convert portainer --dry-run\n  upt convert portainer --track-tag --dry-run\n  upt convert portainer --track-tag --deploy\n  upt convert portainer --rollback"); q.add_argument("service"); modifying(q); progress_options(q); q.add_argument("--output",type=Path,help="override the default /root/SERVICE-stack directory"); q.add_argument("--deploy",action="store_true"); q.add_argument("--rollback",action="store_true"); q.add_argument("--replace-files",action="store_true"); q.add_argument("--track-tag",action="store_true",help="preserve the configured tag so future updates can be detected")
    q=add("disk",COMMANDS["disk"],"Actions: diagnose, growth, diff, history, largest, files, docker, containerd, containers, logs, journal, volumes, deleted, inodes, snapshot, watch"); diskcli.configure(q); progress_options(q)
    q=add("ignore",COMMANDS["ignore"]); q.add_argument("service"); dry(q)
    q=add("unignore",COMMANDS["unignore"]); q.add_argument("service"); dry(q)
    q=add("config",COMMANDS["config"]); q.add_argument("action",choices=["show","path","validate"],nargs="?",default="show")
    q=add("retention",COMMANDS["retention"],"Protected images are old local Docker images recorded by UPT during an update so that the previous service version can be restored. UPT does not duplicate the image; it prevents cleanup from removing that existing Docker image during the retention period.\n\nExamples:\n  upt retention\n  upt retention cleanup --dry-run\n  upt retention cleanup --service flaresolverr --override-protection --dry-run\n  upt retention cleanup --service app --stack media --override-protection --dry-run\n  upt retention cleanup --all --dry-run\n\nShowing retention is read-only. Cleanup may remove UPT-owned artefacts or Docker images; use --dry-run to preview. Overrides permanently expire rollback points and require explicit confirmation. Per-service overrides refuse unproven legacy stack identities; --all explicitly targets every unused protected image."); q.description="Show retention state or clean recovery artefacts.\n\nThe default show action is read-only. Protected images are previous Docker images retained by UPT for rollback. The cleanup action may remove data; use --dry-run to preview."; q.add_argument("action",choices=["show","cleanup"],nargs="?",default="show",help="show retention state (default) or clean eligible recovery data"); modifying(q); scope=q.add_mutually_exclusive_group(); scope.add_argument("--service",metavar="SERVICE",help="limit an override to this service; required with --override-protection"); scope.add_argument("--all","-all",dest="all_protected",action="store_true",help="permanently release every rollback-protected image that no container uses"); q.add_argument("--stack",help="qualify SERVICE's Compose identity; legacy rows require trustworthy backup metadata"); q.add_argument("--override-protection",action="store_true",help="expire only identity-scoped SERVICE rollback protection early; unproven legacy history is refused"); progress_options(q)
    q=add("doctor",COMMANDS["doctor"]); progress_options(q)
    q=add("web",COMMANDS["web"],"Actions:\n  bootstrap    Generate a one-time administrator setup code\n  reset-admin  Generate/use a short-lived administrator recovery code\n  status       Check the bounded agent boundary (read-only)\n\nAn authenticated browser may request only a confirmed update of one eligible Compose service. The agent resolves and revalidates the service and runs the existing core update path. No bulk update, arbitrary command, restart, removal, cleanup, or Compose editing endpoint is exposed.")
    q.description = "Manage the authenticated web interface and local administrator bootstrap/recovery state. Browser-triggered updates are limited to one explicitly selected, confirmed, server-revalidated Compose service. Use --dry-run for auth-state previews."
    q.add_argument("action", choices=["bootstrap","reset-admin","status"], nargs="?", default="status")
    q.add_argument("--apply", action="store_true", help="prompt for and use a previously generated recovery code")
    q.add_argument("--dry-run", action="store_true", help="show auth-state action without changing the database")
    add("help",COMMANDS["help"])
    return p

def selection(q): q.add_argument("service",nargs="?"); q.add_argument("--stack"); q.add_argument("--all",action="store_true")
def dry(q): q.add_argument("--dry-run",action="store_true",help="show actions without making changes")
def modifying(q): dry(q); q.add_argument("--yes","-y",action="store_true",help="skip confirmation")
def progress_options(q,quiet=False):
    if quiet: q.add_argument("--quiet","-q",action="store_true",help="suppress routine progress")
    q.add_argument("--progress",action="store_true",help="force progress rendering")
    q.add_argument("--no-progress",action="store_true",help="disable progress rendering")

def print_main_help(p):
    print(p.format_help().rstrip()); print("\nCommands:")
    for name,desc in COMMANDS.items(): print(f"  {name:<17}{desc}")
    print("\nDisk diagnostics:\n  disk diagnose      Deep disk growth diagnosis\n  disk growth        Show recently growing areas\n  disk diff          Compare disk snapshots\n  disk history       Show disk usage history\n  disk largest       Show largest directories\n  disk files         Show largest files\n  disk docker        Analyse Docker disk usage\n  disk containerd    Analyse containerd storage\n  disk containers    Show container writable layers\n  disk logs          Analyse container log usage\n  disk journal       Analyse journal usage\n  disk volumes       Analyse volumes and root bind mounts\n  disk deleted       Find deleted-but-open files\n  disk inodes        Analyse inode usage\n  disk snapshot      Save a disk baseline\n  disk watch         Watch live disk growth")
    print("\nRetention:\n  retention           Show protected rollback images, sizes, usage and expiry\n  retention cleanup   Purge only expired UPT-owned recovery data\n  retention cleanup --service SERVICE --override-protection\n                      Permanently release one service's rollback protection\n  retention cleanup --service SERVICE --stack STACK --override-protection\n                      Qualify the service to its Compose stack / proven legacy history\n  retention cleanup --all --dry-run\n                      Preview releasing every unused protected image\n\n  Protected images are previous local Docker images retained by UPT so an\n  update can be rolled back. They are not extra image copies. Per-service\n  overrides refuse unproven legacy stack identity, and are refused when a\n  container uses the image or another rollback still needs it. --all explicitly\n  targets every unused protected image.")
    print("\nService removal:\n  remove SERVICE                 Remove its container; preserve all data/config\n  remove SERVICE --images        Also remove unused current and rollback images\n  remove SERVICE --purge-data --dry-run\n                                 Preview permanent data/config deletion\n  remove SERVICE --images --purge-data\n                                 Remove runtime, eligible data/config, and images\n\n  --purge-data deletes only resources proven unshared, creates no recovery copy,\n  and requires typing DELETE SERVICE unless --yes is supplied.")
    print("\nWeb interface:\n  web bootstrap             Generate a one-time setup code\n  web reset-admin           Generate a short-lived recovery code\n  web reset-admin --apply\n                             Prompt for recovery code and new password\n  web status                Check the bounded agent boundary\n\nThe authenticated web UI can update only one explicitly selected eligible Compose service after confirmation. The server and privileged agent revalidate it and use the existing core update path. Bulk updates and arbitrary commands are not exposed.\n\n"+EPILOG)

def services(cfg): return discover(cfg)
def choose(items,args):
    if args.all: return items
    if args.stack:
        out=[s for s in items if s.stack==args.stack]
        if not out: raise ValueError(f"Unknown stack: {args.stack}")
        return out
    if args.service: return [resolve_service(items,args.service)]
    raise ValueError("specify SERVICE, --stack STACK, or --all")

def actionable_updates(items,state,reporter=NULL_REPORTER):
    """Registry-preflight bulk targets; only confirmed updates are deployable."""
    accepted=[]; results=[]
    reporter.start("preflight",f"Checking {len(items)} selected service(s) before update",total=len(items))
    for i,s in enumerate(items,1):
        with reporter.task("Checking whether an update is actually available",service=s.key): result=scan_service_with_tracking(s,state)
        results.append(result)
        if result.status in {"UPDATE","DIGEST CHANGED","PINNED UPDATE"} and s.stack and not s.local_build: accepted.append(s)
        reporter.advance(i,len(items),s.key,result.status)
    reporter.finish(f"Preflight complete: {len(accepted)} update(s), {len(items)-len(accepted)} skipped")
    return accepted,results
def short(x): return x[:19] if x else "unknown"
def table(rows,headers):
    widths=[len(x) for x in headers]
    for row in rows:
        for i,x in enumerate(row): widths[i]=min(48,max(widths[i],len(str(x))))
    print("  ".join(h.ljust(widths[i]) for i,h in enumerate(headers)))
    print("  ".join("-"*w for w in widths))
    for row in rows: print("  ".join(str(x)[:widths[i]].ljust(widths[i]) for i,x in enumerate(row)))

def dashboard(cfg,state,reporter=NULL_REPORTER):
    reporter.start("dashboard","Discovering Docker host")
    with reporter.task("Inspecting containers, images, and Compose labels"): ss=services(cfg)
    stacks={s.stack for s in ss if s.stack}; mutable=sum(parse_image_ref(s.image).mutable and not s.local_build for s in ss)
    healthy=sum(s.state=="running" and s.health not in {"unhealthy","starting"} for s in ss)
    try: run(["docker","system","df"]); images="available"
    except Exception: images="unknown"
    reporter.finish("Dashboard discovery complete")
    print("Docker Update Manager\n"+"─"*40+f"\n\nHost\n  Architecture: {platform.machine()}\n  Containers:   {len(ss)} running\n  Stacks:       {len(stacks)}\n  Docker usage: {images}\n\nMutable tags\n  {mutable} services use mutable tags\n\nHealth\n  {healthy} healthy/running\n  {len(ss)-healthy} require attention\n\nRollback\n  {len(state.protected())} protected images\n\nNo changes have been made.\n\nCommands\n  upt scan\n  upt outdated\n  upt pin --all --dry-run\n  upt inspect SERVICE")

def scan(cfg,state,json_out=False,quiet=False,outdated=False,reporter=NULL_REPORTER,return_results=False):
    found=services(cfg); results=[]; reporter.start("scan",f"Checking {len(found)} services for updates",total=len(found))
    for i,s in enumerate(found,1):
        with reporter.task("Checking registry and comparing digest",service=s.key): r=scan_service_with_tracking(s,state)
        results.append(r); reporter.advance(i,len(found),s.key,r.status)
    wanted=[r for r in results if not outdated or r.status in {"UPDATE","DIGEST CHANGED","PINNED UPDATE"}]
    counts={k:sum(r.status==k for r in results) for k in {r.status for r in results}}
    untracked=counts.get("UNTRACKED DIGEST",0)
    payload={"updates":counts.get("UPDATE",0)+counts.get("DIGEST CHANGED",0)+counts.get("PINNED UPDATE",0),"current":counts.get("CURRENT",0)+counts.get("PINNED",0),"unknown":counts.get("UNKNOWN",0)+counts.get("REGISTRY ERROR",0),"untracked":untracked,"services":[r.as_dict() for r in wanted]}
    reporter.finish(f"Scan complete: {payload['updates']} updates, {payload['unknown']} failed/unknown, {untracked} untracked digest pin(s)")
    if json_out: print(json.dumps(payload,indent=2))
    elif not quiet: table([(r.service.stack or "standalone",r.service.key,r.service.version or parse_image_ref(r.service.image).tag,r.remote_version or short(r.remote_digest),r.status) for r in wanted],["STACK","SERVICE","CURRENT","AVAILABLE","STATUS"])
    code=EXIT_PARTIAL if any(r.status in {"REGISTRY ERROR","UNKNOWN","UNTRACKED DIGEST"} for r in results) else (EXIT_UPDATES if payload["updates"] else EXIT_OK)
    return (code,results) if return_results else code

def interactive_selector(results,cfg,state,reporter):
    candidates=[r for r in results if r.status in {"UPDATE","DIGEST CHANGED"} and r.service.stack]
    if not candidates:
        print("\nNo deployable Compose updates are currently available."); return
    while True:
        print(f"\n{len(candidates)} updates available.\n")
        for i,r in enumerate(candidates,1):
            old=r.service.version or parse_image_ref(r.service.image).tag
            new=r.remote_version or ("same tag [digest changed]" if r.status=="DIGEST CHANGED" else short(r.remote_digest))
            print(f"[{i}] {r.service.key:<20} {old} -> {new}")
        print("\nChoose:\n  1-N   Update one\n  a     Update all listed\n  s     Select multiple\n  d     Details\n  v     Available versions\n  q     Quit")
        choice=reporter.prompt("\nSelection: ").strip().lower()
        if choice in {"q","quit",""}: print("No updates performed."); return
        if choice in {"d","v"}:
            raw=reporter.prompt("Service number: ").strip()
            if not raw.isdigit() or not 1<=int(raw)<=len(candidates): print("Invalid selection."); continue
            r=candidates[int(raw)-1]; s=r.service
            if choice=="d": print(f"\n{s.key}\n  Current: {s.version or s.image}\n  Running digest: {s.digest or 'unknown'}\n  Remote digest:  {r.remote_digest or 'unknown'}\n  Status:         {r.status}")
            else:
                with reporter.task("Fetching available tags",service=s.key): tags=list_tags(s.image,10)
                print("\n"+("\n".join("  "+x for x in tags) if tags else "  Tag listing unavailable for this registry."))
            continue
        if choice=="a": selected=candidates
        elif choice=="s":
            raw=reporter.prompt("Numbers (for example 1,3,5): ")
            try: indexes=sorted({int(x.strip()) for x in raw.split(",")}); selected=[candidates[i-1] for i in indexes if 1<=i<=len(candidates)]
            except ValueError: selected=[]
            if not selected: print("Invalid selection."); continue
        elif choice.isdigit() and 1<=int(choice)<=len(candidates): selected=[candidates[int(choice)-1]]
        else: print("Invalid selection."); continue
        names=", ".join(r.service.key for r in selected)
        if reporter.prompt(f"\nUpdate {names}? [y/N] ").strip().lower() not in {"y","yes"}: print("Cancelled; no updates performed."); continue
        reporter.start("update",f"Updating {len(selected)} selected service(s)",total=len(selected))
        succeeded=failed=0
        state.ensure_compatible()
        with Lock(state.root/"update.lock"):
            for i,r in enumerate(selected,1):
                try:
                    do_update(r.service,state,yes=True,health_timeout=int(cfg.data.get("health_timeout",90)),reporter=reporter,post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True),post_project_change=partial(queue_agent_project_refresh, state=state))
                    succeeded+=1; reporter.advance(i,len(selected),r.service.key,"updated")
                except Exception as exc:
                    failed+=1; reporter.warning(str(exc),r.service.key); reporter.advance(i,len(selected),r.service.key,"failed")
                    if len(selected)==1: break
        reporter.finish(f"Interactive update complete: {succeeded} successful, {failed} failed")
        return

def config_edit(cfg,name,remove=False,dry_run=False):
    data=dict(cfg.data); ex=dict(data.get("exclude",{})); vals=list(ex.get("services",[]))
    vals=[v for v in vals if v!=name] if remove else sorted(set(vals+[name])); ex["services"]=vals; data["exclude"]=ex
    text=yaml.safe_dump(data,sort_keys=False)
    print(("Would remove" if remove else "Would add")+f" service exclusion: {name}")
    if dry_run: return
    cfg.path.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
    tmp=cfg.path.with_suffix(".tmp"); tmp.write_text(text); os.chmod(tmp,0o600); os.replace(tmp,cfg.path)

def execute(args,p,cfg,state,reporter=NULL_REPORTER):
    cmd=ALIASES.get(args.command,args.command)
    if cmd in (None,):
        dashboard(cfg,state,reporter)
        if reporter.tty and sys.stdin.isatty():
            answer=reporter.prompt("\nCheck registries and choose updates now? [y/N] ").strip().lower()
            if answer in {"y","yes"}:
                code,results=scan(cfg,state,reporter=reporter,return_results=True)
                interactive_selector(results,cfg,state,reporter)
                return code
        return 0
    if cmd=="help": print_main_help(p); return 0
    if cmd=="scan":
        if reporter.tty and sys.stdin.isatty() and not args.json and not args.quiet:
            code,results=scan(cfg,state,args.json,args.quiet,reporter=reporter,return_results=True)
            if code==EXIT_UPDATES and reporter.prompt("\nOpen interactive update selector? [y/N] ").strip().lower() in {"y","yes"}: interactive_selector(results,cfg,state,reporter)
            return code
        return scan(cfg,state,args.json,args.quiet,reporter=reporter)
    if cmd=="outdated": return scan(cfg,state,args.json,False,True,reporter=reporter)
    ss=None
    if cmd not in {"history","backups","restore-compose","disk","images","cleanup","config","doctor","retention","web"}: ss=discover(cfg,all_containers=True) if cmd=="remove" else services(cfg)
    if cmd=="web":
        from .webcli import web_command
        return web_command(cfg, args)
    if cmd=="list": table([(s.stack or "standalone",s.key,s.image,s.state,"yes" if s.ignored else "no") for s in ss],["STACK","SERVICE","IMAGE","STATE","IGNORED"])
    elif cmd=="status": table([(s.stack or "standalone",s.key,s.state,s.health,s.version or parse_image_ref(s.image).tag) for s in ss],["STACK","SERVICE","STATE","HEALTH","VERSION"])
    elif cmd=="health": table([(s.stack or "standalone",s.key,s.state,s.health if s.health!="none" else "no healthcheck") for s in ss],["STACK","SERVICE","STATE","HEALTH"])
    elif cmd in {"mutable","pinned"}:
        selected=[s for s in ss if ((parse_image_ref(s.image).mutable and not s.local_build) if cmd=="mutable" else (not parse_image_ref(s.image).mutable and not s.local_build))]
        table([(s.stack or "standalone",s.key,s.image,parse_image_ref(s.image).pin_type,s.version or "unknown") for s in selected],["STACK","SERVICE","IMAGE","TYPE","RUNNING VERSION"])
    elif cmd=="inspect":
        s=resolve_service(ss,args.service); reporter.start("inspect",f"Inspecting {s.key}")
        with reporter.task("Querying registry and comparing image metadata",service=s.key): r=scan_service_with_tracking(s,state)
        reporter.finish(f"Inspection complete for {s.key}")
        print(f"Service: {s.key}\nStack: {s.stack or 'standalone'}\n\nRepository: {parse_image_ref(s.image).registry}/{parse_image_ref(s.image).repository}\nCompose: {s.image}\n\nRunning:\n  Version: {s.version or 'unknown'}\n  Image ID: {s.image_id}\n  Digest: {s.digest or 'unknown'}\n  Created: {s.created or 'unknown'}\n  Architecture: {s.architecture or 'unknown'}\n\nRemote:\n  Version: {r.remote_version or 'unknown'}\n  Digest: {r.remote_digest or 'unknown'}\n  Created: {r.remote_created or 'unknown'}\n\nStatus: {r.status}\nCompose source: {', '.join(s.compose_files) or 'standalone'}")
    elif cmd=="versions":
        s=resolve_service(ss,args.service); reporter.start("versions",f"Resolving available versions for {s.key}")
        reporter.stage(1,4,"Repository identified",service=s.key)
        reporter.stage(2,4,"Registry authentication delegated to Docker/registry",service=s.key)
        with reporter.task("Fetching tags",service=s.key): tags=list_tags(s.image,100 if args.all else args.limit)
        reporter.stage(3,4,"Fetch tags",service=s.key); reporter.stage(4,4,"Filter and sort current channel",service=s.key); reporter.finish(f"Version lookup complete for {s.key}")
        print(f"{s.key}\n\nRunning: {s.version or parse_image_ref(s.image).tag}\n\nAvailable:")
        print("\n".join("  "+t for t in tags) if tags else "  Registry tag listing is not available for this registry; no versions guessed.")
    elif cmd=="compose":
        s=resolve_service(ss,args.service)
        try: src,expr=locate_image_source(s)
        except ValueError as e: src,expr="unknown",str(e)
        var="unknown"; import re
        m=re.search(r"\$\{([A-Za-z_][A-Za-z0-9_]*)",expr); var=m.group(1) if m else "none"
        print(f"Project: {s.stack or 'standalone'}\nService: {s.key}\nWorking directory: {s.working_dir or 'none'}\nCompose files: {', '.join(s.compose_files) or 'none'}\nImage source: {src}\nImage expression: {expr}\n.env variable: {var}\nResolved/running image: {s.image}")
    elif cmd=="logs":
        s=resolve_service(ss,args.service); a=compose_args(s)+["logs","--tail",str(args.tail)]+(["--follow"] if args.follow else [])+[s.key]; os.execvp(a[0],a)
    elif cmd in {"update","pin"}:
        targets=choose(ss,args)
        if cmd=="update" and (args.all or args.stack):
            targets,preflight=actionable_updates(targets,state,reporter)
            print("\nPreflight results:")
            for result in preflight:
                marker="✓" if result.service in targets else "-"
                print(f"  {marker} {result.service.key:<22} {result.status}")
            if not targets:
                print("\nNo updates are available for the selected services. Nothing will be pulled or recreated.")
                return 0
        if cmd=="pin" and (args.all or args.stack):
            original=len(targets); targets=[s for s in targets if parse_image_ref(s.image).mutable and not s.local_build]
            print(f"Pin candidates: {len(targets)} mutable registry image(s); {original-len(targets)} fixed/local image(s) skipped.")
            if not targets: return 0
        reporter.start(cmd,f"{'Updating' if cmd=='update' else 'Pinning'} {len(targets)} service(s)",total=len(targets))
        succeeded=failed=skipped=0
        for index,s in enumerate(targets,1):
            if not s.stack:
                skipped+=1; reporter.warning("Standalone container skipped: original run specification unavailable",s.key); reporter.advance(index,len(targets),s.key,"skipped"); continue
            if s.local_build:
                skipped+=1; reporter.warning("Local build skipped",s.key); reporter.advance(index,len(targets),s.key,"skipped"); continue
            try:
                if cmd=="update": do_update(s,state,dry_run=args.dry_run,yes=args.yes,no_health=args.no_health,pin=args.pin,health_timeout=int(cfg.data.get("health_timeout",90)),reporter=reporter,post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True),post_project_change=partial(queue_agent_project_refresh, state=state))
                else: do_pin(s,state,digest=args.digest,dry_run=args.dry_run,yes=args.yes,reporter=reporter,post_mutation=partial(queue_agent_verification,state=state),reconcile_discover=lambda: discover(cfg,all_containers=True),post_project_change=partial(queue_agent_project_refresh,state=state))
                succeeded+=1; reporter.advance(index,len(targets),s.key,"complete")
            except Exception as exc:
                failed+=1; reporter.warning(str(exc),s.key); reporter.advance(index,len(targets),s.key,"failed")
                if len(targets)==1: raise
        reporter.finish(f"{cmd.title()} complete: {succeeded} successful, {skipped} skipped, {failed} failed")
    elif cmd=="pull":
        s=resolve_service(ss,args.service); state.assert_service_unfenced(s); reporter.start("pull",f"Pulling {s.key}"); do_pull(s,args.dry_run,reporter,state=state); reporter.finish(f"Pull complete for {s.key}")
    elif cmd=="rollback":
        s=resolve_service(ss,args.service); reporter.start("rollback",f"Rolling back {s.key}"); do_rollback(s,state,dry_run=args.dry_run,yes=args.yes,reporter=reporter,post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True),post_project_change=partial(queue_agent_project_refresh, state=state)); reporter.finish(f"Rollback complete for {s.key}")
    elif cmd=="remove":
        s=resolve_service(ss,args.service); reporter.start("remove",f"Preparing removal of {s.key}")
        result=remove_service(s,state,images=args.images,purge_data=args.purge_data,dry_run=args.dry_run,yes=args.yes,reporter=reporter,post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True))
        reporter.finish("Removal preview complete" if args.dry_run else ("Removal complete" if result.get("removed") else "Removal cancelled"))
    elif cmd=="restart":
        targets=[s for s in ss if s.stack==args.stack] if args.stack else [resolve_service(ss,args.service)]
        if args.stack and not args.yes and not args.dry_run and input(f"Restart {len(targets)} services in {args.stack}? [y/N] ").lower() not in {"y","yes"}: return 0
        reporter.start("restart",f"Restarting {len(targets)} service(s)",total=len(targets))
        # Refuse the whole selection before restarting any member.
        for s in targets:
            require_mutation_safe(s)
        for i,s in enumerate(targets,1):
            do_restart(s, state=state, dry_run=args.dry_run, reporter=reporter,post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True))
            reporter.advance(i,len(targets),s.key,"planned" if args.dry_run else "restarted")
        reporter.finish("Restart dry run complete" if args.dry_run else "Restart complete")
    elif cmd=="history":
        rows=state.history(args.service)
        points={p["history_id"]:p for p in rollback_points(cfg,state)}
        if args.json:
            for r in rows: r["rollback_status"]=r.get("rollback_result") or points.get(r["id"],{}).get("status")
            print(json.dumps(rows,indent=2))
        else:
            table([(r["timestamp"],r.get("stack") or "standalone",r["service"],r["action"],r["old_version"] or short(r["old_digest"]),r["new_version"] or short(r["new_digest"]),r["result"],r.get("rollback_result") or points.get(r["id"],{}).get("status") or "-") for r in rows],["DATE","STACK","SERVICE","ACTION","OLD","NEW","RESULT","ROLLBACK"])
    elif cmd=="backups":
        root=state.root/"backups"; rows=[]
        for d in sorted(root.glob("*"),reverse=True) if root.exists() else []:
            try: meta=json.loads((d/"metadata.json").read_text()); rows.append((d.name,meta.get("stack"),meta.get("service"),len(meta.get("files",[]))))
            except Exception: rows.append((d.name,"unknown","unknown","?"))
        table(rows,["BACKUP","STACK","SERVICE","FILES"])
    elif cmd=="restore-compose": restore(state,args,reporter)
    elif cmd=="disk": return diskcli.handle(args,cfg,state,reporter)
    elif cmd=="images":
        reporter.start("images","Resolving Docker image relationships")
        with reporter.task("Inspecting local and rollback-protected images"): image_report(state)
        reporter.finish("Image analysis complete")
    elif cmd=="cleanup": cleanup(state,args,reporter)
    elif cmd=="convert":
        if args.deploy and args.rollback: raise ValueError("--deploy and --rollback are mutually exclusive")
        if args.rollback:
            if args.dry_run: raise ValueError("conversion rollback preview is not yet available; omit --dry-run or inspect history first")
            rollback_conversion(args.service,state,yes=args.yes,reporter=reporter,post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True))
        else:
            s=resolve_service(ss,args.service)
            if s.stack: raise ValueError(f"{s.key} is already managed by Compose")
            output=args.output or default_stack_path(s.name,cfg.data.get("conversion_root","/root"))
            generated=generate_conversion(s,state,output,dry_run=args.dry_run,replace_files=args.replace_files,yes=args.yes,track_tag=args.track_tag,reporter=reporter)
            if generated is None: return 0
            compose_path,summary,raw=generated
            if args.deploy:
                deploy_conversion(s,state,output,summary,raw,yes=args.yes,reporter=reporter,health_timeout=int(cfg.data.get("health_timeout",90)),post_mutation=partial(queue_agent_verification, state=state),reconcile_discover=lambda: discover(cfg,all_containers=True))
            elif not args.dry_run:
                reporter.stage(5,5,"Deployment not requested", "pending",s.name); reporter.finish("Conversion files generated and validated")
                track=" --track-tag" if summary.get("track_tag") else ""
                print(f"\nGenerated: {compose_path}\nNo container was changed. Review, then run:\n  upt convert {s.name}{track} --deploy --replace-files")
    elif cmd in {"ignore","unignore"}: config_edit(cfg,args.service,cmd=="unignore",args.dry_run)
    elif cmd=="config":
        if args.action=="path": print(cfg.path)
        elif args.action=="show": print(yaml.safe_dump(cfg.redacted(),sort_keys=False).rstrip())
        else: print(f"Configuration OK: {cfg.path}")
    elif cmd=="retention":
        if args.action=="cleanup":
            if args.stack and (not args.service or args.all_protected): raise ValueError("--stack requires --service and cannot be combined with --all")
            if args.override_protection and not args.service and not args.all_protected: raise ValueError("--override-protection requires --service SERVICE or --all")
            if args.dry_run: result=retention_cleanup(cfg,state,dry_run=True,reporter=reporter,service=args.service,stack=args.stack,override_protection=args.override_protection,all_protected=args.all_protected)
            else:
                if args.all_protected: prompt="Permanently expire ALL rollback protection and remove every unused protected image? [y/N] "
                elif args.override_protection: prompt=f"Permanently expire rollback protection for {(args.stack + '/' if args.stack else '')}{args.service} and remove its unused image? [y/N] "
                else: prompt="Purge expired UPT-owned recovery artefacts? [y/N] "
                if not args.yes and reporter.prompt(prompt).strip().lower() not in {"y","yes"}: print("Cancelled."); return 0
                state.ensure_compatible()
                with Lock(state.root/"update.lock"): result=retention_cleanup(cfg,state,reporter=reporter,service=args.service,stack=args.stack,override_protection=args.override_protection,all_protected=args.all_protected)
            print_retention(cfg,state,result)
            if result.get("failures"): return EXIT_PARTIAL
        else:
            if args.service or args.stack or args.all_protected or args.override_protection or args.dry_run: raise ValueError("cleanup options require: upt retention cleanup")
            print_retention(cfg,state)
    elif cmd=="doctor": return doctor(cfg,state,reporter)
    return 0

def restore(state,args,reporter=NULL_REPORTER):
    reporter.start("restore", "Preparing Compose backup restoration")
    root=state.root/"backups"; choices=sorted(root.glob("*"),reverse=True) if root.exists() else []
    if not choices: raise ValueError("no backups exist")
    d=Path(args.backup) if args.backup else choices[0]
    if not d.is_absolute(): d=root/d
    meta=json.loads((d/"metadata.json").read_text()); print(f"Backup: {d}")
    for x in meta["files"]: print(f"  {x['backup']} -> {x['source']}")
    if args.dry_run: reporter.stage(1,3,"Read backup metadata"); reporter.stage(2,3,"Back up current files (not executed)","pending"); reporter.stage(3,3,"Restore files (not executed)","pending"); reporter.finish("Restore dry run complete"); print("DRY RUN — no files restored."); return
    if not args.yes and input("Restore these files? [y/N] ").lower() not in {"y","yes"}: return
    from .compose import atomic_write,backup_files
    # Preserve current state as a new recovery backup before overwrite.
    class S: stack=meta.get("stack"); key=meta.get("service")
    current=[Path(x["source"]) for x in meta["files"] if Path(x["source"]).exists()]
    with reporter.task("Back up current configuration"): backup_files(current,state.root,S)
    for i,x in enumerate(meta["files"],1):
        with reporter.task(f"Restore {Path(x['source']).name}"): atomic_write(x["source"],Path(x["backup"]).read_text())
    reporter.finish("Restore complete")
    print("Files restored. Run 'docker compose config' for the project before deployment.")

def image_report(state):
    data=[json.loads(x) for x in run(["docker","image","ls","--no-trunc","--format","{{json .}}"] ).splitlines() if x]; protected=state.protected()
    table([(x.get("Repository"),x.get("Tag"),short(x.get("ID")),"ROLLBACK PROTECTED" if x.get("ID") in protected else "local") for x in data],["REPOSITORY","TAG","IMAGE ID","RELATION"])

def cleanup(state,args,reporter=NULL_REPORTER):
    pinned=getattr(args,"cleanup_state",None)
    if pinned is None:
        with CleanupState(state) as pinned: return _cleanup(pinned,args,reporter)
    return _cleanup(pinned,args,reporter)

def _cleanup(pinned,args,reporter):
    reporter.start("cleanup","Analysing Docker storage")
    # Full IDs only: abbreviated IDs never match stored protection (issue #17).
    listed=run(["docker","image","ls","-q","--no-trunc","--filter","dangling=true"]).split()
    invalid=[x for x in dict.fromkeys(listed) if canonical_image_id(x) is None]
    dangling=list(dict.fromkeys(x for x in map(canonical_image_id,listed) if x))
    protection=pinned.protection()
    protected=[(x,r) for x in dangling if (r:=cleanup_blocker(protection,x))]
    candidates=[x for x in dangling if not cleanup_blocker(protection,x)]
    print(f"Dangling image candidates: {len(candidates)}\nProtected rollback images: {len(protected)}\nInvalid image identities: {len(invalid)}")
    for x in candidates: print("  "+x)
    if protected: print("Protected (not removed):")
    for x,reason in protected: print(f"  {x}  {reason}")
    if invalid: print("Invalid (not removed):")
    for x in invalid: print("  "+x)
    if invalid:
        # Output Docker did not identify exactly cannot prove any listing safe.
        raise RuntimeError(f"Docker returned {len(invalid)} unrecognised image identity(ies); refusing to remove any image")
    if args.dry_run: reporter.finish("Cleanup analysis complete"); print("DRY RUN — no images removed."); return
    if not candidates: reporter.finish("Cleanup complete: nothing eligible"); return
    if not args.yes and input("Remove these unprotected dangling images? [y/N] ").lower() not in {"y","yes"}: return
    removed=0; skipped=[]
    try:
        for i,image in enumerate(candidates,1):
            # Fresh short read before each removal; no SQLite transaction spans Docker.
            reason=cleanup_blocker(pinned.protection(),image)
            if reason:
                skipped.append(image); reporter.warning("SKIPPED - "+reason,short(image)); print(f"  skipped {image}: {reason}")
                reporter.advance(i,len(candidates),short(image),"skipped"); continue
            with reporter.task("Removing image",service=short(image)): run(["docker","image","rm",image])
            removed+=1; reporter.advance(i,len(candidates),short(image),"removed")
    finally:
        print(f"Removed {removed} images."+(f" Skipped {len(skipped)} newly protected image(s)." if skipped else ""))
    reporter.finish(f"Cleanup complete: removed {removed} images")

def doctor(cfg,state,reporter=NULL_REPORTER):
    reporter.start("doctor","Diagnosing Docker Update Manager",total=19)
    checks=[]
    def check(name,fn):
        try:
            val=fn(); checks.append((name,val if str(val).startswith("WARNING") else "OK"+(f" - {val}" if val else "")))
        except Exception as e: checks.append((name,"FAIL - "+str(e)))
        reporter.advance(len(checks),19,name,checks[-1][1].split(" - ",1)[0])
    check("UPT version",lambda: __version__)
    # Read-only running-agent agreement. This CLI cannot see which code a
    # long-running upt-web executes; `upt web status`/Settings cover that.
    versions={}
    def agent_version():
        from .webcli import running_agent_versions
        versions.update(running_agent_versions())
        if versions["status"]==UNAVAILABLE: return "WARNING - agent unavailable"
        if versions["agent"] is None: raise RuntimeError("unknown (agent reported no valid version)")
        if versions["status"]!=MATCH: raise RuntimeError(f"{versions['agent']} (installed {__version__})")
        return versions["agent"]
    def version_agreement_check():
        if not versions: raise RuntimeError("not checked")
        if versions["status"]==MATCH: return "versions match"
        if versions["status"]==UNAVAILABLE: return "WARNING - not checked (agent unavailable)"
        raise RuntimeError(VERSION_MISMATCH_MESSAGE)
    check("Agent version",agent_version)
    check("Version agreement",version_agreement_check)
    check("Docker daemon",lambda: run(["docker","info","--format","{{.ServerVersion}}"]).strip())
    check("Docker Compose",lambda: run(["docker","compose","version","--short"]).strip())
    check("Docker socket",lambda: "accessible" if os.access("/var/run/docker.sock",os.R_OK|os.W_OK) else (_ for _ in ()).throw(RuntimeError("not accessible")))
    check("Compose discovery",lambda: f"{len({s.stack for s in discover(cfg) if s.stack})} projects")
    check("Architecture",platform.machine)
    free=shutil.disk_usage("/").free
    check("Disk space",lambda: ("WARNING - " if free<1024**3 else "")+human_size(free)+" free")
    check("State database",lambda: str(state.db_path) if state.db_path.exists() else f"ready ({state.root.parent} writable: {os.access(state.root.parent, os.W_OK)})")
    check("Backup directory",lambda: str(state.root/"backups"))
    check("Configuration",lambda: str(cfg.path)+( " (defaults)" if not cfg.path.exists() else ""))
    f=fs_metrics(); check("Root filesystem",lambda: ("WARNING - " if f["usage_pct"]>=90 or f["available"]<1024**3 else "")+f"{human_size(f['available'])} free, {f['usage_pct']}% used")
    check("Inodes",lambda: ("WARNING - " if f["inodes_pct"]>=90 else "")+f"{f['inodes_pct']}% used")
    d=docker_df(); check("Docker storage",lambda: human_size(d["images"]+d["containers"]+d["volumes"]+d["build_cache"]))
    logs=sum(x["size"] for x in container_logs()); check("Container logs",lambda: ("WARNING - " if logs>=1024**3 else "")+human_size(logs))
    days=cfg.data.get("retention",{}).get("recovery_days",7); check("Rollback retention",lambda: f"{days} days")
    deleted=deleted_open(); check("Deleted open files",lambda: "lsof unavailable" if not deleted["available"] else ("WARNING - " if deleted["total"]>=1024**3 else "")+human_size(deleted["total"]))
    baseline=state.disk_snapshots(limit=1); check("Disk growth baseline",lambda: "available" if baseline else "not established - run disk snapshot")
    reporter.finish("Doctor complete"); table(checks,["CHECK","RESULT"]); return 0 if not any(x[1].startswith("FAIL") for x in checks) else EXIT_PARTIAL

def print_retention(cfg,state,result=None):
    inv=retention_inventory(cfg,state,image_details=True); s=inv["settings"]; points=inv["rollback_images"]
    recoverable=[p for p in points if p.get("status") not in {"PURGED","ALREADY ABSENT"}]
    print("UPT Retention\n"+"─"*40+f"\n\nCompose backups:      {s['compose_backups_days']} days\nRollback images:      {s['rollback_images_days']} days\nOperational logs:     {s['operational_logs_days']} days\nTemporary files:      {s['temporary_files_days']} days\nDisk trend metadata:  {s['disk_history_days']} days\nAudit history:        {s['audit_history_days']} days\nResolved rollback metadata: {s['resolved_rollback_metadata_days']} days")
    print(f"\nCurrent recoverable data\n  Artefacts:          {len(inv['artifacts'])}\n  Recoverable rollback refs:{len(recoverable):>4}\n  Resolved metadata:  {len(points)-len(recoverable):>5}\n  Managed file size:  {human_size(inv['total_size'])}\n  Expired file size:  {human_size(inv['expired_size'])}\n  Expiring within 24h:{human_size(inv['expiring_24h_size']):>10}")
    if points:
        unique={p["image_id"]:p for p in recoverable}; known=sum((p.get("unique_size") or 0) for p in unique.values()); reclaim=sum((p.get("potential_reclaimable") or 0) for p in unique.values())
        print(f"  Protected image size:{human_size(known):>10}\n  Potential reclaim:   {human_size(reclaim):>10}")
        print("\nRollback Points")
        rows=[]
        for p in points:
            image=str(p.get("image") or p["image_id"])
            rows.append((p.get("stack") or "standalone",p.get("service") or "-",image,human_size(p["unique_size"]) if p.get("unique_size") is not None else "unknown",
                         human_size(p.get("potential_reclaimable",0)),str(p["expires"])[:16].replace("T"," "),p["status"],p.get("containers") if p.get("containers") is not None else "?"))
        table(rows,["STACK","SERVICE","IMAGE","UNIQUE SIZE","RECLAIMABLE","EXPIRES","STATUS","CONTAINERS"])
    if result:
        if result.get("planned_images"):
            print("\nPlanned rollback image actions")
            for item in result["planned_images"]: print(f"  {item.get('service') or '-':<20} {item['image']:<48} {human_size(item.get('reclaimable',0)):>10}  {item.get('action','REMOVE')}")
            print(f"\nEstimated reclaimable: {human_size(sum(x.get('reclaimable',0) for x in result['planned_images']))}")
        if result.get("skipped"):
            print("\nSkipped protected images")
            for item in result["skipped"]:
                target=item.get("image") or item.get("path") or "-"
                print(f"  {str(target)[:30]:<30} {item.get('reason','SKIPPED')}")
        database=result.get("database",{})
        print(f"\n{'DRY RUN — no changes made' if result.get('dry_run') else 'Cleanup result'}\n  Expired references: {result.get('expired_images',0)}\n  Unique images:      {result.get('unique_images',0)}\n  Removed artefacts:  {result.get('files_removed',0)}/{result.get('expired_files',0)}\n  Removed images:     {result.get('images_removed',0)}\n  Already absent:     {result.get('images_absent',0)}\n  Reclaimed:          {human_size(result.get('reclaimed',0))}\n  Safety skips:       {len(result.get('skipped',[]))-len(result.get('failures',[]))}\n  Failures:           {len(result.get('failures',[]))}\n  DB rows pruned:     {database.get('rows_pruned',0)}\n  DB compacted:       {'yes' if database.get('compacted') else 'no'}")

def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ALIASES: argv[0]=ALIASES[argv[0]]
    p=parser()
    if argv in (["-h"],["--help"]): print_main_help(p); return 0
    if not argv: args=p.parse_args([])
    elif argv[0]=="help" and len(argv)>1: argv=[argv[1],"--help"]
    elif argv[0] not in COMMANDS and argv[0] not in {"-h","--help","--version"}:
        hint=difflib.get_close_matches(argv[0],COMMANDS,n=1)
        print(f"Unknown command: {argv[0]}"+(f"\n\nDid you mean:\n  {hint[0]}\n\nRun:\n  upt {hint[0]} --help" if hint else "\n\nRun: upt --help"),file=sys.stderr); return EXIT_FATAL
    old_term=signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        args=p.parse_args(argv)
        if argv and argv[0] in {"-h","--help"}: print_main_help(p); return 0
        # Cleanup must never create or initialise state: an empty database would
        # report no rollback protection, on this run or a retry.
        cfg=Config(); state=State(cfg.state_dir,require_existing=args.command=="cleanup")
        json_mode=bool(getattr(args,"json",False)); quiet=bool(getattr(args,"quiet",False))
        enabled=not bool(getattr(args,"no_progress",False)) and not quiet and not json_mode
        force=True if bool(getattr(args,"progress",False)) else None
        reporter=Reporter(enabled=enabled,force=force,stream=(sys.stderr if json_mode else sys.stdout))
        if args.command=="cleanup":
            # Pin existing state first: ensure_compatible would create or
            # initialise an empty database, hiding lost protection.
            args.cleanup_state=CleanupState(state); state.ensure_compatible()
            args.cleanup_state.protection()  # refuse before the lock, snapshots or Docker
        if args.command in MODIFYING and not bool(getattr(args,"dry_run",False)):
            # Before the lock, snapshots, backups or any Docker/source mutation.
            state.ensure_compatible()
            with Lock(state.root/"update.lock"):
                significant=args.command in {"update","pull","cleanup","rollback","remove"}
                if significant: quick_snapshot(state,kind=f"before-{args.command}",reporter=NULL_REPORTER)
                result=execute(args,p,cfg,state,reporter)
                if significant: quick_snapshot(state,kind=f"after-{args.command}",reporter=NULL_REPORTER)
                retained=retention_cleanup(cfg,state,reporter=NULL_REPORTER,automatic=True)
                if retained.get("files_removed") or retained.get("images_removed") or retained.get("images_absent"):
                    print(f"\nRetention cleanup: {retained['files_removed']} artefact(s), {retained['images_removed']} image(s), {retained.get('images_absent',0)} absent image(s) reconciled, {human_size(retained['reclaimed'])} reclaimed.")
                if retained.get("failures"):
                    print(f"Warning: automatic retention cleanup had {len(retained['failures'])} genuine failure(s); run `upt retention cleanup` for details.",file=sys.stderr)
                return result
        return execute(args,p,cfg,state,reporter)
    except KeyboardInterrupt: print("\nInterrupted safely; completed backups were preserved.",file=sys.stderr); return 130
    except (ValueError,RuntimeError,CommandError,yaml.YAMLError) as e: print(f"Error: {e}",file=sys.stderr); return EXIT_FATAL
    finally:
        if 'reporter' in locals(): reporter.close()
        if getattr(locals().get('args'),"cleanup_state",None): args.cleanup_state.close()
        signal.signal(signal.SIGTERM,old_term)

if __name__=="__main__": raise SystemExit(main())
