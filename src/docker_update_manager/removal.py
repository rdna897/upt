"""Explicit service removal with opt-in, ownership-checked data purging."""
from __future__ import annotations
import json, os, shutil, sqlite3
from pathlib import Path
from .completion_fence import CompletionFenceError
from .compose_namespace import require_mutation_safe
from .docker import compose_args, discover
from .reconciliation import mark_changed, reconcile_operation
from .operations import command_preview
from .progress import NULL_REPORTER
from .system import run

PROTECTED_PATHS={Path(x) for x in ("/","/bin","/boot","/dev","/etc","/home","/lib","/lib64","/mnt","/opt","/proc","/root","/run","/sbin","/srv","/sys","/tmp","/usr","/var","/var/lib","/var/lib/docker","/var/lib/containerd")}
PROTECTED_TREES={Path(x) for x in ("/boot","/dev","/etc","/proc","/run","/sys","/usr","/bin","/sbin","/lib","/lib64","/var/lib/docker","/var/lib/containerd")}

def _service_rollback_history_ids(state,service):
    return [row["id"] for row in state.history_for_service(service.stack, service.key)]

def _service_rollback_images(state,service):
    if not state.db_path.exists(): return []
    history_ids=_service_rollback_history_ids(state,service)
    if not history_ids: return []
    placeholders=",".join("?" for _ in history_ids)
    with state.connect() as c:
        return [row[0] for row in c.execute(f"SELECT DISTINCT r.image_id FROM rollback_refs r WHERE r.history_id IN ({placeholders}) AND r.expired=0",history_ids)]

def _remaining_container_images(exclude_id=None):
    ids=[x for x in run(["docker","ps","-aq"],timeout=30).split()
         if not exclude_id or not (exclude_id.startswith(x) or x.startswith(exclude_id))]
    if not ids: return set()
    try: return {x.get("Image") for x in json.loads(run(["docker","inspect",*ids],timeout=60)) if x.get("Image")}
    except Exception: return set()

def _other_active_rollback(state,image_id,service):
    own_history_ids=_service_rollback_history_ids(state,service)
    exclusion=""
    values=[image_id]
    if own_history_ids:
        exclusion=" AND r.history_id NOT IN ("+",".join("?" for _ in own_history_ids)+")"
        values.extend(own_history_ids)
    with state.connect() as c:
        return bool(c.execute("SELECT 1 FROM rollback_refs r JOIN history h ON h.id=r.history_id WHERE r.image_id=? AND r.expired=0"+exclusion+" LIMIT 1",values).fetchone())

def _claim_status(state,image_id):
    """Fresh G2 claim read before an image decision; failure keeps the image."""
    try: return "UNRESOLVED RECOVERY CLAIM" if image_id in state.completion_claims()["image"] else None
    except (CompletionFenceError,sqlite3.Error): return "RECOVERY CLAIMS UNVERIFIABLE"

def _overlap(a,b):
    try: a.relative_to(b); return True
    except ValueError: pass
    try: b.relative_to(a); return True
    except ValueError: return False

def _safe_bind_source(value,other_sources):
    path=Path(value)
    if not path.is_absolute(): return False,"not an absolute host path"
    try: resolved=path.resolve(strict=False)
    except OSError: return False,"cannot resolve host path"
    if path.is_symlink(): return False,"symbolic-link bind source"
    if resolved in PROTECTED_PATHS or any(resolved.is_relative_to(root) for root in PROTECTED_TREES):
        return False,"protected system path"
    try:
        probe=resolved if resolved.exists() else resolved.parent
        if os.stat(probe).st_dev!=os.stat("/").st_dev: return False,"not on the root filesystem"
    except OSError: return False,"cannot verify filesystem"
    if any(_overlap(resolved,other) for other in other_sources): return False,"shared with another container"
    return True,"exclusive root-filesystem bind"

def resource_plan(service):
    """Return deletable resources and explicit safety skips without reading contents."""
    selected=json.loads(run(["docker","inspect",service.container_id],timeout=60))[0]
    ids=[x for x in run(["docker","ps","-aq"],timeout=30).split()
         if not (service.container_id.startswith(x) or x.startswith(service.container_id))]
    others=json.loads(run(["docker","inspect",*ids],timeout=60)) if ids else []
    other_volumes={m.get("Name") for c in others for m in c.get("Mounts",[]) if m.get("Type")=="volume" and m.get("Name")}
    other_binds=[]
    for c in others:
        for mount in c.get("Mounts",[]):
            if mount.get("Type")=="bind" and mount.get("Source"):
                try: other_binds.append(Path(mount["Source"]).resolve(strict=False))
                except OSError: pass
    volumes=[]; binds=[]
    for mount in selected.get("Mounts",[]):
        if mount.get("Type")=="volume" and mount.get("Name"):
            shared=mount["Name"] in other_volumes
            volumes.append({"name":mount["Name"],"target":mount.get("Destination"),"eligible":not shared,"reason":"shared with another container" if shared else "exclusive named volume"})
        elif mount.get("Type")=="bind" and mount.get("Source"):
            eligible,reason=_safe_bind_source(mount["Source"],other_binds)
            binds.append({"path":str(Path(mount["Source"]).resolve(strict=False)),"target":mount.get("Destination"),"eligible":eligible,"reason":reason})
    same_project=[c for c in others if service.stack and (c.get("Config",{}).get("Labels") or {}).get("com.docker.compose.project")==service.stack]
    configured_services=[]; compose_verified=not service.stack
    if service.stack:
        try:
            configured_services=run(compose_args(service)+["config","--services"],cwd=service.working_dir,timeout=60).split()
            compose_verified=bool(configured_services) and set(configured_services)<={service.key}
        except Exception: compose_verified=False
    configs=[]
    if service.stack:
        sources=list(dict.fromkeys(service.compose_files))
        if service.working_dir:
            for name in (".env",".container.env"):
                candidate=str(Path(service.working_dir)/name)
                if Path(candidate).exists(): sources.append(candidate)
        shared_config=bool(same_project) or not compose_verified
        for value in dict.fromkeys(sources):
            path=Path(value)
            eligible=not shared_config and path.is_absolute() and path.exists() and path.is_file() and not path.is_symlink()
            if same_project or len(configured_services)>1: reason="shared Compose project"
            elif not compose_verified: reason="could not verify single-service Compose project"
            else: reason="eligible source file" if eligible else "missing or unsafe source file"
            configs.append({"path":str(path),"eligible":eligible,"reason":reason})
        protected_configs=[Path(x["path"]).resolve(strict=False) for x in configs if not x["eligible"]]
        for item in binds:
            bind=Path(item["path"])
            if item["eligible"] and any(config.is_relative_to(bind) for config in protected_configs):
                item["eligible"]=False; item["reason"]="contains shared or unverified Compose configuration"
    return {"volumes":volumes,"binds":binds,"configs":configs,"shared_project_services":sorted(set([c.get("Name","").lstrip("/") for c in same_project]+[x for x in configured_services if x!=service.key]))}

def _print_resource_plan(plan):
    print("\nData/config purge plan")
    for item in plan["volumes"]:
        print(f"  Volume {item['name']}: {'DELETE' if item['eligible'] else 'SKIP'} — {item['reason']}")
    for item in plan["binds"]:
        print(f"  Bind   {item['path']}: {'DELETE' if item['eligible'] else 'SKIP'} — {item['reason']}")
    for item in plan["configs"]:
        print(f"  Config {item['path']}: {'DELETE' if item['eligible'] else 'SKIP'} — {item['reason']}")
    if plan["shared_project_services"]: print("  Compose configuration retained for other project services: "+", ".join(plan["shared_project_services"]))

def _delete_path(path):
    target=Path(path)
    if target.is_symlink() or target.is_file(): target.unlink()
    elif target.is_dir(): shutil.rmtree(target)

@reconcile_operation
def remove_service(s,state,*,images=False,purge_data=False,dry_run=False,yes=False,input_fn=input,reporter=NULL_REPORTER):
    require_mutation_safe(s)
    state.assert_completion_unfenced(s)
    remove_cmd=(compose_args(s)+["rm","--stop","--force",s.key]) if s.stack else ["docker","rm","--force",s.container_id]
    rollback_images=_service_rollback_images(state,s) if images else []
    candidates=list(dict.fromkeys([s.image_id,*rollback_images])) if images else []
    plan=resource_plan(s) if purge_data else {"volumes":[],"binds":[],"configs":[],"shared_project_services":[]}
    print(f"Remove: {s.stack+'/'+s.key if s.stack else s.name}\nContainer: {s.name}\nCurrent image: {s.image}\nRuntime type: {'Compose' if s.stack else 'standalone'}")
    if purge_data:
        print("\nWARNING: --purge-data permanently deletes eligible application data and configuration. No recovery backup is created.")
        _print_resource_plan(plan)
    else: print("\nPreserved:\n  Docker volumes\n  Bind-mounted application data\n  Compose source and .env files")
    print("\nCommands:\n"+command_preview(remove_cmd))
    if images:
        print(f"Image candidates: {len(candidates)} current/rollback image ID(s)")
        for image_id in candidates: print("  docker image rm "+image_id)
    total=7 if purge_data else (5 if images else 3)
    reporter.stage(1,total,"Resolve container, ownership, Compose and rollback resources",service=s.key)
    if dry_run:
        reporter.stage(2,total,"Remove container (not executed)","pending",s.key)
        if images:
            in_use=_remaining_container_images(exclude_id=s.container_id)
            for image_id in candidates:
                if image_id in in_use: status="SKIP — used by another container"
                elif claim:=_claim_status(state,image_id): status=f"SKIP — {claim.lower()}"
                elif _other_active_rollback(state,image_id,s): status="SKIP — protected by another service"
                else: status="WOULD REMOVE"
                print(f"  {image_id[:19]:<20} {status}")
        if purge_data:
            reporter.stage(3,total,"Delete exclusive named volumes (not executed)","pending",s.key)
            reporter.stage(4,total,"Delete safe exclusive bind paths (not executed)","pending",s.key)
            reporter.stage(5,total,"Delete unshared Compose/config sources (not executed)","pending",s.key)
            reporter.stage(6,total,"Remove eligible images (not executed)" if images else "Images not requested","pending",s.key)
            reporter.stage(7,total,"Record removal (not executed)","pending",s.key)
        elif images:
            reporter.stage(3,total,"Check image sharing and container references",service=s.key)
            reporter.stage(4,total,"Remove eligible images (not executed)","pending",s.key)
            reporter.stage(5,total,"Expire service rollback records (not executed)","pending",s.key)
        else: reporter.stage(3,total,"Record removal (not executed)","pending",s.key)
        print("\nDRY RUN — no container, image, volume, bind path, config file, or rollback record changed.")
        return {"removed":False,"images_removed":[],"volumes_removed":[],"binds_removed":[],"configs_removed":[],"skipped":[]}
    if purge_data:
        prompt=f"Type DELETE {s.key} to permanently remove the container and eligible data/config: "
        if not yes and reporter.prompt(prompt,input_fn).strip()!=f"DELETE {s.key}": print("Cancelled; nothing removed."); return {"removed":False,"images_removed":[],"skipped":[]}
    else:
        noun="container and its unused current/rollback images" if images else "container"
        if not yes and reporter.prompt(f"Permanently remove {s.key} {noun}? Volumes and configuration will be preserved. [y/N] ",input_fn).strip().lower() not in {"y","yes"}:
            print("Cancelled; nothing removed."); return {"removed":False,"images_removed":[],"skipped":[]}
    require_mutation_safe(s)
    state.assert_completion_unfenced(s)
    with reporter.task("Removing service container",service=s.key):
        mark_changed()
        run(remove_cmd,cwd=s.working_dir if s.stack else None,timeout=600)
    reporter.stage(2,total,"Remove service container",service=s.key)
    removed=[]; skipped=[]; volumes_removed=[]; binds_removed=[]; configs_removed=[]
    if purge_data:
        for item in plan["volumes"]:
            if not item["eligible"]: skipped.append((item["name"],item["reason"])); continue
            try: run(["docker","volume","rm",item["name"]],timeout=300); volumes_removed.append(item["name"])
            except Exception as exc: skipped.append((item["name"],str(exc)))
        reporter.stage(3,total,"Delete exclusive named volumes",service=s.key)
        for item in plan["binds"]:
            if not item["eligible"]: skipped.append((item["path"],item["reason"])); continue
            try: _delete_path(item["path"]); binds_removed.append(item["path"])
            except Exception as exc: skipped.append((item["path"],str(exc)))
        reporter.stage(4,total,"Delete safe exclusive bind paths",service=s.key)
        for item in plan["configs"]:
            if not item["eligible"]: skipped.append((item["path"],item["reason"])); continue
            try:
                if Path(item["path"]).exists(): _delete_path(item["path"])
                configs_removed.append(item["path"])
            except Exception as exc: skipped.append((item["path"],str(exc)))
        if s.working_dir:
            try: Path(s.working_dir).rmdir()
            except OSError: pass
        reporter.stage(5,total,"Delete unshared Compose/config sources",service=s.key)
    if images:
        in_use=_remaining_container_images()
        if not purge_data: reporter.stage(3,total,"Check image sharing and remaining container references",service=s.key)
        own_history_ids=_service_rollback_history_ids(state,s)
        if own_history_ids:
            placeholders=",".join("?" for _ in own_history_ids)
            with state.connect() as c:
                c.execute(f"UPDATE rollback_refs SET expired=1,purge_status='SERVICE REMOVED' WHERE history_id IN ({placeholders})",own_history_ids)
        for image_id in candidates:
            if image_id in in_use: skipped.append((image_id,"IMAGE IN USE")); continue
            if _other_active_rollback(state,image_id,s): skipped.append((image_id,"OTHER ACTIVE ROLLBACK")); continue
            # Immediately before Docker: an unresolved G2 claim always keeps the image.
            if claim:=_claim_status(state,image_id): skipped.append((image_id,claim)); continue
            try: run(["docker","image","rm",image_id],timeout=300); removed.append(image_id)
            except Exception as exc: skipped.append((image_id,str(exc)))
        reporter.stage(6 if purge_data else 4,total,"Remove eligible images",service=s.key)
        if not purge_data: reporter.stage(5,total,"Expire removed service rollback records",service=s.key)
    elif purge_data: reporter.stage(6,total,"Images not requested","pending",s.key)
    details={"container_id":s.container_id,"current_image_id":s.image_id,"images_requested":images,"purge_data_requested":purge_data,"images_removed":removed,"volumes_removed":volumes_removed,"binds_removed":binds_removed,"configs_removed":configs_removed,"skipped":skipped}
    state.record(stack=s.stack,service=s.key,action="remove",old_image=s.image,result="SUCCESS" if not skipped else "SUCCESS_WITH_WARNINGS",details=details)
    if purge_data: reporter.stage(7,total,"Record removal",service=s.key)
    print(f"\nRemoved container: {s.name}\nImages removed: {len(removed)}\nVolumes removed: {len(volumes_removed)}\nBind paths removed: {len(binds_removed)}\nCompose/config files removed: {len(configs_removed)}")
    for target,reason in skipped: print(f"  {str(target)[:50]}  SKIPPED — {reason}")
    if s.stack and not configs_removed: print(f"\nCompose definition remains in {', '.join(s.compose_files)}. A future `docker compose up` can recreate the service.")
    return {"removed":True,"images_removed":removed,"volumes_removed":volumes_removed,"binds_removed":binds_removed,"configs_removed":configs_removed,"skipped":skipped}
