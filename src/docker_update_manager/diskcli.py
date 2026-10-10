from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json, os, time
from pathlib import Path
from .diskdiag import *
from .retention import inventory
from .system import human_size

def configure(parser):
    parser.add_argument("action",nargs="?",default="overview",choices=["overview","diagnose","largest","files","snapshot","diff","history","growth","docker","containers","logs","journal","deleted","containerd","volumes","inodes","watch"])
    parser.add_argument("--json",action="store_true"); parser.add_argument("--top",type=int,default=20); parser.add_argument("--path",default="/")
    parser.add_argument("--depth",type=int,default=2); parser.add_argument("--min-size",default="100M"); parser.add_argument("--deep",action="store_true")
    parser.add_argument("--hours",type=float); parser.add_argument("--days",type=float); parser.add_argument("--interval",type=float,default=10); parser.add_argument("--count",type=int,default=0)

def emit(data,json_mode,printer):
    if json_mode: print(json.dumps(data,indent=2,default=str))
    else: printer(data)

def handle(args,cfg,state,reporter):
    action=args.action
    if action=="overview":
        snap=quick_snapshot(state,save=False,reporter=reporter); paths={}
        for p in ("/var","/usr","/opt","/root"):
            with reporter.task(f"Measure {p}"): paths[p]=du(p)
        snap["paths"]=paths; snap["snapshot_id"]=state.save_disk_snapshot("dashboard",snap)
        previous=select_previous_excluding(state,snap["snapshot_id"]); diff=snapshot_diff(snap,previous) if previous else None
        data={"snapshot":snap,"change":diff,"retention":inventory(cfg,state)}; emit(data,args.json,print_overview); return 0
    if action=="diagnose":
        snap=quick_snapshot(state,deep=True,reporter=reporter); deleted=deleted_open(); volumes=volume_usage(); binds=bind_mount_usage(); ret=inventory(cfg,state)
        previous=select_previous_excluding(state,snap.get("snapshot_id")); diff=snapshot_diff(snap,previous) if previous else None
        likely=assessment(snap,diff,deleted)
        data={"snapshot":snap,"deleted_open":deleted,"volumes":volumes,"bind_mounts":binds,"retention":ret,"change":diff,"assessment":likely}
        emit(data,args.json,print_diagnose); return 0
    if action=="largest":
        reporter.start("disk-largest",f"Scanning {args.path} on one filesystem")
        with reporter.task(f"Measure directories to depth {args.depth}"): rows=largest_dirs(args.path,args.top,args.depth)
        reporter.finish("Largest-directory scan complete"); emit({"path":args.path,"rows":rows},args.json,lambda d: print_rows("Largest directories",d["rows"],"path")); return 0
    if action=="files":
        reporter.start("disk-files",f"Scanning large files under {args.path}")
        minimum=parse_size(args.min_size); rows=largest_files(args.path,args.top,minimum,reporter)
        reporter.finish("Large-file scan complete"); emit({"path":args.path,"minimum":minimum,"rows":rows},args.json,lambda d: print_rows("Largest files",d["rows"],"path")); return 0
    if action=="snapshot":
        snap=quick_snapshot(state,deep=args.deep,reporter=reporter); emit(snap,args.json,lambda d: print(f"Saved {'DEEP' if args.deep else 'QUICK'} SNAPSHOT #{d['snapshot_id']}\nUsed: {human_size(d['filesystem']['used'])}\nAvailable: {human_size(d['filesystem']['available'])}")); return 0
    if action in {"diff","growth"}:
        previous=select_previous(state,args.hours,args.days)
        if not previous:
            msg={"available":False,"message":"Insufficient history. Run: upt disk snapshot --deep"}; emit(msg,args.json,lambda d: print(d["message"])); return 0
        current=quick_snapshot(state,deep=bool(previous.get("paths")),save=False,reporter=reporter); data=snapshot_diff(current,previous)
        emit(data,args.json,print_growth if action=="growth" else print_diff); return 0
    if action=="history":
        since=(datetime.now(timezone.utc)-timedelta(days=args.days or 7)).strftime("%Y-%m-%d %H:%M:%S"); rows=state.disk_snapshots(since=since)
        data={"days":args.days or 7,"snapshots":rows}; emit(data,args.json,print_history); return 0
    if action=="docker":
        reporter.start("disk-docker","Analysing Docker storage")
        df=docker_df(); containers=container_sizes(); logs=container_logs(); volumes=volume_usage(); ret=inventory(cfg,state)
        reporter.finish("Docker storage analysis complete"); emit({"root":str(docker_root()),"storage":df,"containers":containers,"logs":logs,"volumes":volumes,"retention":ret},args.json,print_docker); return 0
    if action=="containers":
        rows=container_sizes(); emit({"containers":rows},args.json,lambda d: print_container_sizes(d["containers"])); return 0
    if action=="logs":
        rows=container_logs(); emit({"logs":rows,"total":sum(x["size"] for x in rows)},args.json,print_logs); return 0
    if action=="journal":
        data=journal_usage(); previous=select_previous(state,args.hours,args.days); data["growth"]=data["size"]-previous.get("journal",{}).get("size",0) if previous else None
        emit(data,args.json,print_journal); return 0
    if action=="deleted":
        data=deleted_open(); emit(data,args.json,print_deleted); return 0
    if action=="containerd":
        reporter.start("disk-containerd","Analysing containerd storage")
        with reporter.task("Measure detected containerd areas"): data=containerd_usage()
        previous=select_previous(state,args.hours,args.days); data["growth"]={}
        if previous:
            for key,rel in CONTAINERD_AREAS.items():
                path=str(Path(data["root"])/rel)
                if path in previous.get("paths",{}): data["growth"][key]=data["areas"][key]-previous["paths"][path]
        reporter.finish("containerd analysis complete"); emit(data,args.json,print_containerd); return 0
    if action=="volumes":
        reporter.start("disk-volumes","Measuring Docker volumes on the root filesystem"); rows=volume_usage(); binds=bind_mount_usage(); reporter.finish("Volume analysis complete")
        emit({"volumes":rows,"bind_mounts":binds},args.json,print_volumes); return 0
    if action=="inodes":
        data=fs_metrics(); emit(data,args.json,print_inodes); return 0
    if action=="watch": return watch(args,state,reporter)
    return 0

def select_previous_excluding(state,current_id):
    rows=state.disk_snapshots(limit=3)
    return next((x["metrics"] for x in rows if x["id"]!=current_id),None)

def assessment(snap,diff,deleted):
    evidence=[]
    if diff:
        changes=sorted(diff["changes"].items(),key=lambda x:x[1],reverse=True)
        evidence=[{"source":k,"change":v} for k,v in changes if v>0][:5]
    if deleted.get("total",0)>0: evidence.insert(0,{"source":"deleted open files","change":deleted["total"]})
    likely=evidence[0]["source"] if evidence else None
    return {"confidence":"LIKELY" if likely and evidence[0]["change"]>512*1024**2 else ("POSSIBLE" if likely else "NO EVIDENCE"),"source":likely,"evidence":evidence,
            "warning":"Never manually remove containerd content or overlay directories; use Docker-supported cleanup."}

def print_overview(data):
    s=data["snapshot"]; f=s["filesystem"]; print("Disk Usage\n"+"─"*40+f"\n\nFilesystem\n  Mount:       /\n  Size:        {human_size(f['total'])}\n  Used:        {human_size(f['used'])}\n  Available:   {human_size(f['available'])}\n  Usage:       {f['usage_pct']}%\n  Inodes:      {f['inodes_pct']}%")
    if data["change"]: print(f"\nChange since last snapshot:\n  {signed(data['change']['used_change'])} in {format_duration(data['change']['elapsed_seconds'])}")
    print("\nLargest areas")
    for p,n in sorted(s["paths"].items(),key=lambda x:x[1],reverse=True): print(f"  {p:<16}{human_size(n):>10}")
    d=s["docker"]; print(f"\nDocker/containerd\n  Images:           {human_size(d['images'])}\n  Writable layers:  {human_size(sum(x['size'] for x in s['container_layers']))}\n  Volumes:          {human_size(d['volumes'])}\n  Build cache:      {human_size(d['build_cache'])}\n  Container logs:   {human_size(s['container_logs_total'])}\n  Journal:          {human_size(s['journal']['size'])}")
    r=data["retention"]; print(f"\nUPT managed recovery\n  Current:          {human_size(r['total_size'])}\n  Expired:          {human_size(r['expired_size'])}")

def print_diagnose(d):
    print_overview({"snapshot":d["snapshot"],"change":d["change"],"retention":d["retention"]})
    print("\nDiagnostic Summary\n"+"─"*40); a=d["assessment"]; print(f"Assessment: {a['confidence']}\nMost likely source: {a['source'] or 'insufficient historical evidence'}")
    for e in a["evidence"]: print(f"  {signed(e['change']):>12}  {e['source']}")
    print("\nSafety: "+a["warning"])

def print_rows(title,rows,key):
    print(title+"\n"+"─"*40+"\n\nSIZE        PATH")
    for r in rows: print(f"{human_size(r['size']):>10}  {r[key]}")
def signed(n): return ("+" if n>=0 else "-")+human_size(abs(n))
def print_diff(d):
    print("Disk Growth Since Previous Snapshot\n"+"─"*40+f"\n\nElapsed: {format_duration(d['elapsed_seconds'])}\nRoot filesystem: {human_size(d['used_before'])} -> {human_size(d['used_current'])}\nChange: {signed(d['used_change'])}\n\nLargest changes:")
    for k,v in sorted(d["changes"].items(),key=lambda x:abs(x[1]),reverse=True)[:20]: print(f"  {signed(v):>12}  {k}")
def print_growth(d):
    print("Recent Disk Growth\n"+"─"*40+f"\n\nRoot filesystem: {signed(d['used_change'])} over {format_duration(d['elapsed_seconds'])}\n\nTop growth sources:")
    for k,v in sorted(d["changes"].items(),key=lambda x:x[1],reverse=True):
        if v>0: print(f"  {signed(v):>12}  {k}")
def print_history(d):
    print("Disk History\n"+"─"*40+"\n\nDATE/TIME                 USED        CHANGE")
    rows=list(reversed(d["snapshots"])); prev=None
    for r in rows:
        used=r["metrics"]["filesystem"]["used"]; change="" if prev is None else signed(used-prev); print(f"{r['timestamp']:<24} {human_size(used):>10}  {change}"); prev=used
def print_docker(d):
    x=d["storage"]; print("Docker Disk Usage\n"+"─"*40+f"\n\nRoot: {d['root']}\n\nImages\n  Total:       {human_size(x['images'])}\n  Active:      {x['images_active']}\n  Reclaimable: {human_size(x['images_reclaimable'])}\n\nContainers\n  Writable:    {human_size(sum(c['size'] for c in d['containers']))}\n\nVolumes:       {human_size(x['volumes'])}\nBuild cache:   {human_size(x['build_cache'])}\nContainer logs:{human_size(sum(l['size'] for l in d['logs']))}\nUPT protected: {len(d['retention']['rollback_images'])} image reference(s)")
    print_container_sizes(d["containers"][:10])
def print_container_sizes(rows):
    print("\nContainer writable layers\n\nCONTAINER                 SIZE       STATUS")
    for r in rows: print(f"{r['container']:<25} {human_size(r['size']):>10}  {r['status']}")
    print("\nLarge writable layers can mean application data is being written inside a container instead of a volume or bind mount.")
def print_logs(d):
    print("Container Log Usage\n"+"─"*40+"\n\nCONTAINER                 SIZE       DRIVER       LIMIT")
    for r in d["logs"]: print(f"{r['container']:<25} {human_size(r['size']):>10}  {r['driver']:<12} {r['max_size'] or 'none'}")
    for r in d["logs"]:
        if r["driver"] in {"json-file","default"} and not r["max_size"] and r["size"]>=100*1024**2: print(f"\nWARNING: {r['container']} has {human_size(r['size'])} of unbounded json-file logs. Consider Docker log rotation; no configuration was changed.")
def print_journal(d): print(f"systemd journal\n{'─'*40}\n\nUsage:  {human_size(d['size'])}\nOldest: {d.get('oldest') or 'unknown'}\nLimits: {d.get('limits') or 'defaults/unset'}\nGrowth: {signed(d['growth']) if d.get('growth') is not None else 'no baseline'}")
def print_deleted(d):
    if not d["available"]: print("lsof is unavailable; install it to diagnose deleted-but-open files."); return
    print("Deleted files still consuming disk\n"+"─"*40+"\n\nPROCESS              PID       SIZE       FILE")
    for r in d["rows"]: print(f"{str(r['process']):<20} {str(r['pid']):<9} {human_size(r['size']):>10}  {r['file']}")
    print(f"\nTotal: {human_size(d['total'])}\nSpace is released only when the owning process closes the file or exits; no process was restarted.")
def print_containerd(d):
    print("containerd\n"+"─"*40+f"\n\nRoot: {d['root']}\nTotal: {human_size(d['total'])}")
    for key,size in d["areas"].items(): print(f"  {key:<12}{human_size(size):>10}"+(f"  ({signed(d['growth'].get(key,0))})" if d.get("growth") and key in d["growth"] else ""))
    print("\nNever manually remove containerd content or overlay directories. Use Docker/containerd-supported lifecycle and cleanup commands.")
def print_volumes(d):
    print("Docker Volumes\n"+"─"*40+"\n\nVOLUME                         SIZE       USED BY")
    for r in d["volumes"]: print(f"{r['volume']:<30} {human_size(r['size']) if r['size'] is not None else 'other filesystem':>12}  {', '.join(r['used_by']) or 'UNUSED'}")
    print("\nBind Mount Usage (root filesystem only)")
    for r in d["bind_mounts"]: print(f"  {r['container']:<20} {human_size(r['size']) if r['size'] is not None else 'mounted/other fs':>12}  {r['path']}")
def print_inodes(d): print(f"Inode Usage\n{'─'*40}\n\nTotal:     {d['inodes_total']:,}\nUsed:      {d['inodes_used']:,}\nAvailable: {d['inodes_available']:,}\nUsage:     {d['inodes_pct']}%")

def watch(args,state,reporter):
    interval=max(1,args.interval); start=fs_metrics(); begun=time.monotonic(); count=0
    print("Disk Growth Monitor — Ctrl+C to stop\n"+"─"*40)
    try:
        while True:
            time.sleep(interval); count+=1; cur=fs_metrics(); elapsed=time.monotonic()-begun; growth=cur["used"]-start["used"]; rate=growth/(elapsed/60) if elapsed else 0
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Used {human_size(start['used'])} -> {human_size(cur['used'])} | Growth {signed(growth)} | Rate {signed(int(rate))}/min",flush=True)
            if args.count and count>=args.count: break
    except KeyboardInterrupt: print("\nDisk growth monitor stopped cleanly.")
    return 0
