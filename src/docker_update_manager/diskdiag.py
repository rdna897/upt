"""Read-only root/boot disk diagnostics and lightweight trend snapshots."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import heapq, json, os, re, shutil, time
from pathlib import Path
from .progress import NULL_REPORTER
from .system import run, human_size, CommandError

MAJOR=("/var","/var/lib","/var/log","/var/cache","/tmp","/var/tmp","/root","/opt")
CONTAINERD_AREAS={"content":"io.containerd.content.v1.content","overlay":"io.containerd.snapshotter.v1.overlayfs",
                  "metadata":"io.containerd.metadata.v1.bolt","runtime":"io.containerd.runtime.v2.task"}

def fs_metrics(path="/"):
    st=os.statvfs(path); total=st.f_blocks*st.f_frsize; free=st.f_bavail*st.f_frsize
    itotal=st.f_files; ifree=st.f_favail
    return {"mount":path,"total":total,"used":total-free,"available":free,"usage_pct":round((total-free)/total*100,1) if total else 0,
            "inodes_total":itotal,"inodes_used":itotal-ifree,"inodes_available":ifree,"inodes_pct":round((itotal-ifree)/itotal*100,1) if itotal else 0}

def parse_size(value):
    if value is None: return 0
    if isinstance(value,(int,float)): return int(value)
    text=str(value).strip().replace(" ",""); m=re.match(r"([0-9.]+)([KMGTPE](?:i?B)?|B)?",text,re.I)
    if not m: return 0
    units={"B":1,"K":1000,"M":1000**2,"G":1000**3,"T":1000**4,"KB":1000,"MB":1000**2,"GB":1000**3,"TB":1000**4,"KIB":1024,"MIB":1024**2,"GIB":1024**3,"TIB":1024**4,"":1}
    return int(float(m.group(1))*units.get((m.group(2) or "").upper(),1))

def du(path):
    p=Path(path)
    if not p.exists(): return 0
    try: return int(run(["du","-sx","--block-size=1",str(p)],timeout=600).split()[0])
    except Exception: return 0

def docker_root():
    try: return Path(run(["docker","info","--format","{{.DockerRootDir}}"],timeout=20).strip())
    except Exception: return Path("/var/lib/docker")

def containerd_root():
    candidates=[]
    for config in (Path("/etc/containerd/config.toml"),Path("/etc/containerd/config.toml.tmpl")):
        if config.exists():
            try:
                m=re.search(r'(?m)^\s*root\s*=\s*["\']([^"\']+)',config.read_text(errors="replace"))
                if m: candidates.append(Path(m.group(1)))
            except OSError: pass
    candidates += [Path("/var/lib/containerd"),docker_root()/"containerd"]
    return next((p for p in candidates if p.exists()),candidates[0])

def docker_df():
    result={"images":0,"images_active":0,"images_reclaimable":0,"containers":0,"volumes":0,"build_cache":0}
    try:
        lines=run(["docker","system","df","--format","{{json .}}"],timeout=60).splitlines()
        for line in lines:
            row=json.loads(line); typ=str(row.get("Type","")).lower(); size=parse_size(row.get("Size")); reclaim=parse_size(str(row.get("Reclaimable","0")).split("(")[0])
            if "image" in typ: result.update(images=size,images_active=int(row.get("Active",0) or 0),images_reclaimable=reclaim)
            elif "container" in typ: result["containers"]=size
            elif "volume" in typ: result["volumes"]=size
            elif "cache" in typ: result["build_cache"]=size
    except Exception: pass
    return result

def container_sizes():
    rows=[]
    try:
        for line in run(["docker","ps","-a","--size","--format","{{json .}}"],timeout=60).splitlines():
            r=json.loads(line); raw=str(r.get("Size","0")).split("(")[0].strip(); size=parse_size(raw)
            rows.append({"container":r.get("Names"),"id":r.get("ID"),"size":size,"status":"LARGE" if size>=1024**3 else ("WARNING" if size>=256*1024**2 else "")})
    except Exception: pass
    return sorted(rows,key=lambda x:x["size"],reverse=True)

def container_logs():
    ids=run(["docker","ps","-aq"],timeout=30).split()
    if not ids: return []
    try: data=json.loads(run(["docker","inspect",*ids],timeout=60))
    except Exception: return []
    rows=[]
    for c in data:
        path=c.get("LogPath") or ""; size=0
        try: size=os.stat(path).st_size if path else 0
        except OSError: pass
        log=(c.get("HostConfig") or {}).get("LogConfig") or {}; options=log.get("Config") or {}
        rows.append({"container":c.get("Name","").lstrip("/"),"size":size,"driver":log.get("Type") or "default",
                     "max_size":options.get("max-size"),"max_file":options.get("max-file"),"path":path})
    return sorted(rows,key=lambda x:x["size"],reverse=True)

def journal_usage():
    result={"size":0,"text":"unavailable","oldest":None}
    try:
        text=run(["journalctl","--disk-usage"],timeout=30).strip(); result["text"]=text
        m=re.search(r"take up\s+([0-9.]+\s*[KMGT](?:i?B)?|[0-9.]+\s*B)",text,re.I); result["size"]=parse_size(m.group(1)) if m else 0
        oldest=run(["journalctl","--no-pager","-n","1","--reverse","-o","short-iso"],timeout=30,check=False).splitlines()
        result["oldest"]=oldest[0].split(" ",1)[0] if oldest else None
    except Exception: pass
    for config in ("/etc/systemd/journald.conf",):
        try:
            vals={}
            for line in Path(config).read_text(errors="replace").splitlines():
                if line.strip() and not line.lstrip().startswith("#") and "=" in line:
                    k,v=line.split("=",1)
                    if k in {"SystemMaxUse","SystemKeepFree","RuntimeMaxUse"}: vals[k]=v
            result["limits"]=vals
        except OSError: result["limits"]={}
    return result

def deleted_open():
    if not shutil.which("lsof"): return {"available":False,"rows":[],"total":0}
    try: text=run(["lsof","-nP","+L1","-F","pcfsn"],timeout=60,check=False)
    except Exception: return {"available":True,"rows":[],"total":0}
    rows=[]; proc={}; file={}
    def flush():
        name=file.get("name","")
        # Anonymous memfd mappings are RAM-backed and commonly advertise huge,
        # sparse logical sizes (for example .NET's 2 TiB doublemapper).  They do
        # not consume boot-disk blocks and must not be reported as disk leaks.
        if name.startswith(("/memfd:","memfd:","/anon_inode:","anon_inode:")):
            return
        if name:
            size=int(file.get("size",0) or 0)
            fd="".join(ch for ch in file.get("fd","") if ch.isdigit())
            if proc.get("pid") and fd:
                try:
                    st=os.stat(f"/proc/{proc['pid']}/fd/{fd}")
                    size=st.st_blocks*512
                except OSError:
                    pass
            rows.append({"process":proc.get("command"),"pid":proc.get("pid"),"size":size,"file":name})
    for line in text.splitlines():
        if not line: continue
        code,val=line[0],line[1:]
        if code=="p": flush(); file={}; proc={"pid":val}
        elif code=="c": proc["command"]=val
        elif code=="f": flush(); file={"fd":val}
        elif code=="s": file["size"]=val
        elif code=="n": file["name"]=val
    flush(); rows=[r for r in rows if r["size"]>0]
    return {"available":True,"rows":sorted(rows,key=lambda x:x["size"],reverse=True),"total":sum(r["size"] for r in rows)}

def quick_snapshot(state,kind="quick",deep=False,reporter=NULL_REPORTER,save=True,connect=None):
    reporter.start("disk-snapshot",f"Collecting {'deep' if deep else 'quick'} disk snapshot")
    metrics={"timestamp":datetime.now(timezone.utc).isoformat(),"filesystem":fs_metrics(),"docker":docker_df()}
    reporter.stage(1,5,"Filesystem and inode usage")
    logs=container_logs(); metrics["container_logs_total"]=sum(x["size"] for x in logs); metrics["container_logs"]=logs
    metrics["container_layers"]=container_sizes(); reporter.stage(2,5,"Docker storage and container layers")
    metrics["journal"]=journal_usage(); reporter.stage(3,5,"Container logs and journal")
    paths={}
    if deep:
        targets=list(MAJOR)+[str(docker_root()),str(containerd_root())]
        for target in dict.fromkeys(targets):
            with reporter.task(f"Measure {target}"): paths[target]=du(target)
        croot=containerd_root()
        for key,rel in CONTAINERD_AREAS.items(): paths[str(croot/rel)]=du(croot/rel)
    metrics["paths"]=paths; reporter.stage(4,5,"Major directory metadata" if not deep else "Deep root-filesystem directory sizes")
    if save: metrics["snapshot_id"]=state.save_disk_snapshot("deep" if deep else kind,metrics,connect=connect)
    reporter.stage(5,5,"Save lightweight metadata" if save else "Snapshot not persisted")
    reporter.finish("Disk snapshot complete"); return metrics

def snapshot_diff(current,previous):
    elapsed=max(0,_time(current)-_time(previous)); curfs=current["filesystem"]; prevfs=previous["filesystem"]
    keys=set(current.get("paths",{}))|set(previous.get("paths",{}))
    changes={k:current.get("paths",{}).get(k,0)-previous.get("paths",{}).get(k,0) for k in keys}
    changes.update({"docker.images":current.get("docker",{}).get("images",0)-previous.get("docker",{}).get("images",0),
                    "docker.build_cache":current.get("docker",{}).get("build_cache",0)-previous.get("docker",{}).get("build_cache",0),
                    "docker.container_logs":current.get("container_logs_total",0)-previous.get("container_logs_total",0),
                    "journal":current.get("journal",{}).get("size",0)-previous.get("journal",{}).get("size",0)})
    return {"elapsed_seconds":elapsed,"used_before":prevfs["used"],"used_current":curfs["used"],"used_change":curfs["used"]-prevfs["used"],"changes":changes,
            "previous":previous.get("timestamp"),"current":current.get("timestamp")}

def _time(metrics):
    try: return datetime.fromisoformat(metrics["timestamp"]).timestamp()
    except Exception: return 0

def select_previous(state,hours=None,days=None):
    rows=state.disk_snapshots()
    if not rows: return None
    if hours or days:
        target=datetime.now(timezone.utc)-timedelta(hours=hours or 24*(days or 0))
        return min(rows,key=lambda r:abs(datetime.fromisoformat(r["metrics"]["timestamp"])-target))["metrics"]
    return rows[0]["metrics"]

def largest_dirs(path="/",top=20,depth=2):
    root=Path(path).resolve(); rootdev=os.stat(root).st_dev
    try:
        out=run(["du","-x","--block-size=1",f"--max-depth={depth}",str(root)],timeout=1800)
        rows=[]
        for line in out.splitlines():
            size,name=line.split("\t",1); rows.append({"size":int(size),"path":name})
        return sorted(rows,key=lambda x:x["size"],reverse=True)[:top]
    except Exception: return []

def largest_files(path="/",top=30,min_size=100*1024**2,reporter=NULL_REPORTER):
    root=Path(path).resolve(); dev=os.stat(root).st_dev; heap=[]; seen=0
    for base,dirs,files in os.walk(root,topdown=True,followlinks=False):
        kept=[]
        for d in dirs:
            try:
                if os.lstat(Path(base)/d).st_dev==dev: kept.append(d)
            except OSError: pass
        dirs[:]=kept
        for name in files:
            try:
                p=Path(base)/name; st=os.lstat(p); seen+=1
                if st.st_dev!=dev or not __import__("stat").S_ISREG(st.st_mode) or st.st_size<min_size: continue
                item=(st.st_size,str(p)); heapq.heappush(heap,item)
                if len(heap)>top: heapq.heappop(heap)
            except OSError: pass
        if seen and seen%10000==0: reporter.progress(f"Scanned {seen} files",service=str(root))
    return [{"size":s,"path":p} for s,p in sorted(heap,reverse=True)]

def containerd_usage():
    root=containerd_root(); areas={key:du(root/rel) for key,rel in CONTAINERD_AREAS.items()}
    return {"root":str(root),"total":du(root),"areas":areas}

def volume_usage():
    names=run(["docker","volume","ls","-q"],timeout=30).split(); used={n:[] for n in names}
    ids=run(["docker","ps","-aq"],timeout=30).split()
    if ids:
        try:
            for c in json.loads(run(["docker","inspect",*ids],timeout=60)):
                for m in c.get("Mounts") or []:
                    if m.get("Type")=="volume" and m.get("Name") in used: used[m["Name"]].append(c.get("Name","").lstrip("/"))
        except Exception: pass
    rows=[]; rootdev=os.stat("/").st_dev
    for name in names:
        try: info=json.loads(run(["docker","volume","inspect",name],timeout=20))[0]; mount=Path(info["Mountpoint"]); size=du(mount) if mount.exists() and os.stat(mount).st_dev==rootdev else None
        except Exception: size=None
        rows.append({"volume":name,"size":size,"used_by":sorted(set(used.get(name,[]))),"unused":not bool(used.get(name))})
    return sorted(rows,key=lambda x:x["size"] if x["size"] is not None else -1,reverse=True)

def bind_mount_usage():
    ids=run(["docker","ps","-q"],timeout=30).split(); rows=[]; rootdev=os.stat("/").st_dev
    if not ids: return rows
    for c in json.loads(run(["docker","inspect",*ids],timeout=60)):
        for m in c.get("Mounts") or []:
            if m.get("Type")!="bind": continue
            p=Path(m["Source"])
            try: size=du(p) if p.exists() and os.stat(p).st_dev==rootdev else None
            except OSError: size=None
            rows.append({"container":c.get("Name","").lstrip("/"),"path":str(p),"size":size,"on_root":size is not None})
    return sorted(rows,key=lambda x:x["size"] if x["size"] is not None else -1,reverse=True)

def format_duration(seconds):
    seconds=int(seconds); d,rem=divmod(seconds,86400); h,rem=divmod(rem,3600); m,_=divmod(rem,60)
    return (f"{d}d " if d else "")+(f"{h}h " if h else "")+f"{m}m"
