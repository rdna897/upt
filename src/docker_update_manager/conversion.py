"""Reversible standalone-container to Compose conversion."""
from __future__ import annotations
from datetime import datetime
import json, os, re, shutil, tempfile, time
from pathlib import Path
import yaml
from .compose_namespace import require_mutation_safe
from .docker import discover, resolve_service
from .progress import NULL_REPORTER
from .reconciliation import mark_changed, reconcile_operation
from .system import run

def _inspect(name): return json.loads(run(["docker","inspect",name]))[0]
def _image(image_id): return json.loads(run(["docker","image","inspect",image_id]))[0]
def _env_map(values):
    out={}
    for value in values or []:
        key,sep,val=value.partition("=")
        if sep: out[key]=val
    return out
def _safe_name(value): return re.sub(r"[^a-zA-Z0-9_.-]+","-",value).strip("-.") or "service"

def default_stack_path(name,root="/root"):
    safe=_safe_name(name)
    return Path(root)/(safe if safe.endswith("-stack") else f"{safe}-stack")

def build_conversion(service,track_tag=False):
    """Return Compose data, secret env text, and a non-secret summary."""
    if service.stack: raise ValueError(f"{service.key} is already managed by Compose")
    c=_inspect(service.name); im=_image(c["Image"]); cfg=c.get("Config") or {}; host=c.get("HostConfig") or {}
    image_cfg=im.get("Config") or {}; name=_safe_name(service.name)
    exact_image=service.image
    if service.digest and not track_tag:
        base=service.image.split("@",1)[0]
        if ":" in base.rsplit("/",1)[-1]: base=base.rsplit(":",1)[0]
        exact_image=f"{base}@{service.digest}"
    node={"image":exact_image,"container_name":service.name}
    if host.get("RestartPolicy",{}).get("Name") and host["RestartPolicy"]["Name"]!="no": node["restart"]=host["RestartPolicy"]["Name"]
    runtime=_env_map(cfg.get("Env")); defaults=_env_map(image_cfg.get("Env")); overrides={k:v for k,v in runtime.items() if defaults.get(k)!=v}
    if overrides: node["env_file"]=[".container.env"]
    if cfg.get("Cmd") != image_cfg.get("Cmd") and cfg.get("Cmd") is not None: node["command"]=cfg["Cmd"]
    if cfg.get("Entrypoint") != image_cfg.get("Entrypoint") and cfg.get("Entrypoint") is not None: node["entrypoint"]=cfg["Entrypoint"]
    for source,target in (("User","user"),("WorkingDir","working_dir"),("Hostname","hostname")):
        value=cfg.get(source)
        auto_hostname=source=="Hostname" and value==str(c.get("Id",""))[:12]
        if value and value!=image_cfg.get(source) and not auto_hostname: node[target]=value
    if cfg.get("Tty"): node["tty"]=True
    if cfg.get("OpenStdin"): node["stdin_open"]=True
    if host.get("Privileged"): node["privileged"]=True
    if host.get("ReadonlyRootfs"): node["read_only"]=True
    if host.get("Init"): node["init"]=True
    if host.get("PidMode"): node["pid"]=host["PidMode"]
    if host.get("IpcMode") and host["IpcMode"] not in {"private","shareable"}: node["ipc"]=host["IpcMode"]
    if host.get("GroupAdd"): node["group_add"]=host["GroupAdd"]
    if host.get("Sysctls"): node["sysctls"]=host["Sysctls"]
    if host.get("ShmSize") and host["ShmSize"] != 67108864: node["shm_size"]=host["ShmSize"]
    if host.get("Memory"): node["mem_limit"]=host["Memory"]
    if host.get("NanoCpus"): node["cpus"]=host["NanoCpus"]/1_000_000_000
    if host.get("Tmpfs"): node["tmpfs"]=[f"{path}:{options}" if options else path for path,options in host["Tmpfs"].items()]
    if host.get("Ulimits"):
        node["ulimits"]={u["Name"]:{"soft":u["Soft"],"hard":u["Hard"]} for u in host["Ulimits"]}
    for source,target in (("CapAdd","cap_add"),("CapDrop","cap_drop"),("SecurityOpt","security_opt"),("Dns","dns"),("ExtraHosts","extra_hosts")):
        if host.get(source): node[target]=host[source]
    devices=[]
    for d in host.get("Devices") or []:
        value=f"{d.get('PathOnHost')}:{d.get('PathInContainer')}"
        if d.get("CgroupPermissions"): value+=f":{d['CgroupPermissions']}"
        devices.append(value)
    if devices: node["devices"]=devices
    ports=[]
    for container_port,bindings in (host.get("PortBindings") or {}).items():
        for binding in bindings or []:
            host_ip=binding.get("HostIp") or ""; host_port=binding.get("HostPort") or ""
            prefix=f"{host_ip}:" if host_ip not in {"","0.0.0.0","::"} else ""
            ports.append(f"{prefix}{host_port}:{container_port}")
    ports=list(dict.fromkeys(ports))
    if ports: node["ports"]=ports
    volumes=[]; named=[]
    for mount in c.get("Mounts") or []:
        source=mount.get("Source") if mount.get("Type")=="bind" else mount.get("Name")
        if not source: continue
        item=f"{source}:{mount['Destination']}"+("" if mount.get("RW",True) else ":ro")
        volumes.append(item)
        if mount.get("Type")=="volume": named.append(source)
    if volumes: node["volumes"]=volumes
    compose={"services":{name:node}}
    if named: compose["volumes"]={v:{"external":True} for v in sorted(set(named))}
    network_mode=host.get("NetworkMode")
    network_names=list((c.get("NetworkSettings") or {}).get("Networks") or {})
    if network_mode in {"host","none"}: node["network_mode"]=network_mode
    elif network_names and network_names!=["bridge"]:
        node["networks"]=network_names; compose["networks"]={n:{"external":True} for n in network_names}
    image_labels=image_cfg.get("Labels") or {}; container_labels=cfg.get("Labels") or {}
    overrides_labels={k:v for k,v in container_labels.items() if image_labels.get(k)!=v and not k.startswith("com.docker.compose.")}
    if overrides_labels: node["labels"]=overrides_labels
    health=cfg.get("Healthcheck")
    if health and health != image_cfg.get("Healthcheck"):
        converted={}
        if health.get("Test"): converted["test"]=health["Test"]
        for source,target in (("Interval","interval"),("Timeout","timeout"),("StartPeriod","start_period"),("Retries","retries")):
            if health.get(source): converted[target]=health[source] if source=="Retries" else f"{health[source]}ns"
        if converted: node["healthcheck"]=converted
    env_text="".join(f"{key}={json.dumps(value)}\n" for key,value in sorted(overrides.items()))
    summary={"service":name,"container":service.name,"image":exact_image,"source_image":service.image,"track_tag":track_tag,"environment_keys":sorted(overrides),
             "ports":ports,"mounts":volumes,"networks":network_names,"named_volumes":sorted(set(named))}
    return compose,env_text,summary,c

def render_compose(data): return yaml.safe_dump(data,sort_keys=False,default_flow_style=False)

def _create(path: Path,content: str,mode: int):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o750)
    fd,tmp=tempfile.mkstemp(prefix=f".{path.name}.",dir=path.parent,text=True)
    try:
        with os.fdopen(fd,"w") as f: f.write(content); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,mode); os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def generate_conversion(service,state,output: Path,*,dry_run=False,replace_files=False,yes=False,track_tag=False,reporter=NULL_REPORTER,input_fn=input):
    require_mutation_safe(service)
    reporter.start("convert",f"Converting standalone container {service.name}")
    with reporter.task("Inspect current container and image",service=service.name): compose,env_text,summary,raw=build_conversion(service,track_tag)
    reporter.stage(1,5,"Capture container configuration",service=service.name)
    text=render_compose(compose); compose_path=output/"compose.yml"; env_path=output/".container.env"
    print("\nGenerated Compose preview (environment values are not displayed):\n")
    print(text.rstrip())
    if summary["environment_keys"]: print("\nRuntime environment keys stored separately:\n  "+"\n  ".join(summary["environment_keys"]))
    reporter.stage(2,5,"Generate Compose and secret environment file",service=service.name)
    if dry_run:
        reporter.stage(3,5,"Write generated files (not executed)","pending",service.name)
        reporter.stage(4,5,"Validate Compose (not executed)","pending",service.name)
        reporter.stage(5,5,"Deploy conversion (not executed)","pending",service.name)
        reporter.finish("Conversion dry run complete"); print(f"\nDRY RUN — would write {compose_path} and {env_path}; no changes made.")
        return compose_path,summary,raw
    if not yes and reporter.prompt(f"Write conversion files under {output}? [y/N] ",input_fn).strip().lower() not in {"y","yes"}:
        reporter.finish("Conversion cancelled"); print("Cancelled; no files or containers were changed."); return None
    existing=[p for p in (compose_path,env_path) if p.exists()]
    if existing and not replace_files: raise ValueError("conversion files already exist; use --replace-files after reviewing them")
    if existing:
        backup=state.root/"conversion-file-backups"/datetime.now().strftime("%Y-%m-%d_%H%M%S_%f")
        backup.mkdir(parents=True,mode=0o700)
        for p in existing: shutil.copy2(p,backup/p.name); os.chmod(backup/p.name,0o600)
    _create(compose_path,text,0o640); _create(env_path,env_text,0o600)
    reporter.stage(3,5,"Write generated files",service=service.name)
    with reporter.task("Validate generated Compose",service=service.name): run(["docker","compose","--project-directory",str(output),"-f",str(compose_path),"config","--quiet"],cwd=str(output))
    reporter.stage(4,5,"Validate Compose",service=service.name)
    return compose_path,summary,raw

@reconcile_operation
def deploy_conversion(service,state,output: Path,summary,raw,*,yes=False,reporter=NULL_REPORTER,input_fn=input,health_timeout=90):
    require_mutation_safe(service)
    if not yes and reporter.prompt(f"Adopt {service.name} into Compose? The original will be stopped but retained. [y/N] ",input_fn).strip().lower() not in {"y","yes"}:
        print("Cancelled; generated files were retained but the container was not changed."); return None
    require_mutation_safe(service)
    stamp=datetime.now().strftime("%Y%m%d-%H%M%S"); backup_name=f"{service.name}-dum-backup-{stamp}"
    snapshot=state.root/"conversion-snapshots"/f"{service.name}-{stamp}"; snapshot.mkdir(parents=True,mode=0o700)
    _create(snapshot/"container-inspect.json",json.dumps(raw,indent=2),0o600)
    compose=["docker","compose","--project-directory",str(output),"-f",str(output/"compose.yml")]
    reporter.stage(1,7,"Save restrictive container snapshot",service=service.name)
    try:
        if summary.get("track_tag"):
            with reporter.task("Bind mutable tag to the currently running image",service=service.name): run(["docker","image","tag",service.image_id,summary["source_image"]])
        require_mutation_safe(service)
        mark_changed(current_name=service.name)
        with reporter.task("Stop original container",service=service.name): run(["docker","stop",service.name],timeout=120)
        reporter.stage(2,7,"Stop original container",service=service.name)
        with reporter.task(f"Retain original as {backup_name}",service=service.name): run(["docker","rename",service.name,backup_name])
        reporter.stage(3,7,"Rename and retain original container",service=service.name)
        with reporter.task("Create Compose-managed replacement",service=service.name): run(compose+["up","-d","--no-deps",summary["service"]],cwd=str(output),timeout=600)
        reporter.stage(4,7,"Create Compose-managed replacement",service=service.name)
        deadline=time.time()+health_timeout; fresh=_inspect(service.name)
        while (fresh.get("State",{}).get("Health") or {}).get("Status")=="starting" and time.time()<deadline:
            reporter.progress("Health check starting",service=service.name); time.sleep(2); fresh=_inspect(service.name)
        status=fresh.get("State",{}).get("Status"); health=(fresh.get("State",{}).get("Health") or {}).get("Status","none")
        reporter.stage(5,7,"Wait for startup",service=service.name)
        if status!="running" or health in {"unhealthy","starting"}: raise RuntimeError(f"replacement state is {status}/{health}")
        reporter.stage(6,7,f"Verify replacement health ({health})",service=service.name)
        state.record(service=service.name,stack=output.name,action="convert",old_image=service.image,old_image_id=service.image_id,old_digest=service.digest,new_image=summary["image"],backup=str(snapshot),result="SUCCESS",details={"backup_container":backup_name,"compose_dir":str(output)})
        reporter.stage(7,7,"Record reversible conversion",service=service.name)
        reporter.finish("Conversion deployment complete")
        print(f"\nConverted {service.name} to Compose. Retained stopped container: {backup_name}")
        return backup_name
    except Exception:
        reporter.warning("Conversion failed; restoring original container",service.name)
        current = next((item for item in discover(all_containers=True) if item.name == service.name), None)
        require_mutation_safe(service)  # retained original: restart also needs protection
        if current is not None:
            require_mutation_safe(current)
        run(compose+["rm","-s","-f",summary["service"]],cwd=str(output),check=False)
        run(["docker","rename",backup_name,service.name],check=False); run(["docker","start",service.name],check=False)
        raise RuntimeError("conversion failed; original container restoration was attempted") from None

@reconcile_operation
def rollback_conversion(service_name,state,*,yes=False,reporter=NULL_REPORTER,input_fn=input):
    candidates=[r for r in state.history(service_name) if r["action"]=="convert" and r["result"]=="SUCCESS"]
    scoped_identities={(row["stack"],row["service"]) for row in candidates if row.get("stack") is not None}
    if len(scoped_identities)>1:
        raise ValueError(f"conversion history for {service_name!r} exists in multiple stacks; refusing to choose a rollback point")
    if scoped_identities:
        stack,identity=next(iter(scoped_identities))
        rows=[r for r in state.history_for_service(stack,identity) if r["action"]=="convert" and r["result"]=="SUCCESS"]
    elif candidates:
        stack,identity=None,service_name
        rows=[r for r in state.history_for_service(stack,identity) if r["action"]=="convert" and r["result"]=="SUCCESS"]
    else: rows=[]
    if not rows: raise ValueError("no successful conversion rollback point exists")
    row=rows[0]; details=json.loads(row["details"] or "{}"); backup=details.get("backup_container")
    if not backup: raise ValueError("conversion history does not contain a retained container")
    current = resolve_service(discover(all_containers=True), service_name)
    retained = resolve_service(discover(all_containers=True), backup)
    require_mutation_safe(current)
    require_mutation_safe(retained)
    if not yes and reporter.prompt(f"Remove the Compose replacement and restore retained container {backup}? [y/N] ",input_fn).strip().lower() not in {"y","yes"}: print("Cancelled."); return
    reporter.start("convert-rollback",f"Restoring standalone container {service_name}")
    require_mutation_safe(current)
    require_mutation_safe(retained)
    mark_changed(current, current_name=service_name)
    run(["docker","stop",service_name],check=False); run(["docker","rm",service_name],check=False)
    reporter.stage(1,3,"Remove Compose-managed replacement",service=service_name)
    run(["docker","rename",backup,service_name]); run(["docker","start",service_name])
    reporter.stage(2,3,"Restore and start retained container",service=service_name)
    state.record(stack=stack,service=service_name,action="convert-rollback",old_image=row["new_image"],new_image=row["old_image"],new_image_id=row["old_image_id"],result="ROLLED BACK",rollback_result="SUCCESS")
    reporter.stage(3,3,"Record conversion rollback",service=service_name); reporter.finish("Conversion rollback complete")
