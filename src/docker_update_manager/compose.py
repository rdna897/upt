from __future__ import annotations
import difflib, json, os, re, shutil, stat, tempfile
from datetime import datetime
from pathlib import Path
import yaml
from .docker import compose_args
from .models import parse_image_ref
from .system import run

VAR_RE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}$")


class ComposeSourceNotWritable(PermissionError):
    """The agent cannot safely replace one of the selected Compose sources."""

    def __init__(self, error_number=None):
        # Keep only the numeric OS category for private server diagnostics.
        # Never retain/display a path or the original exception text.
        message = "UPT cannot modify this service's Compose source from the agent sandbox"
        if error_number is None:
            super().__init__(message)
        else:
            super().__init__(error_number, message)
        self.errno = error_number


def verify_atomic_replace_access(sources):
    """Prove source parents permit the create/unlink step used by atomic writes.

    The check runs in the caller's effective mount namespace and credentials.
    It creates an empty mode-0600 temporary file in each distinct source parent
    and removes it immediately; it never opens or modifies a Compose source.
    """
    parents = set()
    try:
        for source in sources:
            path = Path(os.path.abspath(os.fspath(source)))
            if path.is_symlink() or not path.is_file():
                raise ComposeSourceNotWritable()
            parent = path.parent
            canonical = parent.resolve(strict=True)
            if canonical != parent or not canonical.is_dir():
                raise ComposeSourceNotWritable()
            parents.add(canonical)
    except ComposeSourceNotWritable:
        raise
    except (OSError, TypeError, ValueError):
        raise ComposeSourceNotWritable() from None

    for parent in parents:
        descriptor = None
        probe = None
        failure = None
        try:
            descriptor, probe = tempfile.mkstemp(prefix=".upt-write-probe-", dir=str(parent))
            os.close(descriptor)
            descriptor = None
            os.unlink(probe)
            probe = None
        except OSError as exc:
            failure = exc.errno
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if probe is not None:
                try:
                    os.unlink(probe)
                except OSError as exc:
                    if failure is None:
                        failure = exc.errno
        if failure is not None:
            raise ComposeSourceNotWritable(failure) from None

def locate_image_source(service):
    for filename in reversed(service.compose_files):
        p=Path(filename)
        data=yaml.safe_load(p.read_text()) or {}
        node=(data.get("services") or {}).get(service.compose_service or service.key) or {}
        if "image" in node: return p, str(node["image"])
    raise ValueError("image is generated, inherited, or not defined in the discovered source files")

def pin_target(service, digest=False, target_image=None):
    """Return the exact image reference a pin writes; history records this, never the rewritten source."""
    if digest: return target_image or f"{parse_image_ref(service.image).original.split('@')[0]}@{service.digest}"
    if not service.version: raise ValueError("exact running version is unknown; use --digest")
    ref=parse_image_ref(service.image)
    base=ref.original.rsplit(":",1)[0] if ":" in ref.original.rsplit("/",1)[-1] else ref.original
    return f"{base}:{service.version}"

def pin_source(service):
    """The one file a pin of ``service`` rewrites: its image source or the project .env."""
    source, expression=locate_image_source(service)
    return Path(service.working_dir)/".env" if re.search(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", expression) else source

def pin_plan(service, digest=False, target_image=None):
    source, expression=locate_image_source(service)
    target=pin_target(service, digest, target_image)
    match=re.search(r"\$\{([A-Za-z_][A-Za-z0-9_]*)", expression)
    if match:
        env=Path(service.working_dir)/".env"; var=match.group(1)
        if digest and not (target_image and VAR_RE.fullmatch(expression.strip())):
            raise ValueError("digest pinning cannot safely place a digest in a tag-only .env variable; make the variable control the complete image reference")
        if not env.exists(): raise ValueError(f"image variable {var} is not controlled by a project .env file")
        value=target_image if target_image else (service.digest if digest else service.version)
        old=env.read_text(); new,count=re.subn(rf"(?m)^({re.escape(var)}\s*=).*?$",rf"\g<1>{value}",old,count=1)
        if not count: raise ValueError(f"{var} is not assigned in {env}")
        return env,old,new,"DIGEST PIN" if digest else "VERSION PIN"
    old=source.read_text()
    lines=old.splitlines(keepends=True); in_services=False; in_target=False; changed=False
    service_indent=image_indent=None
    for i,line in enumerate(lines):
        if re.match(r"^services:\s*(?:#.*)?$",line.rstrip()): in_services=True; continue
        if in_services and re.match(r"^\S",line): in_services=False
        m=re.match(r"^(\s+)([^#\s][^:]*):\s*(?:#.*)?$",line.rstrip())
        if in_services and m and len(m.group(1))==2:
            in_target=m.group(2).strip('"\'')==(service.compose_service or service.key); service_indent=len(m.group(1))
        if in_target and re.match(r"^\s+image:\s*",line):
            indent=line[:len(line)-len(line.lstrip())]; comment=""
            body=line.rstrip("\n"); qm=re.search(r"\s+#",body)
            if qm: comment=body[qm.start():]
            lines[i]=f"{indent}image: {target}{comment}\n"; changed=True; break
    if not changed: raise ValueError("could not safely identify the image source line")
    return source,old,"".join(lines),"DIGEST PIN" if digest else "VERSION PIN"

def diff(old,new,path): return "".join(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile=str(path),tofile=str(path)))

def backup_files(files, root, service):
    stamp=datetime.now().strftime("%Y-%m-%d_%H%M%S_%f")
    dest=root/"backups"/stamp; dest.mkdir(parents=True,mode=0o700)
    meta={"stack":service.stack,"service":service.key,"files":[]}
    for f in files:
        p=Path(f); out=dest/p.name; shutil.copy2(p,out); os.chmod(out,0o600); meta["files"].append({"source":str(p),"backup":str(out)})
    (dest/"metadata.json").write_text(json.dumps(meta,indent=2)); os.chmod(dest/"metadata.json",0o600)
    return dest

def atomic_write(path, content):
    p=Path(path); mode=stat.S_IMODE(p.stat().st_mode); uid,gid=p.stat().st_uid,p.stat().st_gid
    fd,tmp=tempfile.mkstemp(prefix=f".{p.name}.",dir=p.parent,text=True)
    try:
        with os.fdopen(fd,"w") as f: f.write(content); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,mode)
        try: os.chown(tmp,uid,gid)
        except PermissionError: pass
        os.replace(tmp,p)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def atomic_write_bytes(path, content, *, expected=None, on_replaced=lambda: None):
    """Atomically replace a Compose/configuration source while preserving metadata."""
    p=Path(path); mode=stat.S_IMODE(p.stat().st_mode); uid,gid=p.stat().st_uid,p.stat().st_gid
    fd,tmp=tempfile.mkstemp(prefix=f".{p.name}.",dir=p.parent)
    try:
        with os.fdopen(fd,"wb") as f: f.write(content); f.flush(); os.fsync(f.fileno())
        os.chmod(tmp,mode)
        try: os.chown(tmp,uid,gid)
        except PermissionError: pass
        if expected is not None:
            # Check again after preparing the temporary file, immediately
            # before replacement. Never restore over an observed operator edit.
            from .compose_drift import read_input
            if read_input("compose", str(p)).content != expected:
                raise ValueError("configuration source changed before atomic replacement")
        os.replace(tmp,p)
        on_replaced()
        directory = os.open(p.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def validate(service, *, project_name=None):
    run(compose_args(service, project_name=project_name)+["config","--quiet"],cwd=service.working_dir)
