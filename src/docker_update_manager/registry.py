from __future__ import annotations
import json, re
from .models import parse_image_ref, ScanResult
from .system import run, CommandError
from .state import AmbiguousHistoryError

LOCAL_DIGEST_UNVERIFIED = "Local repository digest is unavailable; update comparison is unverified."

def remote_manifest(image: str) -> dict:
    raw = run(["docker", "buildx", "imagetools", "inspect", image, "--raw"], timeout=60)
    data = json.loads(raw)
    digest = data.get("digest")
    manifests = data.get("manifests", [])
    if not digest and manifests:
        # Hash of an index is unavailable in raw JSON; docker manifest inspect --verbose gives it.
        text = run(["docker", "buildx", "imagetools", "inspect", image], timeout=60)
        m = re.search(r"Digest:\s*(sha256:[0-9a-f]{64})", text); digest = m.group(1) if m else None
    platforms = [{"os": m.get("platform",{}).get("os"), "architecture": m.get("platform",{}).get("architecture")} for m in manifests]
    annotations = data.get("annotations") or {}
    return {"digest": digest, "platforms": platforms, "version": annotations.get("org.opencontainers.image.version"), "created": annotations.get("org.opencontainers.image.created")}

def tracking_image(s,state=None):
    """Recover the tag/channel a digest pin should follow without guessing it."""
    ref=parse_image_ref(s.image)
    if not ref.digest: return s.image
    base=s.image.rsplit("@",1)[0]
    # A tag before @ is an explicit channel, e.g. image:latest@sha256:...
    if ":" in base.rsplit("/",1)[-1]: return base
    if state is not None:
        for row in state.history_for_service(s.stack, s.key):
            for key in ("new_image","old_image"):
                candidate=row.get(key)
                if not candidate: continue
                parsed=parse_image_ref(candidate)
                if not parsed.digest and parsed.registry==ref.registry and parsed.repository==ref.repository:
                    return candidate
    return None

def scan_service(s,tracking_ref=None) -> ScanResult:
    if s.ignored: return ScanResult(s, "IGNORED")
    if s.local_build: return ScanResult(s, "LOCAL BUILD")
    ref = parse_image_ref(s.image)
    query=tracking_ref if ref.digest else s.image
    if ref.digest and not query:
        return ScanResult(s,"UNTRACKED DIGEST",error="digest pin has no trusted tracking tag; no release channel was guessed", tracking_issue="missing_channel")
    try: remote = remote_manifest(query)
    except (CommandError, ValueError, json.JSONDecodeError) as e: return ScanResult(s, "REGISTRY ERROR", error=str(e))
    platforms = remote["platforms"]
    if platforms and not any(p["os"] in (None,"linux") and p["architecture"] == s.architecture for p in platforms):
        return ScanResult(s, "ARCH UNSUPPORTED", remote_digest=remote["digest"])
    # A registry manifest cannot establish the identity of the running image.
    # Preserve registry/platform failures above, but never compare an absent
    # local repository digest or substitute the image ID/configured pin for it.
    if not s.digest:
        return ScanResult(s, "UNKNOWN", error=LOCAL_DIGEST_UNVERIFIED)
    same = bool(s.digest and remote["digest"] and s.digest == remote["digest"])
    status = "CURRENT" if same else ("DIGEST CHANGED" if ref.mutable and remote["digest"] else ("UPDATE" if remote["digest"] else "UNKNOWN"))
    if ref.digest: status = "PINNED" if same else ("PINNED UPDATE" if remote["digest"] else "UNKNOWN")
    return ScanResult(s, status, remote["digest"], remote["version"], remote["created"])

def scan_service_with_tracking(s, state=None) -> ScanResult:
    """Scan using trusted history; expose history ambiguity as untracked, not current."""
    try:
        tracking_ref = tracking_image(s, state)
    except AmbiguousHistoryError:
        return ScanResult(
            s,
            "UNTRACKED DIGEST",
            error="digest pin has ambiguous legacy tracking history; no release channel was guessed",
            tracking_issue="ambiguous_history",
        )
    return scan_service(s, tracking_ref)

def list_tags(image: str, limit=10) -> list[str]:
    ref = parse_image_ref(image)
    # Docker Hub API only; other registries differ and may require bearer flows.
    if ref.registry != "docker.io": return []
    import urllib.request
    url = f"https://hub.docker.com/v2/repositories/{ref.repository}/tags?page_size={min(max(limit,10),100)}&ordering=last_updated"
    with urllib.request.urlopen(url, timeout=20) as r: data = json.load(r)
    tags = [x["name"] for x in data.get("results", [])]
    channel = ref.tag.lower()
    if channel in {"beta","nightly","develop","dev","edge"}: tags = [t for t in tags if channel in t.lower()]
    return tags[:limit]
