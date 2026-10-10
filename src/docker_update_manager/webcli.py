from __future__ import annotations

import argparse
import getpass
import grp
import os
import pwd
import sys
from pathlib import Path

from . import __version__
from .agent import AgentClient, AgentUnavailable
from .component_version import MATCH, VERSION_MISMATCH_MESSAGE, version_agreement
from .auth import hash_password, new_token, token_hash, utc_after
from .config import Config, WebConfig
from .lock import Lock
from .state import State
from .webstate import WebState, validate_web_files, validate_web_root
from .webapp import create_app
from .webservice import AgentServer, ReadOnlyService


def web_state(config: WebConfig) -> State:
    """Return web state rooted inside the validated managed directory."""
    return WebState(validate_web_files(Path(config.web_state_dir)))


def _validate_web_root(root: Path) -> Path:
    """Backwards-compatible alias for the shared, pure web-root validator."""
    return validate_web_root(root)


def _prepare_web_state_permissions(config: WebConfig, state: State) -> bool:
    """Validate and restrict the web database directory before auth changes.

    The web state path is deliberately limited to an absolute, non-symlinked
    local path.  If the configured service account exists, it becomes the
    owner of the directory and SQLite files; otherwise root keeps the
    directory private and the operator is expected to create the account
    before starting ``upt-web``.
    """
    root = validate_web_files(state.root)
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    owner = str(config.data.get("web", {}).get("state_owner", "docker-update-manager-web"))
    try:
        account = pwd.getpwnam(owner)
        group = grp.getgrnam(owner)
    except KeyError:
        # Keep the state private to root until the documented service
        # account is created; do not guess a uid/gid or weaken modes.
        return False

    os.chown(root, account.pw_uid, group.gr_gid)
    for candidate in (state.db_path, Path(str(state.db_path) + "-wal"), Path(str(state.db_path) + "-shm")):
        if not candidate.exists():
            continue
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"refusing unsafe web state file: {candidate}")
        os.chown(candidate, account.pw_uid, group.gr_gid)
        os.chmod(candidate, 0o600)
    return True


def bootstrap(config: WebConfig, *, kind="bootstrap") -> int:
    state = web_state(config)
    _prepare_web_state_permissions(config, state)
    if kind == "bootstrap" and state.web_user():
        raise ValueError("administrator already exists; use `upt web reset-admin` for recovery")
    token = new_token()
    minutes = int(config.data.get("web", {}).get("bootstrap_minutes", 15))
    digest = token_hash(token)
    state.create_credential(kind, digest, utc_after(minutes=minutes))
    try:
        # The database may have been created by this root CLI invocation;
        # apply ownership/modes again so the unprivileged web process can
        # read it without granting broader access.
        _prepare_web_state_permissions(config, state)
    except Exception:
        state.delete_credential(kind, digest)
        raise
    print(f"UPT web {kind} code (shown once; expires in {minutes} minutes):")
    print(token)
    print("Keep this code private. It is not written to logs or displayed by the web API.")
    return 0


def reset_admin(config: WebConfig, args) -> int:
    state = web_state(config)
    _prepare_web_state_permissions(config, state)
    user = state.web_user()
    if not user: raise ValueError("no administrator exists; use `upt web bootstrap` first")
    if args.apply:
        code = getpass.getpass("Recovery code: ")
        password = getpass.getpass("New password: ")
        password_digest = hash_password(password)
        state.update_password_with_credential(token_hash(code), user["id"], password_digest)
        state.audit("password_recovery", "success", user_id=user["id"], username=user["username"])
        print("Administrator password reset. Existing web sessions were revoked.")
        return 0
    return bootstrap(config, kind="recovery")


def web_main(argv=None):
    parser = argparse.ArgumentParser(prog="upt-web", description="Run the unprivileged authenticated UPT web service")
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    args = parser.parse_args(argv)
    config = WebConfig(); settings = config.data.get("web", {})
    host, port = args.host or settings.get("listen", "127.0.0.1"), args.port or int(settings.get("port", 8787))
    local_hosts = {"127.0.0.1", "localhost", "::1"}
    if host not in local_hosts and not settings.get("allow_insecure_http", False):
        raise SystemExit("refusing non-loopback HTTP bind without allow_insecure_http=true (use TLS/reverse proxy in production)")
    try:
        import uvicorn
    except ImportError as exc: raise SystemExit("uvicorn is required to run upt-web") from exc
    uvicorn.run(create_app(config), host=host, port=port, proxy_headers=False, server_header=False)


def agent_main(argv=None):
    parser = argparse.ArgumentParser(prog="upt-agent", description="Run the bounded privileged UPT agent")
    parser.add_argument("--socket")
    args = parser.parse_args(argv)
    config, web_config = Config(), WebConfig()
    socket_path = args.socket or str(web_config.socket_path)
    service_name = str(web_config.settings.get("state_owner", "docker-update-manager-web"))
    try:
        allowed_mutation_uid = pwd.getpwnam(service_name).pw_uid
    except KeyError:
        raise SystemExit(f"configured web service account {service_name!r} does not exist") from None
    AgentServer(ReadOnlyService(config, State(config.state_dir), web_settings=web_config.settings),
                socket_path, allowed_mutation_uid=allowed_mutation_uid).serve_forever()


def running_agent_versions(timeout: float = 5.0) -> dict:
    """Bounded read-only running-agent version agreement for `upt doctor`."""
    socket_path = WebConfig().data.get("web", {}).get("socket", "/run/docker-update-manager/agent.sock")
    try:
        return version_agreement(AgentClient(socket_path, timeout=timeout).call("health"))
    except AgentUnavailable:
        return version_agreement(None)


def web_command(config: Config, args):
    config = WebConfig()
    if getattr(args, "dry_run", False):
        print(f"DRY RUN — no web auth state changed ({args.action}).")
        return 0
    if args.action == "bootstrap":
        with Lock(web_state(config).root / "web.lock", no_follow=True):
            return bootstrap(config)
    if args.action == "reset-admin":
        with Lock(web_state(config).root / "web.lock", no_follow=True):
            return reset_admin(config, args)
    if args.action == "status":
        socket_path=config.data.get("web",{}).get("socket","/run/docker-update-manager/agent.sock")
        try: health=AgentClient(socket_path).call("health")
        except AgentUnavailable as exc: print(f"Agent unavailable: {exc}", file=sys.stderr); return 20
        print(health)
        print(f"Web state database: {web_state(config).db_path}")
        versions=version_agreement(health)
        print(f"UPT version: {__version__}")
        # This CLI shares the web package; a running upt-web that was not
        # restarted shows its own version in Settings and is refused by the agent.
        print(f"Web version (installed): {versions['web']}")
        print(f"Agent version (running): {versions['agent'] or 'unknown'}")
        if versions["status"]==MATCH:
            print("Version status: versions match")
            return 0
        print(f"Version status: {VERSION_MISMATCH_MESSAGE} Restart upt-agent and upt-web after installing the same UPT release.", file=sys.stderr)
        return 20
    if args.action == "serve": return web_main([])
    raise ValueError("unknown web action")
