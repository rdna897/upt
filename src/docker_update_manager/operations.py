from __future__ import annotations
import json, re, time
from pathlib import Path
from .compose import atomic_write, atomic_write_bytes, backup_files, pin_plan, pin_target, diff, validate
from .compose_namespace import require_mutation_safe
from .docker import compose_args, discover
from .registry import LOCAL_DIGEST_UNVERIFIED, remote_manifest, tracking_image
from .system import run, run_compose_progress
from .progress import NULL_REPORTER, UPDATE_STAGE_TOTAL, UPDATE_RECORD_LABEL
from .models import parse_image_ref
from .reconciliation import mark_changed, mark_project_inputs_changed, reconcile_operation

class RecoveryRefused(RuntimeError):
    """A web-only safety check refused automatic Compose recovery."""

class RecoveryRequired(RuntimeError):
    """Automatic recovery was refused and requires operator intervention."""

class RecoveryFailed(RecoveryRequired):
    """The guarded automatic recovery recreation ran but did not succeed."""

class ReviewedTargetChanged(RuntimeError):
    """The exact image target reviewed by the web user can no longer be proven."""

class PreMutationRefusal(ValueError):
    """A validation guard refused the operation.

    Raising this is not itself proof that nothing changed: an operation is
    reported as blocked only when its caller also proves the explicit
    mutation boundary (see mutation_started) had not been crossed.
    """
    def __init__(self, message, reason="validation_refused"):
        super().__init__(message)
        self.reason = reason

BLOCKING_REFUSALS = (PreMutationRefusal, ReviewedTargetChanged)

class WebRollbackFailure(RuntimeError):
    """A bounded web rollback failed; its recovery outcome is explicit."""
    def __init__(self, *, recovered=False, manual_recovery_required=False):
        self.recovered = bool(recovered)
        self.manual_recovery_required = bool(manual_recovery_required)
        super().__init__("web rollback did not complete")

def command_preview(args): return "  " + " ".join(repr(x) if any(c.isspace() for c in x) else x for x in args)

@reconcile_operation
def do_pin(s,state,*,digest=False,dry_run=False,yes=False,input_fn=input,reporter=NULL_REPORTER,output=print):
    if not s.digest:
        raise PreMutationRefusal(LOCAL_DIGEST_UNVERIFIED, "target_unavailable")
    total=5; reporter.stage(1,total,"Resolve running image",service=s.key)
    with reporter.task("Generate pin proposal",service=s.key): path,old,new,kind=pin_plan(s,digest); target=pin_target(s,digest)
    patch=diff(old,new,path); reporter.stage(2,total,"Generate proposed diff",service=s.key)
    output(f"Proposed change ({kind}):\n\n{patch}")
    if dry_run: reporter.stage(3,total,"Identify backup files",service=s.key); reporter.stage(4,total,"Compose validation (not executed)","pending",s.key); reporter.stage(5,total,"Apply configuration (not executed)","pending",s.key); output("DRY RUN — no files changed."); return None
    if not yes and reporter.prompt("Apply? [y/N] ",input_fn).strip().lower() not in {"y","yes"}: output("Cancelled."); return None
    state.ensure_compatible()
    state.assert_service_unfenced(s)  # refuse an unsupported state database before any side effect
    with reporter.task("Back up configuration",service=s.key): backup=backup_files([path],state.root,s)
    reporter.stage(3,total,"Backup configuration",service=s.key)
    mark_changed(s)
    mark_project_inputs_changed()
    atomic_write(path,new)
    try:
        with reporter.task("Validate Compose configuration",service=s.key): validate(s)
    except Exception:
        atomic_write(path,old)
        raise RuntimeError("Compose validation failed; original configuration restored") from None
    reporter.stage(4,total,"Compose validation",service=s.key)
    state.record(stack=s.stack,service=s.key,action="pin",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,new_image=target,backup=str(backup),result="SUCCESS")
    reporter.stage(5,total,"Record pin",service=s.key)
    output(f"Pinned {s.key} ({kind}); backup: {backup}")
    return backup

def do_pull(s,dry_run=False,reporter=NULL_REPORTER,*,state=None):
    if not dry_run:
        if state is None:
            raise ValueError("state authority is required before image mutation")
        state.ensure_compatible()
        state.assert_service_unfenced(s)
    args=compose_args(s)+["pull",s.key]
    if dry_run: reporter.stage(1,2,"Generate Docker pull command",service=s.key); reporter.stage(2,2,"Pull image (not executed)","pending",s.key); print("DRY RUN\n"+command_preview(args)); return
    reporter.stage(1,2,"Generate Docker pull command",service=s.key)
    with reporter.task("Pulling image from Docker progress events",service=s.key): run_compose_progress(args,reporter,s.key,cwd=s.working_dir,timeout=1800)
    reporter.stage(2,2,"Pull image; running container unchanged",service=s.key); print(f"Pulled {s.key}; running container was not recreated.")

def _do_pinned_update(s,state,*,dry_run=False,yes=False,no_health=False,health_timeout=90,input_fn=input,reporter=NULL_REPORTER,output=print,audit_context=None,pre_source_write_check=None,pre_pull_check=None,pre_recreate_check=None,post_pin_check=None,pre_recovery_check=None,target_guard=None,mutation_started=None,project_name=None,namespace_update=None):
    def mutation_check():
        if namespace_update: namespace_update.check()
        else: require_mutation_safe(s)
    mutation_check()
    channel=tracking_image(s,state)
    if not channel: raise ValueError("digest pin has no trustworthy tracking tag in Compose or UPT history; refusing to guess a release channel")
    with reporter.task(f"Resolving tracked channel {channel}",service=s.key): remote=remote_manifest(channel)
    digest=remote.get("digest")
    if not digest: raise RuntimeError(f"registry returned no digest for tracked channel {channel}")
    reporter.stage(1,UPDATE_STAGE_TOTAL,"Resolve tracked channel",service=s.key)
    if target_guard: target_guard("registry", remote)
    if s.digest==digest: output(f"{s.key} is already pinned to the current {channel} digest."); return {"updated": False, "image": s.image, "version": s.version, "digest": s.digest}
    platforms=remote.get("platforms") or []
    if platforms and not any(p["os"] in (None,"linux") and p["architecture"]==s.architecture for p in platforms): raise RuntimeError("replacement image does not support the running architecture")
    reporter.stage(2,UPDATE_STAGE_TOTAL,"Verify architecture",service=s.key)
    target=f"{channel.rsplit('@',1)[0]}@{digest}"
    path,old,new,kind=pin_plan(s,digest=True,target_image=target)
    patch=diff(old,new,path); base=compose_args(s,project_name=project_name); up=base+["up","-d","--no-deps",s.key]
    if namespace_update: up=base+["up","-d","--no-deps","--pull","never","--no-build",s.key]
    output(f"Tracked channel: {channel}\nPinned target:   {target}\n\nProposed Compose change:\n\n{patch}\nCommands:\n{command_preview(['docker','pull',target])}\n{command_preview(up)}")
    if dry_run:
        for n,label in enumerate(("Back up Compose configuration (not executed)","Pull exact replacement digest (not executed)","Write and validate new digest pin (not executed)","Recreate service without dependencies (not executed)","Verify startup and health (not executed)",f"{UPDATE_RECORD_LABEL} (not executed)"),3): reporter.stage(n,UPDATE_STAGE_TOTAL,label,"pending",s.key)
        output("DRY RUN — no image pulled, file changed, or container recreated."); return
    if not yes and reporter.prompt(f"Advance {s.key} digest pin and update the service? [y/N] ",input_fn).strip().lower() not in {"y","yes"}: output("Cancelled."); return
    state.ensure_compatible()
    state.assert_service_unfenced(s)  # refuse an unsupported state database before any side effect
    mutation_check()
    if pre_source_write_check: pre_source_write_check(path)
    sources=list(s.compose_files); env=Path(s.working_dir)/".env"
    if env.exists(): sources.append(str(env))
    if namespace_update: sources=[item[1] for item in namespace_update.review.inputs if item[2]]
    backup=backup_files(sources,state.root,s); reporter.stage(3,UPDATE_STAGE_TOTAL,"Back up Compose configuration",service=s.key)
    pin_written=False; recreate_started=False; side_effect_started=False
    try:
        if pre_pull_check: pre_pull_check()
        # Mutation boundary: nothing below may be reported as "blocked".
        side_effect_started=True
        if mutation_started: mutation_started("pull")
        with reporter.task("Pulling exact replacement digest",service=s.key): run(["docker","pull",target],timeout=1800)
        if target_guard: target_guard("pulled", target)
        reporter.stage(4,UPDATE_STAGE_TOTAL,"Pull exact replacement digest",service=s.key)
        if pre_recreate_check: pre_recreate_check()
        mark_changed()
        mark_project_inputs_changed()
        atomic_write(path,new)
        pin_written=True
        validate(s,project_name=project_name)
        reporter.stage(5,UPDATE_STAGE_TOTAL,"Write and validate new digest pin",service=s.key)
        if post_pin_check: post_pin_check(target)
        if namespace_update: namespace_update.accept_pin(path,old,new,target)
        with reporter.task("Recreating only the pinned service",service=s.key):
            mutation_check()
            if namespace_update: namespace_update.before_exec()
            recreate_started=True
            run(up,cwd=s.working_dir,timeout=600)
        reporter.stage(6,UPDATE_STAGE_TOTAL,"Recreate service without dependencies",service=s.key)
        fresh=next(x for x in discover() if x.stack==s.stack and x.key==s.key)
        if namespace_update: namespace_update.check(fresh)
        reporter.stage(7,UPDATE_STAGE_TOTAL,"Verify startup and health",state="running",service=s.key)
        deadline=time.time()+health_timeout; attempts=1
        while not no_health and fresh.health=="starting" and time.time()<deadline:
            reporter.emit("task_progress",f"Health starting; attempt {attempts}",service=s.key,status="running"); time.sleep(2); attempts+=1
            fresh=next(x for x in discover() if x.stack==s.stack and x.key==s.key)
            if namespace_update: namespace_update.check(fresh)
        if fresh.state!="running" or fresh.health in {"unhealthy","starting"}: raise RuntimeError(f"replacement state is {fresh.state}/{fresh.health}")
        reporter.stage(7,UPDATE_STAGE_TOTAL,"Verify startup and health",service=s.key)
        details={"tracking_channel":channel,"pin_advanced":True,**(audit_context or {})}
        if namespace_update: namespace_update.check(fresh)
        history_id=state.record(stack=s.stack,service=s.key,action="update",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,new_image=target,new_image_id=fresh.image_id,new_digest=fresh.digest,new_version=fresh.version,backup=str(backup),result="SUCCESS",details=details,**({'namespace_operation_id': namespace_update.operation_id} if namespace_update else {}))
        reporter.stage(8,UPDATE_STAGE_TOTAL,UPDATE_RECORD_LABEL,service=s.key)
        output(f"Updated {s.key} and advanced its digest pin to {digest}; previous image is rollback-protected.")
        return {"updated": True, "history_id": history_id, "image": target, "version": fresh.version, "digest": fresh.digest}
    except BaseException as exc:
        # Post-marker: no source restoration or recreation. The new pin and the
        # backup are retained as evidence for manual recovery.
        if namespace_update and namespace_update.marked:
            _failed_namespace_update(s,state,namespace_update,backup,audit_context)
        if not isinstance(exc, Exception): raise
        # Restore the source pin. If recreation had begun, make a best-effort
        # service-scoped return to the old exact digest.
        restored=not pin_written; recovery_refused=False; recovery_recreated=False; recovery_started=False; recovery_failed=False
        if pin_written:
            try:
                # Do not overwrite an operator's concurrent edit while trying
                # to restore our own pin. The source is recoverable only if it
                # still contains exactly the bytes UPT wrote.
                if path.read_text()!=new: raise RuntimeError("Compose source changed after UPT wrote the digest pin")
                atomic_write(path,old); validate(s,project_name=project_name)
                restored=True
                if recreate_started:
                    if pre_recovery_check:
                        try: pre_recovery_check()
                        except RecoveryRefused:
                            recovery_refused=True
                            raise
                    recovery_service = next((x for x in discover(all_containers=True) if x.stack == s.stack and x.key == s.key), s)
                    require_mutation_safe(recovery_service, allow_absent=True)
                    recovery_started=True
                    run(up,cwd=s.working_dir,timeout=600)
                    recovery_recreated=True
            except RecoveryRefused:
                recovery_refused=True
            except Exception:
                # With the web guard installed, any failure before the
                # recovery command means equivalence was not established.
                # Keep all artefacts and make the manual-recovery outcome
                # durable instead of presenting this as a completed rollback.
                if pre_recovery_check and not recovery_started:
                    recovery_refused=True
                elif pre_recovery_check and recovery_started and not recovery_recreated:
                    recovery_failed=True
        recorded_error = "details redacted for web-triggered operation" if audit_context else str(exc)
        details={"tracking_channel":channel,"error":recorded_error,"configuration_restored":restored,**(audit_context or {})}
        if not side_effect_started and isinstance(exc, BLOCKING_REFUSALS):
            details.update(blocked=True, mutation_performed=False, reason=getattr(exc,"reason","reviewed_target_changed"))
            state.record(stack=s.stack,service=s.key,action="update",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,new_image=target,backup=str(backup),result="BLOCKED",details=details)
            raise
        if recovery_refused or recovery_failed:
            details["recovery_required"] = True
            details["recovery_attempted"] = recovery_started
            details["recovery_result"] = "failed" if recovery_failed else "refused"
            if recovery_failed:
                details["recovery_failure"] = "recovery recreation command failed"
            state.record(stack=s.stack,service=s.key,action="update",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,new_image=target,backup=str(backup),result="FAILED",rollback_result="MANUAL RECOVERY REQUIRED",details=details)
            if recovery_failed:
                raise RecoveryFailed("automatic recovery recreation failed; manual recovery is required") from None
            raise RecoveryRequired("automatic recovery recreation was refused because Compose configuration changed or could not be verified; manual recovery is required") from None
        if recovery_recreated:
            details["recovery_required"] = False
            details["recovery_result"] = "automatic recovery recreated the previous service"
        state.record(stack=s.stack,service=s.key,action="update",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,new_image=target,backup=str(backup),result="FAILED",details=details)
        if isinstance(exc, ReviewedTargetChanged):
            raise
        recovery = ("original Compose pin was restored" if pin_written and restored
                    else "original Compose pin was unchanged" if not pin_written
                    else "Compose pin restoration could not be verified")
        raise RuntimeError(f"pinned update failed; {recovery}: {exc}") from None

def _failed_namespace_update(s,state,guard,backup,audit_context):
    guard.failure()
    state.record(stack=s.stack,service=s.key,action='update',old_image=s.image,old_image_id=s.image_id,
        old_digest=s.digest,old_version=s.version,new_image=guard.target_image,backup=str(backup),result='FAILED',
        rollback_result='MANUAL RECOVERY REQUIRED',details={**(audit_context or {}),
            'manual_recovery_required':True,'recovery_required':True,'recovery_attempted':False,
            'mutation_performed':True,'error':'Namespace image update postcondition could not be proved'})
    raise RecoveryRequired('Namespace image update failed; no automatic recovery was attempted; manual recovery is required') from None


@reconcile_operation
def do_update(s,state,*,dry_run=False,yes=False,no_health=False,pin=False,health_timeout=90,input_fn=input,reporter=NULL_REPORTER,output=print,audit_context=None,pre_source_write_check=None,pre_pull_check=None,pre_recreate_check=None,post_pin_check=None,pre_recovery_check=None,target_guard=None,mutation_started=None,project_name=None,namespace_review=None):
    # Explicit single-service CLI updates do not run scan preflight. Keep the
    # same local-identity boundary here before backup, pull, pin or recreate.
    if not s.digest:
        raise PreMutationRefusal(LOCAL_DIGEST_UNVERIFIED, "target_unavailable")
    namespace_update=None
    if (s.network_mode or '').startswith('container:'):
        from .namespace_update import NamespaceImageUpdate
        state.ensure_compatible()
        state.assert_service_unfenced(s)
        if no_health or pin:
            raise PreMutationRefusal('Namespace image updates require complete verification and do not support --no-health or --pin', 'namespace_unsupported_compose')
        namespace_update=NamespaceImageUpdate(s,state,review=namespace_review,audit_context=audit_context)
        project_name=s.stack
        existing_target_guard=target_guard
        def verified_target(stage,observed):
            if existing_target_guard: existing_target_guard(stage,observed)
            namespace_update.target(stage,observed)
        target_guard=verified_target
    else:
        require_mutation_safe(s)
    if parse_image_ref(s.image).digest:
        return _do_pinned_update(s,state,dry_run=dry_run,yes=yes,no_health=no_health,health_timeout=health_timeout,input_fn=input_fn,reporter=reporter,output=output,audit_context=audit_context,pre_source_write_check=pre_source_write_check,pre_pull_check=pre_pull_check,pre_recreate_check=pre_recreate_check,post_pin_check=post_pin_check,pre_recovery_check=pre_recovery_check,target_guard=target_guard,mutation_started=mutation_started,project_name=project_name,namespace_update=namespace_update)
    base=compose_args(s,project_name=project_name); pull=base+["pull",s.key]; up=base+["up","-d","--no-deps",s.key]
    if namespace_update: up=base+["up","-d","--no-deps","--pull","never","--no-build",s.key]
    total=UPDATE_STAGE_TOTAL; reporter.stage(1,total,"Record current state",service=s.key)
    output("Commands:"); output(command_preview(pull)); output(command_preview(up))
    output(f"Would back up: {', '.join(s.compose_files)}" + (f", {s.working_dir}/.env (if used)" if s.working_dir else ""))
    if dry_run:
        reporter.stage(2,total,"Identify backup files",service=s.key)
        with reporter.task("Check remote image",service=s.key): remote=remote_manifest(s.image)
        reporter.stage(3,total,"Check remote image",service=s.key)
        if remote["platforms"] and not any(p["os"] in (None,"linux") and p["architecture"]==s.architecture for p in remote["platforms"]): raise RuntimeError("replacement image does not support the running architecture")
        reporter.stage(4,total,"Verify architecture",service=s.key)
        for n,label in enumerate(("Pull image (not executed)","Recreate container (not executed)","Health check (not executed)","Record update (not executed)"),5): reporter.stage(n,total,label,"pending",s.key)
        output("DRY RUN — no images pulled and no containers recreated."); return
    if not yes and reporter.prompt(f"Update {s.key}? [y/N] ",input_fn).strip().lower() not in {"y","yes"}: output("Cancelled."); return
    state.ensure_compatible()
    state.assert_service_unfenced(s)  # refuse an unsupported state database before any side effect
    if namespace_update: namespace_update.check()
    else: require_mutation_safe(s)
    backup_sources=list(s.compose_files)
    env=Path(s.working_dir)/".env"
    if env.exists(): backup_sources.append(str(env))
    if namespace_update: backup_sources=[item[1] for item in namespace_update.review.inputs if item[2]]
    with reporter.task("Backing up Compose configuration",service=s.key): backup=backup_files(backup_sources,state.root,s)
    reporter.stage(2,total,"Backup configuration",service=s.key)
    with reporter.task("Checking remote image",service=s.key): remote=remote_manifest(s.image)
    reporter.stage(3,total,"Check remote image",service=s.key)
    if remote["platforms"] and not any(p["os"] in (None,"linux") and p["architecture"]==s.architecture for p in remote["platforms"]): raise RuntimeError("replacement image does not support the running architecture")
    reporter.stage(4,total,"Verify architecture",service=s.key)
    side_effect_started=False
    try:
        if pre_pull_check: pre_pull_check()
        if target_guard:
            # `remote` was resolved immediately above and is the fresh result
            # checked for architecture. Bind the pull to that same result; a
            # second registry lookup here could authorize a different target.
            target_guard("registry", remote)
            digest = remote.get("digest")
            if not digest or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(digest)):
                raise ReviewedTargetChanged("The reviewed image target could not be verified. Refresh the service and review the available target again.")
            if namespace_update and digest == s.digest:
                output(f'{s.key} already matches the verified image digest.')
                return {'updated':False,'image':s.image,'digest':s.digest,'version':s.version}
            image_base = s.image.split("@", 1)[0]
            last = image_base.rsplit("/", 1)[-1]
            if ":" in last:
                image_base = image_base.rsplit(":", 1)[0]
            exact_image = f"{image_base}@{digest}"
            # Mutation boundary: nothing below may be reported as "blocked".
            side_effect_started=True
            if mutation_started: mutation_started("pull")
            # Pull the immutable reviewed object, not a mutable tag that may
            # move while Docker is downloading it.
            with reporter.task("Pulling exact reviewed image digest",service=s.key):
                run(["docker", "pull", exact_image], timeout=1800)
            target_guard("pulled", exact_image)
            # Compose still declares the user's tag, so make its local alias
            # resolve to the verified immutable object and forbid Compose
            # from consulting the registry during recreation.
            run(["docker", "image", "tag", exact_image, s.image], timeout=30)
            target_guard("resolved", s.image)
            if pre_recreate_check: pre_recreate_check()
            target_guard("resolved", s.image)
        else:
            side_effect_started=True
            if mutation_started: mutation_started("pull")
            with reporter.task("Pulling image from Docker progress events",service=s.key):
                run_compose_progress(pull,reporter,s.key,cwd=s.working_dir,timeout=1800)
        reporter.stage(5,total,"Pull image",service=s.key)
        if namespace_update: namespace_update.check()
        else: require_mutation_safe(s)
        with reporter.task("Recreating container",service=s.key):
            if namespace_update:
                namespace_update.before_exec()
                mark_changed()
                run(up,cwd=s.working_dir,timeout=600)
            elif target_guard:
                mark_changed()
                run(up[:-1] + ["--pull", "never", up[-1]], cwd=s.working_dir, timeout=600)
            else:
                if pre_recreate_check: pre_recreate_check()
                mark_changed()
                run(up,cwd=s.working_dir,timeout=600)
        reporter.stage(6,total,"Recreate container",service=s.key)
        fresh=next(x for x in discover() if x.stack==s.stack and x.key==s.key)
        if namespace_update: namespace_update.check(fresh)
        deadline=time.time()+health_timeout
        reporter.stage(7,total,"Verify startup and health",state="running",service=s.key)
        if no_health: reporter.note("Health verification skipped by request",service=s.key)
        attempts=1; health_start=time.monotonic()
        while not no_health and fresh.health=="starting" and time.time()<deadline:
            reporter.emit("task_progress",f"Health starting; attempt {attempts}; elapsed {time.monotonic()-health_start:.1f}s",service=s.key,status="running")
            time.sleep(2); attempts+=1; fresh=next(x for x in discover() if x.stack==s.stack and x.key==s.key)
            if namespace_update: namespace_update.check(fresh)
        if fresh.health=="starting" and not no_health: raise RuntimeError(f"health check did not complete within {health_timeout}s; rollback is available")
        if fresh.state!="running" or fresh.health in {"unhealthy"}: raise RuntimeError(f"replacement state is {fresh.state}/{fresh.health}; rollback is available")
        reporter.stage(7,total,"Verify startup and health",service=s.key)
        details = dict(audit_context or {})
        if namespace_update: namespace_update.check(fresh)
        history_id=state.record(stack=s.stack,service=s.key,action="update",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,new_image=fresh.image,new_image_id=fresh.image_id,new_digest=fresh.digest,new_version=fresh.version,backup=str(backup),result="SUCCESS",**({"details": details} if details else {}),**({'namespace_operation_id': namespace_update.operation_id} if namespace_update else {}))
        reporter.stage(8,total,UPDATE_RECORD_LABEL,service=s.key)
        output(f"Updated {s.key}: {fresh.state}/{fresh.health}; previous image is rollback-protected.")
        if pin: do_pin(fresh,state,yes=True,reporter=reporter,output=output)
        return {"updated": True, "history_id": history_id, "image": fresh.image, "version": fresh.version, "digest": fresh.digest, "health": fresh.health}
    except BaseException as e:
        if namespace_update and namespace_update.marked:
            _failed_namespace_update(s,state,namespace_update,backup,audit_context)
        if not isinstance(e, Exception): raise
        failure_details = ({**audit_context, "error": "details redacted for web-triggered operation"}
                           if audit_context else str(e))
        blocked = not side_effect_started and isinstance(e, BLOCKING_REFUSALS)
        if blocked:
            failure_details = {**(audit_context or {}), "error": "details redacted for web-triggered operation" if audit_context else str(e),
                               "blocked": True, "mutation_performed": False,
                               "reason": getattr(e, "reason", "reviewed_target_changed")}
        state.record(stack=s.stack,service=s.key,action="update",old_image=s.image,old_image_id=s.image_id,old_digest=s.digest,old_version=s.version,backup=str(backup),result="BLOCKED" if blocked else "FAILED",details=failure_details)
        raise

@reconcile_operation
def do_rollback(s,state,*,dry_run=False,yes=False,input_fn=input,reporter=NULL_REPORTER):
    # Rollback history may predate conversion to a local build; restoring it
    # would replace the build with a registry image. Classification is the
    # caller's current discovery state, so no registry lookup is needed.
    if s.local_build:
        raise PreMutationRefusal("service is a local build; registry rollback is not available", "service_ineligible")
    require_mutation_safe(s)
    state.ensure_compatible()
    state.assert_service_unfenced(s)  # rollback points are read from state; refuse before planning or mutation
    rows=[r for r in state.history_for_service(s.stack,s.key) if r["action"]=="update" and r["result"]=="SUCCESS"]
    if not rows: raise ValueError("no successful update rollback point exists")
    row=rows[0]
    with state.connect() as c:
        point=c.execute("SELECT expired,purge_status FROM rollback_refs WHERE history_id=?",(row["id"],)).fetchone()
    if point and point[0]: raise ValueError(f"rollback point expired ({point[1] or 'recovery artefacts unavailable'})")
    if row.get("backup") and not Path(row["backup"]).exists(): raise ValueError("rollback configuration backup has expired or is missing")
    old=row["old_image_id"] or row["old_image"]
    base=compose_args(s); args=base+["up","-d","--no-deps",s.key]
    tag=["docker","image","tag",row["old_image_id"],row["old_image"]] if row["old_image_id"] and row["old_image"] and "@" not in row["old_image"] else None
    print(f"Rollback target: {old}\nCompose backup: {row['backup']}")
    if tag: print(command_preview(tag))
    print(command_preview(args))
    if dry_run:
        for n,label in enumerate(("Locate rollback point","Restore Compose configuration","Verify old image","Recreate previous version","Wait for startup","Verify health","Record rollback"),1): reporter.stage(n,7,label,"completed" if n<4 else "pending",s.key)
        print("DRY RUN — no changes made."); return
    if not yes and reporter.prompt(f"Rollback {s.key}? [y/N] ",input_fn).strip().lower() not in {"y","yes"}: print("Cancelled."); return
    require_mutation_safe(s)
    # Compose must reference the old image. Restore exact backed-up sources first.
    reporter.stage(1,7,"Locate rollback point",service=s.key)
    meta=Path(row["backup"])/"metadata.json"; data=json.loads(meta.read_text())
    current=[]
    for item in data["files"]:
        mark_changed()
        mark_project_inputs_changed()
        p=Path(item["source"]); current.append(p); atomic_write(p,Path(item["backup"]).read_text())
    reporter.stage(2,7,"Restore Compose configuration",service=s.key)
    with reporter.task("Validating restored Compose",service=s.key): validate(s)
    if tag:
        with reporter.task("Verifying and retagging old image",service=s.key): run(tag)
    reporter.stage(3,7,"Verify old image",service=s.key)
    require_mutation_safe(s)
    with reporter.task("Recreating previous version",service=s.key): run(args,cwd=s.working_dir,timeout=600)
    reporter.stage(4,7,"Recreate previous version",service=s.key)
    fresh=next(x for x in discover() if x.stack==s.stack and x.key==s.key)
    reporter.stage(5,7,"Wait for startup",service=s.key)
    if fresh.state!="running" or fresh.health=="unhealthy": raise RuntimeError(f"rollback container state is {fresh.state}/{fresh.health}")
    reporter.stage(6,7,f"Verify health ({fresh.health})",service=s.key)
    state.record(stack=s.stack,service=s.key,action="rollback",old_image=s.image,old_image_id=s.image_id,new_image=row["old_image"],new_image_id=row["old_image_id"],result="ROLLED BACK",rollback_result="SUCCESS")
    reporter.stage(7,7,"Record rollback",service=s.key)
    print(f"Rolled back {s.key}; restored Compose configuration and recreated only that service.")

@reconcile_operation
def do_web_rollback(s, row, state, *, sources, operation_id, rollback_command,
                    recovery_command, verify_before_restore, verify_before_recreate,
                    verify_recovery_sources, verify_pre_rollback_recovery,
                    health_timeout=90, reporter=NULL_REPORTER):
    """Run one server-bound rollback with one separately guarded recovery.

    All plan data and verification callbacks are created in the privileged
    agent. The web request carries only its opaque, one-use review reference.
    """
    from .system import CommandError

    require_mutation_safe(s)
    state.assert_completion_unfenced(s)

    expected_command=compose_args(s,project_name=s.stack)+["up","-d","--no-deps","--pull","never",s.compose_service]
    if rollback_command!=expected_command or recovery_command!=expected_command:
        raise ValueError("rollback command did not match the selected Compose service")
    if not isinstance(sources,list) or not sources:
        raise ValueError("rollback source inventory could not be verified")
    if (not re.fullmatch(r"sha256:[0-9a-f]{64}",str(row.get("old_image_id") or ""))
            or not re.fullmatch(r"sha256:[0-9a-f]{64}",str(s.image_id or ""))
            or not isinstance(row.get("old_image"),str) or not row["old_image"]
            or not isinstance(s.image,str) or not s.image):
        raise ValueError("rollback image identity could not be verified")
    for item in sources:
        if (not isinstance(item,dict) or not isinstance(item.get("path"),str)
                or not isinstance(item.get("before"),bytes) or not isinstance(item.get("restore"),bytes)):
            raise ValueError("rollback source inventory could not be verified")

    total=8; recovery_backup=None; restored=[]; rollback_recreate_started=False; running_stage=None
    target_tag_attempted=False; automatically_recovered=False; manual_required=False
    target_image=row.get("old_image"); target_image_id=row.get("old_image_id")
    current_image=s.image; current_image_id=s.image_id

    def verify_image_reference(image_id,reference):
        if (not isinstance(image_id,str) or not re.fullmatch(r"sha256:[0-9a-f]{64}",image_id)
                or not isinstance(reference,str) or not reference):
            raise ValueError("the exact local image reference cannot be verified")
        resolved=run(["docker","image","inspect","--format","{{.Id}}",reference],timeout=30).strip()
        if resolved!=image_id:
            raise RuntimeError("the Compose image reference no longer resolves to the protected local image")

    def tag_local_image(image_id,reference):
        if reference and not parse_image_ref(str(reference)).digest:
            run(["docker","image","tag",image_id,reference],timeout=30)
            verify_image_reference(image_id,reference)

    def restore_current_sources():
        # The pre-rollback identity and recovery backup are proven before any
        # source restoration. Exact bytes are checked again before each write.
        verify_pre_rollback_recovery("before-source-restore",recovery_backup)
        verify_recovery_sources(recovery_backup)
        for item in reversed(tuple(restored)):
            path=Path(item["path"])
            verify_recovery_sources(recovery_backup)
            if path.is_symlink() or not path.is_file() or path.read_bytes()!=item["restore"]:
                raise RuntimeError("a Compose source changed during rollback; automatic recovery was refused")
            atomic_write_bytes(path,item["before"])
            restored.remove(item)
        validate(s,project_name=s.stack)

    def verify_runtime(expected_image_id):
        matches=[x for x in discover() if x.stack==s.stack and x.compose_service==s.compose_service]
        if len(matches)!=1:
            raise RuntimeError("service identity after recreation could not be verified")
        fresh=matches[0]
        deadline=time.monotonic()+max(0,int(health_timeout))
        while fresh.health=="starting" and time.monotonic()<deadline:
            reporter.progress("Health is starting",service=s.key)
            time.sleep(min(2,max(.05,deadline-time.monotonic())))
            matches=[x for x in discover() if x.stack==s.stack and x.compose_service==s.compose_service]
            if len(matches)!=1:
                raise RuntimeError("service identity after recreation could not be verified")
            fresh=matches[0]
        if (fresh.state!="running" or fresh.health in {"unhealthy","starting"}
                or fresh.image_id!=expected_image_id):
            raise RuntimeError("service did not return with the exact expected image and healthy runtime state")

    def record_failure(*, recovery_required=False, recovered=False):
        state.record(stack=s.stack,service=s.key,action="rollback",old_image=current_image,
                     old_image_id=current_image_id,old_digest=s.digest,old_version=s.version,
                     new_image=target_image,new_image_id=target_image_id,
                     backup=str(recovery_backup) if recovery_backup else None,result="FAILED",
                     rollback_result=("MANUAL RECOVERY REQUIRED" if recovery_required else
                                      "AUTOMATIC RECOVERY SUCCEEDED" if recovered else "NO CHANGES MADE"),
                     details={"origin":"web","operation_id":operation_id,
                              "rollback_history_id":int(row["id"]),
                              "recovery_required":bool(recovery_required),
                              "recovery_attempted":bool(rollback_recreate_started),
                              "recovery_result":"manual recovery required" if recovery_required else
                                                "succeeded" if recovered else "not required"})

    try:
        reporter.stage(1,total,"Revalidate rollback point",service=s.key)
        require_mutation_safe(s)
        verify_before_restore("initial")
        with reporter.task("Create pre-rollback recovery backup",service=s.key):
            recovery_backup=backup_files([item["path"] for item in sources],state.root,s)
        reporter.stage(2,total,"Protect current configuration and image",service=s.key)

        for item in sources:
            require_mutation_safe(s)
            verify_before_restore("source-write")
            path=Path(item["path"])
            if path.is_symlink() or not path.is_file() or path.read_bytes()!=item["before"]:
                raise RuntimeError("a Compose source changed before rollback; no source was overwritten")
            mark_changed()
            mark_project_inputs_changed()
            atomic_write_bytes(path,item["restore"])
            restored.append(item)
        reporter.stage(3,total,"Restore retained Compose configuration",service=s.key)
        with reporter.task("Validate restored Compose configuration",service=s.key): validate(s,project_name=s.stack)
        reporter.stage(4,total,"Validate restored Compose",service=s.key)

        verify_before_recreate()
        if target_image and not parse_image_ref(str(target_image)).digest:
            target_tag_attempted=True
            with reporter.task("Bind exact protected image locally",service=s.key):
                tag_local_image(target_image_id,target_image)
        verify_before_recreate()
        verify_image_reference(target_image_id,target_image)
        reporter.stage(5,total,"Verify protected rollback image",service=s.key)
        running_stage=(6,"Recreate selected service without dependencies")
        reporter.stage(6,total,"Recreate selected service without dependencies",state="running",service=s.key)
        require_mutation_safe(s)
        rollback_recreate_started=True
        mark_changed()
        with reporter.task("Recreate selected service without pulling",service=s.key):
            run(rollback_command,cwd=s.working_dir,timeout=600)
        reporter.stage(6,total,"Recreate selected service without dependencies",service=s.key)
        running_stage=(7,"Verify startup and health")
        reporter.stage(7,total,"Verify startup and health",state="running",service=s.key)
        verify_runtime(target_image_id)
        reporter.stage(7,total,"Verify startup and health",service=s.key)
        running_stage=None
        state.record(stack=s.stack,service=s.key,action="rollback",old_image=current_image,
                     old_image_id=current_image_id,old_digest=s.digest,old_version=s.version,
                     new_image=target_image,new_image_id=target_image_id,backup=str(recovery_backup),
                     result="ROLLED BACK",rollback_result="SUCCESS",
                     details={"origin":"web","operation_id":operation_id,
                              "rollback_history_id":int(row["id"]),"recovery_required":False})
        reporter.stage(8,total,"Record rollback outcome",service=s.key)
        return {"rolled_back":True,"history_id":int(row["id"]),"image":target_image,
                "version":row.get("old_version"),"digest":row.get("old_digest"),
                "recovery_backup":str(recovery_backup)}
    except (OSError, RuntimeError, ValueError, TypeError, KeyError, CommandError):
        if running_stage:  # the step that was in flight is the one that failed
            reporter.stage(running_stage[0],total,running_stage[1],state="failed",service=s.key)
        if rollback_recreate_started:
            try:
                # First validate the captured model/image and all UPT-owned
                # source bytes; restore only then, revalidate live model, and
                # perform the separately bounded recovery recreation once.
                restore_current_sources()
                verify_pre_rollback_recovery("before-recovery-recreate",recovery_backup)
                tag_local_image(current_image_id,current_image)
                verify_pre_rollback_recovery("before-recovery-recreate",recovery_backup)
                verify_image_reference(current_image_id,current_image)
                reporter.note("Recovering previous service once",service=s.key)
                recovery_service = next((x for x in discover(all_containers=True) if x.stack == s.stack and x.key == s.key), s)
                require_mutation_safe(recovery_service, allow_absent=True)
                run(recovery_command,cwd=s.working_dir,timeout=600)
                verify_runtime(current_image_id)
                automatically_recovered=True
            except (OSError, RuntimeError, ValueError, TypeError, KeyError, CommandError):
                manual_required=True
        else:
            if restored:
                try: restore_current_sources()
                except (OSError, RuntimeError, ValueError, TypeError, KeyError, CommandError): manual_required=True
            if target_tag_attempted:
                try: tag_local_image(current_image_id,current_image)
                except (OSError, RuntimeError, ValueError, TypeError, KeyError, CommandError): manual_required=True
        try:
            record_failure(recovery_required=manual_required,recovered=automatically_recovered)
            # The final numbered stage is the success record; a failure is persisted
            # to History but is reported as a marker, never as a completed/failed step.
            reporter.note("Recorded manual recovery requirement" if manual_required else "Recorded rollback failure",service=s.key)
        except (OSError, RuntimeError, ValueError, TypeError, KeyError):
            manual_required=True
        if manual_required: raise WebRollbackFailure(manual_recovery_required=True) from None
        if automatically_recovered: raise WebRollbackFailure(recovered=True) from None
        raise WebRollbackFailure() from None


@reconcile_operation
def do_restart(service, *, state=None, dry_run=False, reporter=NULL_REPORTER, output=print):
    require_mutation_safe(service)
    if state is not None:
        state.assert_completion_unfenced(service)
    command = compose_args(service) + ["restart", "--no-deps", service.key]
    if dry_run:
        output("DRY RUN\n" + command_preview(command))
        return
    with reporter.task("Restarting container", service=service.key):
        mark_changed()
        run(command, cwd=service.working_dir)
