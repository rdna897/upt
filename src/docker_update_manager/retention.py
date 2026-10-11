"""Retention for recovery artefacts owned exclusively by Docker Update Manager."""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
import json, os, shutil, sqlite3
from pathlib import Path
from .diskdiag import du, parse_size
from .progress import NULL_REPORTER
from .system import run, CommandError

MANAGED_DIRS=("backups","conversion-file-backups","conversion-snapshots","restore-bundles","tmp","compose-recoveries")
TERMINAL_PURGE_STATUSES={"PURGED","ALREADY ABSENT"}
# Only unambiguous legacy history identities confer rollback eligibility.
_LEGACY_CANDIDATE=(
    "p.history_id IS NOT NULL "
    "AND NOT EXISTS (SELECT 1 FROM rollback_refs r WHERE r.history_id=p.history_id) "
    "AND (SELECT COUNT(*) FROM protected_images other WHERE other.history_id=p.history_id)=1"
)
_LEGACY_REF_CANDIDATES="SELECT p.history_id,p.image_id,p.created FROM protected_images p WHERE "+_LEGACY_CANDIDATE
# A protection is resolved by retention only through its own rollback ref.
# Anything else (manual/NULL-history, ambiguous or mismatched legacy rows) is
# unresolved and must block image removal regardless of other expired refs.
def _matching_ref(table="p"):
    return f"EXISTS (SELECT 1 FROM rollback_refs r WHERE r.history_id={table}.history_id AND r.image_id={table}.image_id)"
def _resolved_protection():
    # Its own ref exists and no active ref still needs the image.
    return (_matching_ref("protected_images")+" AND NOT EXISTS (SELECT 1 FROM rollback_refs active "
            "WHERE active.image_id=protected_images.image_id AND active.expired=0)")
_UNRESOLVED_PROTECTION=(
    "SELECT 1 FROM protected_images p WHERE p.image_id=? "
    "AND NOT "+_matching_ref()+" AND NOT ("+_LEGACY_CANDIDATE+")"
)

def _utc(value=None):
    if value is None: return datetime.now(timezone.utc)
    if isinstance(value,datetime): return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.fromisoformat(str(value).replace("Z","+00:00")).replace(tzinfo=timezone.utc) if "+" not in str(value)[10:] else datetime.fromisoformat(str(value))

def expires(created,days): return _utc(created)+timedelta(days=int(days))
def expired(created,days,now=None): return expires(created,days)<=_utc(now)

def _settings(cfg):
    r=cfg.data.get("retention",{}); base=int(r.get("recovery_days",7))
    return {"compose_backups_days":int(r.get("compose_backups_days",base)),"rollback_images_days":int(r.get("rollback_images_days",base)),
            "operational_logs_days":int(r.get("operational_logs_days",base)),"temporary_files_days":int(r.get("temporary_files_days",base)),
            "disk_history_days":int(r.get("disk_history_days",30)),"audit_history_days":int(r.get("audit_history_days",365)),
            "resolved_rollback_metadata_days":int(r.get("resolved_rollback_metadata_days",30))}

def _artifact_created(path): return datetime.fromtimestamp(path.stat().st_mtime,timezone.utc)

def inventory(cfg,state,now=None,image_details=False):
    now=_utc(now); settings=_settings(cfg); artifacts=[]
    for dirname in MANAGED_DIRS:
        root=state.root/dirname
        if dirname == "compose-recoveries":
            artifacts.extend(_compose_artifacts(state, settings["compose_backups_days"], now))
            continue
        if not root.exists(): continue
        days=settings["compose_backups_days"] if dirname in {"backups","conversion-file-backups","conversion-snapshots","restore-bundles"} else settings["temporary_files_days"]
        for path in root.iterdir():
            try:
                created=_artifact_created(path); size=du(path) if path.is_dir() else path.stat().st_size
                artifacts.append({"kind":dirname,"path":str(path),"created":created.isoformat(),"expires":expires(created,days).isoformat(),"expired":expired(created,days,now),"size":size})
            except OSError: pass
    logs=[]
    if cfg.log_dir.exists():
        for path in cfg.log_dir.iterdir():
            if not path.is_file(): continue
            created=_artifact_created(path); days=settings["operational_logs_days"]
            logs.append({"kind":"operational-log","path":str(path),"created":created.isoformat(),"expires":expires(created,days).isoformat(),"expired":expired(created,days,now),"size":path.stat().st_size})
    refs=rollback_points(cfg,state,now,image_details=image_details)
    return {"settings":settings,"artifacts":artifacts,"logs":logs,"rollback_images":refs,
            "total_size":sum(x["size"] for x in artifacts+logs),"expired_size":sum(x["size"] for x in artifacts+logs if x["expired"]),
            "expiring_24h_size":sum(x["size"] for x in artifacts+logs if not x["expired"] and x.get("protection", "terminal") == "terminal" and _utc(x["expires"])<=now+timedelta(hours=24))}

def _compose_artifacts(state, days, now):
    from .compose_recovery_retention import checked_bundle, lifecycle
    root = state.root / "compose-recoveries"
    if root.is_symlink() or not root.is_dir():
        return []
    artifacts = []
    with state.read() as c:
        for path in root.iterdir():
            try:
                with checked_bundle(state.root, path) as bundle:
                    status, finished = lifecycle(c, path.name, bundle)
                    created = _utc(finished) if finished else datetime.fromtimestamp(bundle["created"], timezone.utc)
                    artifacts.append({"kind": "compose-recoveries", "path": str(path),
                                      "created": created.isoformat(), "expires": expires(created, days).isoformat(),
                                      "expired": status == "terminal" and expired(created, days, now),
                                      "size": bundle["size"], "protection": status})
            except (OSError, ValueError, TypeError, RecursionError):
                # No untrusted path/name/content is projected into inventory.
                continue
    return artifacts


def _cleanup_compose_artifact(state, path, days, now, dry_run):
    from .compose_recovery_retention import checked_bundle, lifecycle, remove_bundle
    # Serialize lifecycle proof/deletion against pruning and terminal writes.
    with state.connect() as c:
        with checked_bundle(state.root, path) as bundle:
            status, finished = lifecycle(c, path.name, bundle)
            if status != "terminal" or not finished or not expired(finished, days, now):
                raise ValueError("recovery evidence is protected")
            if not dry_run:
                remove_bundle(path, bundle)
                c.execute("DELETE FROM compose_recovery_receipts WHERE operation_id=?", (path.name,))


def _migrate_refs(state):
    if not state.db_path.exists(): return
    with state.connect() as c:
        c.execute("INSERT OR IGNORE INTO rollback_refs(history_id,image_id,created) " + _LEGACY_REF_CANDIDATES)

def _docker_image_accounting():
    """Return Docker's own per-image logical and unique-size accounting."""
    try:
        payload=json.loads(run(["docker","system","df","-v","--format","{{json .}}"],timeout=120))
    except Exception:
        return {}
    out={}
    for row in payload.get("Images",[]):
        image_id=str(row.get("ID") or "")
        if not image_id: continue
        repository=str(row.get("Repository") or "<none>"); tag=str(row.get("Tag") or "<none>")
        out[image_id]={"image":f"{repository}:{tag}","size":parse_size(row.get("Size") or "0B"),
                       "unique_size":parse_size(row.get("UniqueSize") or "0B"),
                       "shared_size":parse_size(row.get("SharedSize") or "0B"),
                       "containers":int(row.get("Containers") or 0)}
    return out

def _image_info(accounting,image_id):
    if image_id in accounting: return accounting[image_id]
    matches=[v for key,v in accounting.items() if key.startswith(image_id) or image_id.startswith(key)]
    return matches[0] if len(matches)==1 else {}

def _removal_blocker(state,image_id,*,check_active):
    """Revalidate image removal in a short read immediately before acting."""
    with state.read() as c:
        if check_active and c.execute("SELECT 1 FROM rollback_refs WHERE image_id=? AND expired=0 LIMIT 1",(image_id,)).fetchone():
            return "SKIPPED - SHARED ACTIVE ROLLBACK"
        if c.execute(_UNRESOLVED_PROTECTION,(image_id,)).fetchone():
            return "SKIPPED - UNRESOLVED PROTECTION"
    return None

def rollback_points(cfg,state,now=None,image_details=False):
    if not state.db_path.exists(): return []
    days=_settings(cfg)["rollback_images_days"]; now=_utc(now)
    # Project exactly the candidates used by _migrate_refs without mutating
    # state; NULL or ambiguous history identities remain protected separately.
    with state.read() as c:
        c.row_factory=sqlite3.Row
        rows=c.execute(
            "SELECT r.*,h.stack,h.service,h.old_image,h.old_version,h.old_digest,h.result "
            "FROM (SELECT history_id,image_id,created,expired,purge_status FROM rollback_refs "
            "UNION ALL "
            "SELECT legacy.history_id,legacy.image_id,legacy.created,0,NULL FROM (" +
            _LEGACY_REF_CANDIDATES + ") legacy"
            ") r LEFT JOIN history h ON h.id=r.history_id ORDER BY r.created DESC"
        ).fetchall()
    # Docker may take up to 120 seconds. Neither a write reservation nor a
    # read snapshot should be held while the subprocess is running.
    accounting=_docker_image_accounting() if image_details else {}
    out=[]
    for row in rows:
        item=dict(row); expiry=expires(item["created"],days); item["expires"]=expiry.isoformat()
        purge=item.get("purge_status") or ""
        if purge in TERMINAL_PURGE_STATUSES: item["status"]=purge
        elif purge=="SKIPPED - IMAGE IN USE": item["status"]="IMAGE IN USE"
        else: item["status"]="EXPIRED" if expiry<=now or item["expired"] else "AVAILABLE"
        info=_image_info(accounting,item["image_id"]); item.update(info)
        item["image"]=info.get("image") or item.get("old_image") or item["image_id"]
        item["size"]=info.get("size")
        item["unique_size"]=info.get("unique_size")
        item["containers"]=info.get("containers")
        item["potential_reclaimable"]=(info.get("unique_size") or 0) if info.get("containers")==0 else 0
        out.append(item)
    return out

def _image_exists(image_id):
    try: run(["docker","image","inspect",image_id],timeout=30); return True
    except CommandError as exc:
        if "no such image" in str(exc).lower(): return False
        return None


def _container_image_ids():
    ids=run(["docker","ps","-aq"],timeout=30).split()
    if not ids: return set()
    try: return {x.get("Image") for x in json.loads(run(["docker","inspect",*ids],timeout=60)) if x.get("Image")}
    except Exception: return set()

def cleanup(cfg,state,*,dry_run=False,reporter=NULL_REPORTER,automatic=False,now=None,service=None,stack=None,override_protection=False,all_protected=False):
    if not dry_run: _migrate_refs(state)
    now=_utc(now); inv=inventory(cfg,state,now,image_details=True); expired_files=[x for x in inv["artifacts"]+inv["logs"] if x["expired"]]
    if all_protected and service: raise ValueError("--all cannot be combined with --service")
    if stack and not service: raise ValueError("--stack requires --service")
    if override_protection and not service and not all_protected: raise ValueError("--override-protection requires --service or --all")
    forced=override_protection or all_protected
    service_points=[x for x in inv["rollback_images"] if x.get("service")==service and
                    x.get("purge_status") not in TERMINAL_PURGE_STATUSES] if service else []
    selected_service_points=[]
    if override_protection and service and service_points:
        if stack is None:
            stacks={x.get("stack") for x in service_points}
            if None in stacks:
                raise ValueError(
                    f"rollback protection for service {service!r} includes history with unproven stack identity; "
                    "specify --stack to select proven history or use --all"
                )
            if len(stacks)>1:
                raise ValueError(f"rollback protection for service {service!r} exists in multiple stacks; specify --stack")
            stack=next(iter(stacks))
        history_ids={row["id"] for row in state.history_for_service(stack,service)}
        selected_service_points=[x for x in service_points if x["history_id"] in history_ids]
    points=[x for x in inv["rollback_images"] if x.get("purge_status") not in TERMINAL_PURGE_STATUSES and
            (x["status"] in {"EXPIRED","IMAGE IN USE"} or all_protected or (override_protection and x in selected_service_points))]
    if forced and not points: raise ValueError(f"no rollback protection found{f' for service: {service}' if service else ''}")
    if automatic and not expired_files and not points: return {"files_removed":0,"images_removed":0,"skipped":[],"reclaimed":0}
    task_total=len(expired_files)+len({p["image_id"] for p in points})
    reporter.start("retention",f"{'Previewing' if dry_run else 'Cleaning'} expired UPT recovery data",total=task_total)
    result={"files_removed":0,"images_removed":0,"images_absent":0,"skipped":[],"failures":[],"reclaimed":0,
            "expired_files":len(expired_files),"expired_images":len(points),"unique_images":len({p["image_id"] for p in points}),
            "dry_run":dry_run,"override_protection":forced,"all_protected":all_protected,"planned_images":[],"database":{}}
    index=0
    for item in expired_files:
        index+=1; path=Path(item["path"])
        if item["kind"] == "compose-recoveries":
            try:
                _cleanup_compose_artifact(state, path, inv["settings"]["compose_backups_days"], now, dry_run)
                if not dry_run:
                    result["files_removed"] += 1
                    result["reclaimed"] += item["size"]
                reporter.advance(index, task_total, path.name, "would purge" if dry_run else "purged")
            except (OSError, ValueError, TypeError, RecursionError):
                result["skipped"].append({"path": str(path), "reason": "RECOVERY EVIDENCE PROTECTED OR UNSAFE"})
            continue
        # Refuse any path that is not a direct descendant of an explicitly managed root.
        allowed=[state.root/d for d in MANAGED_DIRS if d != "compose-recoveries"]+[cfg.log_dir]
        if not any(path.parent.resolve()==root.resolve() for root in allowed): result["skipped"].append({"path":str(path),"reason":"OUTSIDE MANAGED ROOT"}); continue
        if dry_run: reporter.advance(index,task_total,path.name,"would purge"); continue
        try:
            if path.is_dir(): shutil.rmtree(path)
            else: path.unlink()
            result["files_removed"]+=1; result["reclaimed"]+=item["size"]; reporter.advance(index,task_total,path.name,"purged")
        except OSError as e: result["skipped"].append({"path":str(path),"reason":str(e)}); reporter.warning(str(e),path.name)
    in_use=_container_image_ids() if points else set()
    # Expire audit refs first, then remove an image only when every ref is expired.
    if dry_run:
        grouped={}
        selected={p["history_id"] for p in points}
        for point in inv["rollback_images"]:
            grouped.setdefault(point["image_id"],0)
            if point["status"]!="EXPIRED" and point["history_id"] not in selected: grouped[point["image_id"]]+=1
        refs=list(grouped.items())
    else:
        with state.connect() as c:
            purge_status="MANUALLY EXPIRED" if forced else "EXPIRED"
            warned=set()
            for point in points:
                if forced and point["image_id"] in in_use:
                    if point["image_id"] not in warned:
                        reason="SKIPPED - IMAGE IN USE"; result["skipped"].append({"image":point["image_id"],"reason":reason}); reporter.warning(reason,point["image_id"][:19]); warned.add(point["image_id"])
                    continue
                c.execute("UPDATE rollback_refs SET expired=1,purge_status=? WHERE history_id=?",(purge_status,point["history_id"]))
            refs=c.execute("SELECT image_id, SUM(CASE WHEN expired=0 THEN 1 ELSE 0 END) FROM rollback_refs GROUP BY image_id").fetchall()
    for image_id,active_refs in refs:
        image_points=[p for p in points if p["image_id"]==image_id]
        if not image_points: continue
        index+=1
        if active_refs:
            if not (forced and image_id in in_use):
                reason="SKIPPED - SHARED ACTIVE ROLLBACK"; result["skipped"].append({"image":image_id,"reason":reason}); reporter.warning(reason,image_id[:19])
            continue
        # Earlier Docker removals may have taken minutes; real cleanup also
        # rechecks active refs published since the batch counts above.
        reason=_removal_blocker(state,image_id,check_active=not dry_run)
        if reason:
            result["skipped"].append({"image":image_id,"reason":reason}); reporter.warning(reason,image_id[:19]); continue
        if image_id in in_use:
            reason="SKIPPED - IMAGE IN USE"; result["skipped"].append({"image":image_id,"reason":reason})
            with state.connect() as c: c.execute("UPDATE rollback_refs SET purge_status=? WHERE image_id=? AND expired=1",(reason,image_id))
            reporter.warning(reason,image_id[:19]); continue
        info=next((p for p in image_points if p.get("unique_size") is not None),{})
        image_known=bool(info)
        if dry_run:
            presence=True if image_known else _image_exists(image_id)
            if presence is False: action,planned="would reconcile already-absent image","RECONCILE ABSENT"
            elif presence is True: action,planned="would remove rollback image","REMOVE"
            else: action,planned="would verify image during cleanup","VERIFY"
            result["planned_images"].append({"image_id":image_id,"image":image_points[0].get("image") or image_id,
                                             "service":image_points[0].get("service"),"reclaimable":max((p.get("potential_reclaimable",0) for p in image_points),default=0),
                                             "action":planned})
            reporter.advance(index,task_total,image_id[:19],action); continue
        terminal=None
        try:
            run(["docker","image","rm",image_id],timeout=300)
            terminal="PURGED"; result["images_removed"]+=1
            result["reclaimed"]+=max((p.get("potential_reclaimable",0) for p in image_points),default=0)
        except CommandError as e:
            if "no such image" in str(e).lower(): terminal="ALREADY ABSENT"; result["images_absent"]+=1
            else:
                reason="SKIPPED - "+str(e); result["skipped"].append({"image":image_id,"reason":reason}); result["failures"].append({"image":image_id,"reason":str(e)})
                with state.connect() as c: c.execute("UPDATE rollback_refs SET purge_status=? WHERE image_id=? AND expired=1",(reason,image_id))
                reporter.warning(reason,image_id[:19]); continue
        except Exception as e:
            reason="SKIPPED - "+str(e); result["skipped"].append({"image":image_id,"reason":reason}); result["failures"].append({"image":image_id,"reason":str(e)})
            reporter.warning(reason,image_id[:19]); continue
        with state.connect() as c:
            c.execute("UPDATE rollback_refs SET purge_status=? WHERE image_id=? AND expired=1",(terminal,image_id))
            c.execute("UPDATE history SET rollback_result=? WHERE id IN (SELECT history_id FROM rollback_refs WHERE image_id=? AND expired=1)",(terminal,image_id))
            c.execute("DELETE FROM protected_images WHERE image_id=? AND "+_resolved_protection(),(image_id,))
        reporter.advance(index,task_total,image_id[:19],"removed" if terminal=="PURGED" else "already absent; reconciled")
    if not dry_run:
        disk_cutoff=(now-timedelta(days=inv["settings"]["disk_history_days"])).strftime("%Y-%m-%d %H:%M:%S")
        resolved_cutoff=(now-timedelta(days=inv["settings"]["resolved_rollback_metadata_days"])).strftime("%Y-%m-%d %H:%M:%S")
        audit_cutoff=(now-timedelta(days=inv["settings"]["audit_history_days"])).strftime("%Y-%m-%d %H:%M:%S")
        with state.connect() as c:
            before=c.total_changes
            c.execute("DELETE FROM disk_snapshots WHERE timestamp<?",(disk_cutoff,))
            # Retire resolved protections before their terminal refs, and keep a
            # terminal ref while any protection still uses its history_id (even
            # for another image): that occupied ID is what keeps the remaining
            # protection from being re-migrated as an active, expirable ref.
            c.execute("DELETE FROM protected_images WHERE "+_resolved_protection())
            c.execute("DELETE FROM rollback_refs WHERE expired=1 AND purge_status IN ('PURGED','ALREADY ABSENT') AND created<? "
                      "AND NOT EXISTS (SELECT 1 FROM protected_images p WHERE p.history_id=rollback_refs.history_id)",
                      (resolved_cutoff,))
            c.execute("DELETE FROM history WHERE timestamp<? AND id NOT IN (SELECT history_id FROM rollback_refs)",(audit_cutoff,))
            c.execute("PRAGMA optimize")
            result["database"]["rows_pruned"]=c.total_changes-before
        result["database"].update(state.compact_if_needed())
    reporter.finish(f"Retention cleanup complete: {result['files_removed']} artefact(s), {result['images_removed']} image(s), {result['images_absent']} absent image(s) reconciled")
    return result
