"""Shared assertions for the operation progress model.

A numbered stage is ``"<n>/<N> <label>"``. For one operation: every stage uses the
workflow's real total ``N``; numbers never go backwards; a number completes at
most once and nothing happens to it afterwards; informational events are never
numbered; and the terminal event is last, with nothing recorded after it.
"""
import re

STAGE = re.compile(r"^(\d+)/(\d+) (.+)$")
TERMINAL_KINDS = {"operation_completed", "operation_failed", "operation_blocked"}
PROGRESS_KINDS = {"task_started", "task_progress", "task_completed", "task_failed"}


def numbered(events):
    """(number, total, label, kind, status) for each numbered persisted progress event."""
    found = []
    for event in events:
        match = STAGE.match(event.get("stage") or "")
        if match and event.get("kind") in PROGRESS_KINDS:
            found.append((int(match[1]), int(match[2]), match[3], event["kind"], event.get("status")))
    return found


def assert_stage_model(case, events, total, *, terminal=True):
    """Validate persisted operation events; return the completed stage numbers in order."""
    stages = numbered(events)
    case.assertTrue(all(item[1] == total for item in stages), [item[:3] for item in stages])
    highest = 0
    completed = []
    closed = set()
    labels = {}
    for number, _total, label, kind, status in stages:
        case.assertEqual(labels.setdefault(number, label), label, f"stage {number} changed its label mid-stage")
        case.assertGreaterEqual(number, highest, f"stage {number} {label!r} went backwards")
        case.assertNotIn(number, closed, f"stage {number} {label!r} changed after it finished")
        highest = number
        if status in {"completed", "failed"}:
            closed.add(number)
        if status == "completed":
            completed.append(number)
    case.assertEqual(completed, sorted(set(completed)))
    for event in events:
        if event.get("kind") in {"operation_started", "task_info", "task_running"} or event.get("status") in {"queued", "info"}:
            case.assertIsNone(STAGE.match(event.get("stage") or ""), f"informational event is numbered: {event}")
    ids = [event["id"] for event in events]
    case.assertEqual(ids, sorted(ids))
    terminal_events = [event for event in events if event.get("kind") in TERMINAL_KINDS]
    if terminal:
        case.assertEqual(len(terminal_events), 1, [event.get("kind") for event in events])
        case.assertIs(events[-1], terminal_events[0], "nothing may be recorded after the terminal event")
    else:
        case.assertEqual(terminal_events, [])
    return completed


def assert_core_stage_model(case, reporter_events, total):
    """The same rules for raw core Reporter events (before persistence)."""
    stages = [(e.data["step"], e.data["steps"], e.data["label"], e.status) for e in reporter_events
              if e.kind.startswith("task_") and "step" in e.data]
    case.assertTrue(stages)
    case.assertTrue(all(item[1] == total for item in stages), stages)
    highest, completed, labels = 0, [], {}
    for number, _total, label, status in stages:
        case.assertEqual(labels.setdefault(number, label), label, f"stage {number} changed its label mid-stage")
        case.assertGreaterEqual(number, highest, f"stage {number} {label!r} went backwards")
        highest = number
        if status == "completed":
            case.assertNotIn(number, completed, f"stage {number} {label!r} completed twice")
            completed.append(number)
    return completed
