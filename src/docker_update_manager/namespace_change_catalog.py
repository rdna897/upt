"""Namespace Stage 2 positive change catalogue (Layer A, 2026-10-05).

Hash calibration is necessary but never mutation authority. Initial Stage 2 may
change only the selected-consumer fields/shapes positively exercised by Layer A.
A field outside the catalogue may stay present and unchanged where Stage 1 proof
accepts it; any baseline -> desired difference involving it is refused. The
catalogue is deliberately independent of compose_namespace.HASH_FIELDS, which
only describes what the hash reconstruction understands.

Each validator receives the raw value on one side (None when absent) and must
accept only the exact bounded shape that Layer A exercised.
"""
from __future__ import annotations

import os
import re

from .compose_namespace import NamespaceRefused

REASON = 'namespace_change_unqualified'
_TEXT = 4096


def _text(value, limit=_TEXT):
    return isinstance(value, str) and len(value) <= limit and '\x00' not in value


def _string_map(value):
    """Explicit environment/label map of strings (inherit-from-shell is refused by inventory)."""
    return (isinstance(value, dict) and len(value) <= 512
            and all(_text(key, 256) and _text(item, 65536) for key, item in value.items()))


def _script(value):
    return _text(value, 8192) and bool(value)


def command_entrypoint_qualified(entrypoint, command):
    """The exact (entrypoint, command) combinations Layer A exercised.

    * shape-command: no entrypoint, command ["sh", "-c", <script>];
    * shape-entrypoint: entrypoint ["sh", "-c"] coupled with command [<script>];
    * neither field set.

    Neither half of the pair is qualified alone, and an empty list is a distinct
    shape, not absence (it is never mapped to None).
    """
    if entrypoint is None and command is None:
        return True
    if entrypoint is None:
        return (isinstance(command, list) and len(command) == 3 and command[:2] == ['sh', '-c']
                and _script(command[2]))
    return entrypoint == ['sh', '-c'] and isinstance(command, list) and len(command) == 1 and _script(command[0])


def _restart(value):
    return value == 'unless-stopped'


def _logging(value):
    if not isinstance(value, dict) or set(value) != {'driver', 'options'} or value['driver'] != 'json-file':
        return False
    options = value['options']
    return (isinstance(options, dict) and 0 < len(options) <= 2 and set(options) <= {'max-size', 'max-file'}
            and all(isinstance(item, str) for item in options.values())
            and re.fullmatch(r'[1-9][0-9]{0,8}[kmg]?', options.get('max-size', '1')) is not None
            and re.fullmatch(r'[1-9][0-9]{0,3}', options.get('max-file', '1')) is not None)


def _volumes(value):
    """Existing, absolute, read-only long-syntax bind with create_host_path=false."""
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        return False
    for mount in value:
        if (not isinstance(mount, dict) or set(mount) != {'type', 'source', 'target', 'read_only', 'bind'}
                or mount['type'] != 'bind' or mount['read_only'] is not True
                or mount['bind'] != {'create_host_path': False}
                or not _text(mount['source']) or not os.path.isabs(mount['source'])
                or not _text(mount['target']) or not os.path.isabs(mount['target'])):
            return False
        try:
            if not os.path.isdir(mount['source']):
                return False
        except OSError:
            return False
    return True


# A catalogue field is changed only if each non-absent side is a qualified shape.
CATALOGUE = {'environment': _string_map, 'labels': _string_map, 'restart': _restart, 'logging': _logging,
             'volumes': _volumes}
# command/entrypoint are validated only as a coupled pair, never independently.
COUPLED = ('entrypoint', 'command')
# Compared by the existing relationship/image gates, not by this catalogue.
_HANDLED_ELSEWHERE = frozenset({'network_mode', 'depends_on', 'image'})


def refuse_unqualified_changes(baseline, desired):
    """Raise NamespaceRefused unless every changed field/shape is Layer A-qualified.

    Never carries a field value: callers only see the fixed reason.
    """
    if not isinstance(baseline, dict) or not isinstance(desired, dict):
        raise NamespaceRefused(REASON)
    # Exact resolved-value comparison: no generic empty-map/list normalisation. An
    # empty command/entrypoint is a distinct changed shape and is refused below.
    for field in sorted(set(baseline) | set(desired)):
        if field in _HANDLED_ELSEWHERE or field in COUPLED or baseline.get(field) == desired.get(field):
            continue
        accept = CATALOGUE.get(field)
        if accept is None:
            raise NamespaceRefused(REASON)
        for side in (baseline.get(field), desired.get(field)):
            if side is not None and not accept(side):
                raise NamespaceRefused(REASON)
    if any(baseline.get(field) != desired.get(field) for field in COUPLED):
        for model in (baseline, desired):
            if not command_entrypoint_qualified(model.get('entrypoint'), model.get('command')):
                raise NamespaceRefused(REASON)
