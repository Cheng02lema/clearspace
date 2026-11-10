"""Read-only planning helpers for the combined workflow.

These functions do not clean files or change system settings.
"""
import ntpath
import os
from .action_groups import ACTION_GROUPS, action_group


PREFERRED_ACTIONS = ('block-location-sync-language',)


def action_plan(actions):
    """Select non-restore actions, preferring the combined location option.

    Returns both selections and conflict exclusions for display before execution.
    """
    candidates = [item for item in actions if item['id'] in ACTION_GROUPS and action_group(item)[1] == 'settings']
    ordered = sorted(candidates, key=lambda item: (item['id'] not in PREFERRED_ACTIONS,))
    chosen = []
    skipped = [{'item': item, 'reason': '尚未核实是否属于恢复操作'}
               for item in actions if item['id'] not in ACTION_GROUPS]
    for item in ordered:
        conflict = next((selected for selected in chosen
                         if selected['id'] in item.get('exclusiveWith', [])
                         or item['id'] in selected.get('exclusiveWith', [])), None)
        if conflict:
            skipped.append({'item': item, 'reason': f'与“{conflict["title"]}”互斥'})
        else:
            chosen.append(item)
    return chosen, skipped


def _paths(target):
    return [item for item in target.get('resources', [])
            if item.get('exists') and item.get('displayPath')]


def _contained(child, parent):
    left, right = child['displayPath'], parent['displayPath']
    paths = ntpath if ntpath.splitdrive(left)[0] or ntpath.splitdrive(right)[0] else os.path
    try:
        left = paths.normcase(paths.normpath(left))
        right = paths.normcase(paths.normpath(right))
        if left == right:
            return True
        return parent.get('kind') == 'directory' and paths.commonpath((left, right)) == right
    except ValueError:
        return False


def cleanup_plan(targets):
    """Choose available, non-overlapping targets, with broad paths first."""
    available = [item for item in targets if item.get('exists') and not item.get('blockedReason') and _paths(item)]
    def depth(target):
        return min(len(ntpath.normpath(r['displayPath']).replace('\\', '/').split('/')) for r in _paths(target))
    ordered = sorted(available, key=lambda item: (depth(item), -len(_paths(item))))
    chosen, skipped = [], []
    for item in ordered:
        conflict = next((other for other in chosen
                         if other['id'] in item.get('exclusiveWith', [])
                         or item['id'] in other.get('exclusiveWith', [])
                         or any(_contained(a, b) or _contained(b, a)
                                for a in _paths(item) for b in _paths(other))), None)
        if conflict:
            skipped.append({'item': item, 'reason': f'与“{conflict["title"]}”重叠或互斥'})
        else:
            chosen.append(item)
    return chosen, skipped
