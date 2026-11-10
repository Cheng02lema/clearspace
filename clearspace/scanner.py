"""Bounded, read-only size estimation; never follows symbolic links."""
import os
import stat
import time


def path_size(path, *, max_nodes=4000, max_seconds=0.9):
    state = {'nodes': 0, 'partial': False}
    deadline = time.monotonic() + max_seconds

    def visit(current):
        if state['nodes'] >= max_nodes or time.monotonic() >= deadline:
            state['partial'] = True
            return 0
        info = os.lstat(current)
        state['nodes'] += 1
        if state['nodes'] >= max_nodes or time.monotonic() >= deadline:
            state['partial'] = True
            return 0
        # Windows junctions and other reparse points must not be traversed.
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            return info.st_size
        if not stat.S_ISDIR(info.st_mode):
            return info.st_size
        total = 0
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    if state['nodes'] >= max_nodes or time.monotonic() >= deadline:
                        state['partial'] = True
                        break
                    try:
                        total += visit(entry.path)
                    except OSError:
                        state['partial'] = True
        except OSError:
            state['partial'] = True
        return total

    return {'bytes': visit(path), 'partial': state['partial']}
