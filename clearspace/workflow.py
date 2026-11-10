"""One-click orchestration with a reviewable plan and conservative recovery."""
import json
import hashlib
import os
from pathlib import Path
import tempfile
from datetime import datetime, timezone

from .one_click import action_plan, cleanup_plan

RESTORE_MAP = {
    'protect-dns': 'restore-dns',
    'block-location-sync-language': 'restore-browser-location-language',
}


def state_presence(action_id):
    """Whether a legacy recovery record existed; None means not safely known."""
    if os.name != 'nt':
        return None
    appdata = os.environ.get('APPDATA')
    if not appdata or not Path(appdata).is_absolute():
        return None
    user_data = Path(appdata) / '澄界'
    try:
        def exists(candidate):
            try:
                candidate.lstat()
                return True
            except FileNotFoundError:
                return False
        if action_id == 'protect-dns':
            return exists(user_data / 'dns-leak-protection-state.json')
        if action_id == 'block-location-sync-language':
            import winreg
            profile_exists = exists(user_data / 'browser-location-language-profiles.json')
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'Software\KelaudeStudio\Cleaner') as key:
                    try:
                        winreg.QueryValueEx(key, 'BrowserLocationLanguageState')
                        policy_exists = True
                    except FileNotFoundError:
                        policy_exists = False
            except FileNotFoundError:
                policy_exists = False
            return profile_exists or policy_exists
    except OSError:
        return None
    return None


def state_signature(action_id):
    """Fingerprint saved legacy recovery state without storing its contents."""
    if os.name != 'nt' or not os.environ.get('APPDATA'):
        return None
    root = Path(os.environ['APPDATA']) / '澄界'
    if not root.is_absolute():
        return None
    digest = hashlib.sha256()
    found = False
    try:
        file_name = ('dns-leak-protection-state.json' if action_id == 'protect-dns'
                     else 'browser-location-language-profiles.json' if action_id == 'block-location-sync-language' else None)
        if not file_name:
            return None
        file_path = root / file_name
        try:
            info = file_path.lstat()
            if file_path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400 or not file_path.is_file() or info.st_size > 4 * 1024 * 1024:
                return None
            contents = file_path.read_bytes()
            after = file_path.lstat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                return None
            digest.update(file_name.encode('utf-8') + b'\0' + contents)
            found = True
        except FileNotFoundError:
            pass
        if action_id == 'block-location-sync-language':
            import winreg
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'Software\KelaudeStudio\Cleaner') as key:
                    value, kind = winreg.QueryValueEx(key, 'BrowserLocationLanguageState')
                    encoded = repr((kind, value)).encode('utf-8')
                    if len(encoded) > 4 * 1024 * 1024:
                        return None
                    digest.update(b'\0registry\0' + encoded)
                    found = True
            except FileNotFoundError:
                pass
        return digest.hexdigest() if found else None
    except (OSError, ValueError):
        return None


def journal_path():
    base = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else None
    if not base or not Path(base).is_absolute():
        base = str(Path.home() / '.local' / 'share')
    return Path(base) / 'ClearspacePython' / 'one-click.json'


class Journal:
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else journal_path()

    def load(self):
        try:
            info = self.path.lstat()
            if self.path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400 or not self.path.is_file() or info.st_size > 1024 * 1024:
                return None
            data = json.loads(self.path.read_text(encoding='utf-8'))
            return data if isinstance(data, dict) and data.get('schema') == 1 else None
        except (OSError, ValueError):
            return None

    def save(self, record):
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # A hostile reparse point in any parent would redirect the journal.
        for part in (self.path.parent, *self.path.parent.parents):
            st = part.lstat()
            if part.is_symlink() or getattr(st, 'st_file_attributes', 0) & 0x400:
                raise RuntimeError('操作记录目录包含链接或重解析点，已停止。')
        fd, name = tempfile.mkstemp(prefix='one-click-', suffix='.tmp', dir=self.path.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(record, stream, ensure_ascii=False, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.isfile(name):
                os.unlink(name)


def prepare(core):
    scan = core.call('scan')
    actions = core.call('actions')
    clean, overlap = cleanup_plan(scan)
    settings, conflicts = action_plan(actions)
    if len(clean) > 500 or len(settings) > 16:
        raise RuntimeError('扫描结果过多，请分批手动处理。')
    closed = core.call('prepare-close')
    unavailable = [item for item in scan if item.get('exists') and item.get('blockedReason')]
    baseline = {key: state_presence(key) for key in RESTORE_MAP}
    if baseline['protect-dns'] is False:
        try:
            inspection = core.call('inspect-recovery')
            dns = inspection.get('dns', {})
            if not inspection.get('available'):
                baseline['protect-dns'] = None
            elif dns.get('ownershipEvidence') or dns.get('loopbackLocked'):
                baseline['protect-dns'] = True
        except Exception:
            baseline['protect-dns'] = None
    return {'cleanup': clean, 'settings': settings, 'overlap': overlap, 'conflicts': conflicts, 'unavailable': unavailable,
            'close': closed, 'baseline': baseline}


def _paths(targets):
    return sorted(os.path.normcase(os.path.normpath(resource['displayPath']))
                  for target in targets for resource in target.get('resources', [])
                  if resource.get('exists') and resource.get('displayPath'))


def _prepared_paths(prepared):
    return sorted(os.path.normcase(os.path.normpath(item[4:]))
                  for item in prepared.get('items', []) if item.startswith('    '))


def execute(core, plan, journal=None, progress=lambda message: None, presence=state_presence, signature=state_signature):
    """Execute only the confirmed plan, stopping if cleanup scope changes."""
    journal = journal or Journal()
    existing = journal.load()
    if existing is None and journal.path.exists():
        raise RuntimeError('先前的一键操作记录无法读取，已停止以免覆盖恢复信息。')
    if existing and any(item.get('restoreEligible') and not item.get('restored')
                        for item in existing.get('actions', [])):
        raise RuntimeError('上一次一键操作仍有可恢复的设置，请先完成一键恢复。')
    record = {'schema': 1, 'createdAt': datetime.now(timezone.utc).isoformat(), 'status': 'running',
              'cleanup': [], 'actions': []}
    journal.save(record)  # Persist before any modification.
    results = []
    try:
        close = plan['close']
        if not close.get('empty'):
            progress('正在关闭已确认的浏览器…')
            result = core.call('close', token=close['token'], acknowledged=True)
            if result.get('remaining') or result.get('status') not in ('closed', 'not-running'):
                raise RuntimeError('浏览器未全部关闭，已停止后续操作。')
        if plan['cleanup']:
            progress('正在重新核对清理范围…')
            ids = [item['id'] for item in plan['cleanup']]
            prepared = core.call('prepare-clean', ids=ids)
            if _prepared_paths(prepared) != _paths(plan['cleanup']):
                raise RuntimeError('清理路径在确认后发生变化，已停止；请重新预检。')
            record['cleanup'] = [{'id': item['id'], 'title': item['title'], 'status': 'attempting',
                                  'restorable': False} for item in plan['cleanup']]
            journal.save(record)
            progress('正在清理已确认的数据…')
            result = core.call('clean', ids=ids, token=prepared['token'], acknowledged=True)
            clean_results = {x.get('id'): x for x in result.get('results', [])}
            for item in record['cleanup']:
                outcome = clean_results.get(item['id'], {})
                item['status'] = outcome.get('status', 'unknown')
                if outcome.get('resources'):
                    item['detail'] = '；'.join(x.get('error') for x in outcome['resources'] if x.get('error'))
            journal.save(record)
            results.extend({'title': x['title'], 'status': x['status'], 'message': x.get('detail', '')} for x in record['cleanup'])
            if any(x['status'] not in ('cleaned', 'skipped') for x in record['cleanup']):
                raise RuntimeError('部分清理未完成，已停止后续设置。')
        for action in plan['settings']:
            ident = action['id']
            progress('正在执行：' + action['title'])
            # Do not reuse an older recovery record, which represents a state before this run.
            baseline = plan['baseline'].get(ident)
            eligible = ident in RESTORE_MAP and baseline is False and presence(ident) is False
            entry = {'id': ident, 'title': action['title'], 'status': 'attempting',
                     'restoreEligible': eligible, 'restored': False}
            record['actions'].append(entry)
            journal.save(record)
            try:
                prepared = core.call('prepare-privacy', ids=[ident])
                response = core.call('privacy', ids=[ident], token=prepared['token'], acknowledged=True)
                outcome = next((x for x in response.get('results', []) if x.get('id') == ident), {})
                entry['status'] = outcome.get('status', 'failed')
                entry['message'] = outcome.get('message', '未收到操作结果。')
            except Exception as error:
                entry['status'] = 'failed'
                entry['message'] = str(error)
            if eligible:
                entry['stateSignature'] = signature(ident)
                if not entry['stateSignature']:
                    entry['restoreEligible'] = False
            journal.save(record)
            results.append({'title': entry['title'], 'status': entry['status'], 'message': entry['message']})
        record['status'] = 'completed' if all(x['status'] in ('cleaned', 'skipped', 'completed') for x in results) else 'completed-with-errors'
    except Exception as error:
        record['status'] = 'interrupted'
        record['error'] = str(error)
        results.append({'title': '一键启动', 'status': 'failed', 'message': str(error)})
    journal.save(record)
    return {'status': record['status'], 'results': results}


def prepare_restore(core, journal=None, signature=state_signature):
    journal = journal or Journal()
    record = journal.load()
    if not record:
        if journal.path.exists():
            raise RuntimeError('一键操作记录无法读取，未执行恢复。')
        return {'empty': True, 'message': '没有找到本应用的一键操作记录。过去未备份的清理数据无法恢复。'}
    candidates = [entry for entry in record.get('actions', [])
                  if entry.get('restoreEligible') and not entry.get('restored') and entry.get('id') in RESTORE_MAP]
    actions, unavailable = [], []
    for entry in candidates:
        current_signature = signature(entry['id'])
        if current_signature and current_signature == entry.get('stateSignature'):
            actions.append(entry)
        else:
            unavailable.append(entry)
    close = core.call('prepare-close') if actions else {'empty': True}
    return {'record': record, 'actions': actions, 'unavailable': unavailable, 'close': close}


def restore(core, plan, journal=None, progress=lambda message: None, signature=state_signature):
    journal = journal or Journal()
    current = journal.load()
    if current != plan['record']:
        raise RuntimeError('操作记录在确认后发生变化，请重新检查。')
    close = plan['close']
    if not close.get('empty'):
        result = core.call('close', token=close['token'], acknowledged=True)
        if result.get('remaining') or result.get('status') not in ('closed', 'not-running'):
            raise RuntimeError('浏览器未全部关闭，已停止恢复。')
    results = []
    for original in reversed(plan['actions']):
        ident = original['id']
        entry = next(x for x in current['actions'] if x['id'] == ident)
        progress('正在恢复：' + entry['title'])
        try:
            if not entry.get('stateSignature') or signature(ident) != entry['stateSignature']:
                raise RuntimeError('恢复记录已改变或不可读取，已跳过以保护当前设置。')
            restore_id = RESTORE_MAP[ident]
            prepared = core.call('prepare-privacy', ids=[restore_id])
            response = core.call('privacy', ids=[restore_id], token=prepared['token'], acknowledged=True)
            result = next((x for x in response.get('results', []) if x.get('id') == restore_id), {})
            status = result.get('status', 'failed')
            message = result.get('message', '未收到恢复结果。')
            if status == 'completed':
                entry['restored'] = True
        except Exception as error:
            status, message = 'failed', str(error)
        entry['restoreStatus'] = status
        entry['restoreMessage'] = message
        journal.save(current)
        results.append({'title': entry['title'], 'status': status, 'message': message})
    return {'status': 'completed' if all(x['status'] == 'completed' for x in results) else 'completed-with-errors',
            'results': results}
