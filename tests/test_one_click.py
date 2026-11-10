import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from clearspace.one_click import action_plan, cleanup_plan
from clearspace import workflow


class OneClickPlanningTests(unittest.TestCase):
    def test_excludes_restores_and_resolves_conflicting_location_options(self):
        actions = [
            {'id': 'block-location', 'title': '关闭定位', 'exclusiveWith': ['block-location-sync-language']},
            {'id': 'block-location-sync-language', 'title': '关闭定位并同步语言', 'exclusiveWith': ['block-location']},
            {'id': 'restore-dns', 'title': '恢复 DNS'},
            {'id': 'protect-dns', 'title': '保护 DNS'},
        ]
        selected, skipped = action_plan(actions)
        self.assertEqual({a['id'] for a in selected}, {'block-location-sync-language', 'protect-dns'})
        self.assertEqual([x['item']['id'] for x in skipped], ['block-location'])

    def test_cleanup_prefers_parent_and_does_not_select_blocked_items(self):
        def target(ident, location, kind='file', blocked=False):
            return {'id': ident, 'title': ident, 'exists': True, 'blockedReason': 'blocked' if blocked else None,
                    'resources': [{'exists': True, 'displayPath': location, 'kind': kind}]}
        targets = [target('child', r'C:\Users\Alice\App\data\settings.json'),
                   target('parent', r'C:\Users\Alice\App\data', 'directory'),
                   target('blocked', r'C:\Users\Alice\blocked', blocked=True)]
        selected, skipped = cleanup_plan(targets)
        self.assertEqual([x['id'] for x in selected], ['parent'])
        self.assertEqual([x['item']['id'] for x in skipped], ['child'])

    def test_does_not_confuse_neighboring_directory_names(self):
        targets = [
            {'id': 'a', 'title': 'a', 'exists': True, 'resources': [{'exists': True, 'displayPath': r'C:\app\data', 'kind': 'directory'}]},
            {'id': 'b', 'title': 'b', 'exists': True, 'resources': [{'exists': True, 'displayPath': r'C:\app\data2\settings', 'kind': 'file'}]},
        ]
        selected, skipped = cleanup_plan(targets)
        self.assertEqual(len(selected), 2)
        self.assertFalse(skipped)


class FakeCore:
    def __init__(self, changed_path=False):
        self.calls = []
        self.changed_path = changed_path
        self.actions = [
            {'id': 'protect-dns', 'title': '保护 DNS', 'description': '保护', 'exclusiveWith': ['restore-dns']},
            {'id': 'claude-environment', 'title': '环境变量', 'description': '清理环境'},
            {'id': 'restore-dns', 'title': '恢复 DNS'},
        ]

    def call(self, command, **payload):
        self.calls.append((command, payload))
        if command == 'scan':
            return [{'id': 'fixture', 'title': 'fixture', 'exists': True, 'resources': [
                {'exists': True, 'displayPath': r'C:\test\selected', 'kind': 'file'}]}]
        if command == 'actions': return self.actions
        if command == 'prepare-close': return {'empty': True}
        if command == 'inspect-recovery': return {'available': True, 'dns': {'ownershipEvidence': False, 'loopbackLocked': False}}
        if command == 'prepare-clean':
            return {'token': 'clean-token', 'items': ['fixture', '    ' + (r'C:\test\other' if self.changed_path else r'C:\test\selected')]}
        if command == 'clean': return {'results': [{'id': 'fixture', 'status': 'cleaned'}]}
        if command == 'prepare-privacy': return {'token': 'privacy-token'}
        if command == 'privacy': return {'results': [{'id': payload['ids'][0], 'status': 'completed', 'message': 'ok'}]}
        raise AssertionError(command)


class OneClickWorkflowTests(unittest.TestCase):
    def test_run_and_restore_only_backed_settings(self):
        core = FakeCore()
        with tempfile.TemporaryDirectory() as temp:
            journal = workflow.Journal(Path(temp).resolve() / 'journal.json')
            with patch('clearspace.workflow.state_presence', return_value=False):
                plan = workflow.prepare(core)
            result = workflow.execute(core, plan, journal=journal, presence=lambda action: False, signature=lambda action: 'signature')
            self.assertEqual(result['status'], 'completed')
            stored = journal.load()
            self.assertEqual(stored['cleanup'][0]['restorable'], False)
            self.assertEqual([x['id'] for x in stored['actions'] if x['restoreEligible']], ['protect-dns'])
            recovery = workflow.prepare_restore(core, journal=journal, signature=lambda action: 'signature')
            self.assertEqual([x['id'] for x in recovery['actions']], ['protect-dns'])
            result = workflow.restore(core, recovery, journal=journal, signature=lambda action: 'signature')
            self.assertEqual(result['status'], 'completed')
            self.assertTrue(journal.load()['actions'][0]['restored'])
            self.assertIn(('privacy', {'ids': ['restore-dns'], 'token': 'privacy-token', 'acknowledged': True}), core.calls)

    def test_changed_cleanup_paths_stop_before_deletion_or_settings(self):
        core = FakeCore(changed_path=True)
        with tempfile.TemporaryDirectory() as temp:
            journal = workflow.Journal(Path(temp).resolve() / 'journal.json')
            with patch('clearspace.workflow.state_presence', return_value=False):
                plan = workflow.prepare(core)
            result = workflow.execute(core, plan, journal=journal, presence=lambda action: False)
            self.assertEqual(result['status'], 'interrupted')
            self.assertNotIn('clean', [x[0] for x in core.calls])
            self.assertNotIn('privacy', [x[0] for x in core.calls])

    def test_prior_recovery_record_is_not_overwritten(self):
        core = FakeCore()
        with tempfile.TemporaryDirectory() as temp:
            journal = workflow.Journal(Path(temp).resolve() / 'journal.json')
            journal.save({'schema': 1, 'actions': [{'id': 'protect-dns', 'restoreEligible': True, 'restored': False}]})
            with patch('clearspace.workflow.state_presence', return_value=False):
                plan = workflow.prepare(core)
            with self.assertRaisesRegex(RuntimeError, '一键恢复'):
                workflow.execute(core, plan, journal=journal, presence=lambda action: False)
            self.assertNotIn('clean', [x[0] for x in core.calls])

    def test_existing_backup_is_not_claimed_by_new_operation(self):
        core = FakeCore()
        with tempfile.TemporaryDirectory() as temp:
            journal = workflow.Journal(Path(temp).resolve() / 'journal.json')
            with patch('clearspace.workflow.state_presence', return_value=True):
                plan = workflow.prepare(core)
            workflow.execute(core, plan, journal=journal, presence=lambda action: True, signature=lambda action: 'state')
            dns = next(x for x in journal.load()['actions'] if x['id'] == 'protect-dns')
            self.assertFalse(dns['restoreEligible'])

    def test_changed_recovery_record_is_not_applied(self):
        core = FakeCore()
        with tempfile.TemporaryDirectory() as temp:
            journal = workflow.Journal(Path(temp).resolve() / 'journal.json')
            journal.save({'schema': 1, 'cleanup': [], 'actions': [{'id': 'protect-dns', 'title': 'DNS',
                           'restoreEligible': True, 'restored': False, 'stateSignature': 'original'}]})
            plan = workflow.prepare_restore(core, journal=journal, signature=lambda action: 'changed')
            self.assertFalse(plan['actions'])
            self.assertEqual([x['id'] for x in plan['unavailable']], ['protect-dns'])
            self.assertNotIn('privacy', [x[0] for x in core.calls])

    def test_rechecks_recovery_state_after_confirmation(self):
        core = FakeCore()
        with tempfile.TemporaryDirectory() as temp:
            journal = workflow.Journal(Path(temp).resolve() / 'journal.json')
            journal.save({'schema': 1, 'cleanup': [], 'actions': [{'id': 'protect-dns', 'title': 'DNS',
                           'restoreEligible': True, 'restored': False, 'stateSignature': 'original'}]})
            plan = workflow.prepare_restore(core, journal=journal, signature=lambda action: 'original')
            result = workflow.restore(core, plan, journal=journal, signature=lambda action: 'changed')
            self.assertEqual(result['status'], 'completed-with-errors')
            self.assertNotIn('privacy', [x[0] for x in core.calls])
            self.assertFalse(journal.load()['actions'][0]['restored'])


if __name__ == '__main__':
    unittest.main()
