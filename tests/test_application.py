import tempfile
import time
import unittest
import subprocess
from pathlib import Path
from unittest import mock

from clearspace.client import CoreClient, CoreError
from clearspace.scanner import path_size


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.client = CoreClient()

    def tearDown(self):
        self.client.close()

    def test_catalog_and_request_validation(self):
        from clearspace.action_groups import ACTION_GROUPS
        self.assertTrue(self.client.call('ping')['ready'])
        ids = {x['id'] for x in self.client.call('actions')}
        self.assertEqual(ids, set(ACTION_GROUPS))
        self.assertIn('protect-dns', ids)
        self.assertIn('restore-dns', ids)
        with self.assertRaises(CoreError):
            self.client.call('prepare-privacy', ids=['protect-dns', 'restore-dns'])
        with self.assertRaises(CoreError):
            self.client.call('prepare-privacy', ids=['unknown'])

    def test_confirmation_is_bound_and_consumed_on_mismatch(self):
        prepared = self.client.call('prepare-privacy', ids=['claude-environment'])
        token = prepared['token']
        with self.assertRaises(CoreError):
            self.client.call('privacy', ids=['mail-cookie'], token=token, acknowledged=True)
        with self.assertRaises(CoreError):
            self.client.call('privacy', ids=['claude-environment'], token=token, acknowledged=True)

    def test_missing_acknowledgement_cannot_execute(self):
        prepared = self.client.call('prepare-privacy', ids=['claude-environment'])
        with self.assertRaises(CoreError):
            self.client.call('privacy', ids=['claude-environment'], token=prepared['token'], acknowledged=False)

    def test_read_only_recovery_inspection(self):
        result = self.client.call('inspect-recovery')
        self.assertIn('dns', result)
        self.assertIn('proxy', result)

    def test_old_node_version_is_rejected_before_backend_starts(self):
        with mock.patch('clearspace.client.shutil.which', return_value='node'), \
             mock.patch('clearspace.client.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout='18.20.0\n')), \
             mock.patch('clearspace.client.subprocess.Popen') as popen:
            with self.assertRaisesRegex(CoreError, '24.4'):
                self.client.call('ping')
            popen.assert_not_called()


class ScannerTests(unittest.TestCase):
    def test_size_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'one').write_bytes(b'hello')
            (root / 'two').write_bytes(b'world')
            self.assertEqual(path_size(root)['bytes'], 10)
            self.assertTrue(path_size(root, max_nodes=1)['partial'])


class FakeCore:
    def call(self, command, **payload):
        if command == 'actions':
            return [
                {'id': 'block-location', 'title': '关闭浏览器定位', 'description': '描述一', 'risk': 'high', 'exclusiveWith': ['restore-browser-location-language']},
                {'id': 'restore-browser-location-language', 'title': '恢复浏览器定位与语言', 'description': '描述二', 'risk': 'medium', 'exclusiveWith': ['block-location']},
                {'id': 'protect-dns', 'title': '强制 DNS 防泄漏', 'description': '描述三', 'risk': 'high', 'exclusiveWith': ['restore-dns']},
                {'id': 'restore-dns', 'title': '恢复 DNS', 'description': '描述四', 'risk': 'medium', 'exclusiveWith': ['protect-dns']},
            ]
        return {}

    def close(self):
        pass


class WindowTests(unittest.TestCase):
    def test_motion_can_be_disabled(self):
        from clearspace.app import ClearspaceApp, AnimatedMark
        with mock.patch('clearspace.app.CoreClient', FakeCore):
            app = ClearspaceApp()
            try:
                app.update()
                mark = next(child for group in app.sidebar.winfo_children() for child in group.winfo_children()
                            if isinstance(child, AnimatedMark))
                app.motion.set(False)
                before = mark.angle
                mark._tick()
                self.assertEqual(mark.angle, before)
                app.motion.set(True)
                mark._tick()
                self.assertNotEqual(mark.angle, before)
            finally:
                app.destroy()

    def test_views_and_mutual_exclusion(self):
        from clearspace.app import ClearspaceApp
        with mock.patch('clearspace.app.CoreClient', FakeCore):
            app = ClearspaceApp()
            try:
                for _ in range(30):
                    app.update()
                    if not app.busy:
                        break
                    time.sleep(.02)
                self.assertEqual(len(app.actions), 4)
                app._navigate('browser')
                app.update()
                self.assertEqual([a['id'] for a in app._page_actions()], ['block-location', 'restore-browser-location-language'])
                self.assertEqual(len(app.scroll.body.grid_slaves()), 2)
                app._toggle_action(app.actions[0], True)
                app._toggle_action(app.actions[1], True)
                app.update()
                self.assertFalse(app.action_selections['block-location'])
                self.assertTrue(app.action_selections['restore-browser-location-language'])
                app._navigate('system')
                app.update()
                self.assertEqual([a['id'] for a in app._page_actions()], ['protect-dns', 'restore-dns'])
                app._toggle_action(app.actions[2], True)
                with mock.patch.object(app, '_work') as work:
                    app._prepare_privacy()
                    self.assertEqual(work.call_args.kwargs['ids'], ['protect-dns'])
                with mock.patch.object(app, '_show_result_details'):
                    app._completed('privacy', {'results': []}, {'ids': ['protect-dns']})
                self.assertTrue(app.action_selections['restore-browser-location-language'])
                self.assertNotIn('protect-dns', app.action_selections)
                app._navigate('recovery')
                app.recovery = {'dns': {'needsRecovery': False}, 'proxy': {'canRepairAutomatically': False}}
                app.render()
                app.update()
                app._navigate('clean')
                app.update()
                self.assertGreaterEqual(app.winfo_width(), 1020)
            finally:
                app.destroy()


if __name__ == '__main__':
    unittest.main()
