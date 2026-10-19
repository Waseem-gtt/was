import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from cyber_platform.server import App


class SchedulerGateTests(unittest.TestCase):
    def test_disabled_or_future_schedule_never_takes_execution_gate(self):
        for config in ({}, {'enabled':False}, {'enabled':True,'next_at':time.time()+3600}):
            with self.subTest(config=config):
                app=SimpleNamespace(store=Mock(),execution_lock=Mock())
                app.store.setting.return_value=config
                with patch('cyber_platform.server.knowledge.scheduled_tick') as tick:
                    self.assertFalse(App.run_scheduled_tick(app))
                    app.execution_lock.acquire.assert_not_called()
                    tick.assert_not_called()

    def test_due_schedule_respects_busy_gate_and_releases_after_failure(self):
        app=SimpleNamespace(store=Mock(),execution_lock=Mock())
        app.store.setting.return_value={'enabled':True,'next_at':0}
        app.execution_lock.acquire.return_value=False
        with patch('cyber_platform.server.knowledge.scheduled_tick') as tick:
            self.assertFalse(App.run_scheduled_tick(app))
            tick.assert_not_called()
            app.execution_lock.release.assert_not_called()
        app.execution_lock.acquire.return_value=True
        with patch('cyber_platform.server.knowledge.scheduled_tick',side_effect=RuntimeError('fixture failure')):
            with self.assertRaises(RuntimeError):
                App.run_scheduled_tick(app)
        app.execution_lock.release.assert_called_once()
