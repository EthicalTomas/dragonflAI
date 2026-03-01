"""Tests for the create_run API endpoint enqueue behaviour.

Verifies that job_timeout and retry are forwarded to rq.Queue.enqueue.
"""

import sys
import types
import unittest
from unittest.mock import MagicMock, patch


def _build_mock(name: str) -> types.ModuleType:
    mod = MagicMock()
    mod.__name__ = name
    mod.__spec__ = None
    return mod


_MOCKED_MODULES = [
    "fastapi",
    "redis",
    "rq",
    "rq.job",
    "sqlalchemy",
    "sqlalchemy.orm",
    "backend",
    "backend.app",
    "backend.app.core",
    "backend.app.core.config",
    "backend.app.db",
    "backend.app.db.session",
    "backend.app.models",
    "backend.app.schemas",
    "backend.app.schemas.run",
]

_original_modules: dict = {}


def setUpModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        _original_modules[name] = sys.modules.get(name)
        sys.modules[name] = _build_mock(name)

    # Wire up fastapi stubs so the router decorator works without a real FastAPI.
    router_mock = MagicMock()
    router_mock.post.return_value = lambda f: f
    router_mock.get.return_value = lambda f: f
    sys.modules["fastapi"].APIRouter.return_value = router_mock
    sys.modules["fastapi"].Depends.return_value = None
    sys.modules["fastapi"].HTTPException = Exception


def tearDownModule() -> None:  # noqa: N802
    for name in _MOCKED_MODULES:
        original = _original_modules.get(name)
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
    sys.modules.pop("backend.app.api.routes.runs", None)


def _load_runs_module():
    """Import (or reload) the runs route module after mocks are in place."""
    import importlib.util

    sys.modules.pop("backend.app.api.routes.runs", None)
    spec = importlib.util.spec_from_file_location(
        "backend.app.api.routes.runs",
        "backend/app/api/routes/runs.py",
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["backend.app.api.routes.runs"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestCreateRunEnqueue(unittest.TestCase):
    """Verify that create_run passes job_timeout and retry to rq enqueue."""

    def _make_run(self, run_id: int = 1) -> MagicMock:
        run = MagicMock()
        run.id = run_id
        run.target_id = 10
        run.status = "queued"
        run.progress = 0
        run.config_json = "{}"
        run.log_text = ""
        return run

    def test_enqueue_passes_job_timeout(self) -> None:
        """create_run must forward job_timeout to rq.Queue.enqueue."""
        mod = _load_runs_module()

        mock_run = self._make_run(1)
        mock_db = MagicMock()
        mock_db.get.return_value = MagicMock()  # target exists
        mock_db.refresh.side_effect = lambda obj: None

        mock_queue = MagicMock()
        mock_settings = MagicMock()
        mock_settings.redis_url = "redis://localhost:6379/0"
        mock_settings.job_timeout_seconds = 3600

        mod.settings = mock_settings
        mod.Redis = MagicMock(return_value=MagicMock())
        mod.Queue = MagicMock(return_value=mock_queue)
        mod.Run = MagicMock(return_value=mock_run)
        mod.Retry = MagicMock()

        body = MagicMock()
        body.target_id = 10
        body.modules = []
        body.config = {}

        mod.create_run(body, db=mock_db)

        call_kwargs = mock_queue.enqueue.call_args
        self.assertIsNotNone(call_kwargs, "enqueue was not called")
        kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
        self.assertIn("job_timeout", kwargs, "job_timeout not passed to enqueue")
        self.assertEqual(kwargs["job_timeout"], 3600)

    def test_enqueue_passes_retry(self) -> None:
        """create_run must forward a Retry object to rq.Queue.enqueue."""
        mod = _load_runs_module()

        mock_run = self._make_run(2)
        mock_db = MagicMock()
        mock_db.get.return_value = MagicMock()
        mock_db.refresh.side_effect = lambda obj: None

        mock_queue = MagicMock()
        mock_settings = MagicMock()
        mock_settings.redis_url = "redis://localhost:6379/0"
        mock_settings.job_timeout_seconds = 3600

        mod.settings = mock_settings
        mod.Redis = MagicMock(return_value=MagicMock())
        mod.Queue = MagicMock(return_value=mock_queue)
        mod.Run = MagicMock(return_value=mock_run)
        fake_retry = object()
        mod.Retry = MagicMock(return_value=fake_retry)

        body = MagicMock()
        body.target_id = 10
        body.modules = []
        body.config = {}

        mod.create_run(body, db=mock_db)

        call_kwargs = mock_queue.enqueue.call_args
        kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
        self.assertIn("retry", kwargs, "retry not passed to enqueue")

    def test_job_timeout_uses_settings_value(self) -> None:
        """job_timeout passed to enqueue must come from settings.job_timeout_seconds."""
        mod = _load_runs_module()

        mock_run = self._make_run(3)
        mock_db = MagicMock()
        mock_db.get.return_value = MagicMock()
        mock_db.refresh.side_effect = lambda obj: None

        mock_queue = MagicMock()
        mock_settings = MagicMock()
        mock_settings.redis_url = "redis://localhost:6379/0"
        mock_settings.job_timeout_seconds = 7200  # custom value

        mod.settings = mock_settings
        mod.Redis = MagicMock(return_value=MagicMock())
        mod.Queue = MagicMock(return_value=mock_queue)
        mod.Run = MagicMock(return_value=mock_run)
        mod.Retry = MagicMock()

        body = MagicMock()
        body.target_id = 10
        body.modules = []
        body.config = {}

        mod.create_run(body, db=mock_db)

        call_kwargs = mock_queue.enqueue.call_args
        kwargs = call_kwargs.kwargs if call_kwargs.kwargs else call_kwargs[1]
        self.assertEqual(kwargs["job_timeout"], 7200)


if __name__ == "__main__":
    unittest.main()
