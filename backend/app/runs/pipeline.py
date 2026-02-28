import logging
import os
import time
from collections.abc import Callable

from sqlalchemy.orm import Session

from backend.app.models import Run, RunStatus, Target
from backend.app.scope.validator import ScopeValidator
from backend.app.services.runs_service import append_log, set_progress, set_status

logger = logging.getLogger(__name__)


def _dummy_module(
    target: Target,
    config: dict,
    artifacts_dir: str,
    scope_validator: ScopeValidator,
) -> None:
    time.sleep(2)
    logger.info("Dummy module complete")


class ReconPipeline:
    def __init__(self, run_id: int, db: Session, scope_validator: ScopeValidator) -> None:
        self.run_id = run_id
        self.db = db
        self.scope_validator = scope_validator
        self.registry: dict[str, Callable] = {
            "dummy": _dummy_module,
        }

    def execute(self, modules: list[str], config: dict) -> None:
        run = self.db.get(Run, self.run_id)
        if run is None:
            logger.warning("ReconPipeline: run_id=%d not found", self.run_id)
            return

        target = self.db.get(Target, run.target_id)
        if target is None:
            logger.warning("ReconPipeline: target_id=%d not found for run_id=%d", run.target_id, self.run_id)
            set_status(self.db, run, RunStatus.FAILED)
            append_log(self.db, run, f"Target id={run.target_id} not found.")
            self.db.commit()
            return

        set_status(self.db, run, RunStatus.RUNNING)
        self.db.commit()

        artifacts_dir = os.path.join("artifacts", str(run.target_id), str(self.run_id))
        os.makedirs(artifacts_dir, exist_ok=True)

        total = len(modules)
        for i, module_name in enumerate(modules):
            append_log(self.db, run, f"Running module: {module_name}")
            self.db.commit()

            fn = self.registry.get(module_name)
            if fn is None:
                logger.warning(
                    "ReconPipeline: module %r not found in registry, skipping",
                    module_name,
                )
                append_log(self.db, run, f"Warning: module '{module_name}' not found, skipping")
                self.db.commit()
                continue

            fn(target, config, artifacts_dir, self.scope_validator)

            progress = int((i + 1) / total * 100) if total else 100
            set_progress(self.db, run, progress)
            self.db.commit()

        set_progress(self.db, run, 100)
        set_status(self.db, run, RunStatus.SUCCEEDED)
        self.db.commit()
