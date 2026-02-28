import json
import logging
import traceback

from sqlalchemy.orm import Session

from backend.app.models import Program, Run, RunStatus, Target
from backend.app.runs.pipeline import ReconPipeline
from backend.app.scope.parser import parse_scope_text
from backend.app.scope.validator import ScopeValidator
from backend.app.services.runs_service import append_log, set_status

logger = logging.getLogger(__name__)


class RunOrchestrator:
    def __init__(self, run_id: int, db: Session) -> None:
        self.run_id = run_id
        self.db = db

    def execute(self) -> None:
        run = None
        try:
            run = self.db.get(Run, self.run_id)
            if run is None:
                logger.warning("RunOrchestrator: run_id=%d not found", self.run_id)
                return

            target = self.db.get(Target, run.target_id)
            if target is None:
                raise ValueError(f"Target id={run.target_id} not found for run_id={self.run_id}")

            program = self.db.get(Program, target.program_id)
            if program is None:
                raise ValueError(f"Program id={target.program_id} not found for run_id={self.run_id}")

            if not program.scope_text:
                append_log(self.db, run, "No scope rules defined. Cannot proceed.")
                set_status(self.db, run, RunStatus.FAILED)
                self.db.commit()
                return

            rules = parse_scope_text(program.scope_text)
            scope_validator = ScopeValidator(rules)

            config_data = json.loads(run.config_json or "{}")
            modules = config_data.get("modules", [])
            config = config_data.get("config", {})

            pipeline = ReconPipeline(self.run_id, self.db, scope_validator)
            return pipeline.execute(modules, config)

        except Exception:
            if run is not None:
                append_log(self.db, run, traceback.format_exc())
                set_status(self.db, run, RunStatus.FAILED)
                self.db.commit()
            else:
                logger.exception(
                    "RunOrchestrator: unhandled error before run was loaded (run_id=%d)",
                    self.run_id,
                )
