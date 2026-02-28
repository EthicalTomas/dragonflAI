import json
import logging

from sqlalchemy.orm import Session

from backend.app.models.asset import Asset
from backend.app.models.endpoint import Endpoint
from backend.app.models.run import Run, RunStatus

logger = logging.getLogger(__name__)

_ASSET_COMPARE_FIELDS = ("is_alive", "status_code", "title", "tech_json", "ports_json")
_ENDPOINT_COMPARE_FIELDS = ("status_code", "params_json")
_JSON_FIELDS = frozenset({"tech_json", "ports_json", "params_json"})


def _parse_json(value: str | None) -> object:
    if not value:
        return []
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def _fields_changed(current: object, previous: object, fields: tuple[str, ...]) -> dict:
    """Return a dict of {field: {"old": ..., "new": ...}} for fields that differ."""
    changes: dict = {}
    for field in fields:
        curr_val = getattr(current, field)
        prev_val = getattr(previous, field)
        if field in _JSON_FIELDS:
            curr_val = _parse_json(curr_val)
            prev_val = _parse_json(prev_val)
        if curr_val != prev_val:
            changes[field] = {"old": prev_val, "new": curr_val}
    return changes


def _build_all_new_asset_diff(assets: list[Asset]) -> dict:
    return {
        "new_assets": assets,
        "removed_assets": [],
        "changed_assets": [],
        "unchanged_count": 0,
        "summary": {
            "new": len(assets),
            "removed": 0,
            "changed": 0,
            "unchanged": 0,
        },
    }


def _build_all_new_endpoint_diff(endpoints: list[Endpoint]) -> dict:
    return {
        "new_endpoints": endpoints,
        "removed_endpoints": [],
        "changed_endpoints": [],
        "unchanged_count": 0,
        "summary": {
            "new": len(endpoints),
            "removed": 0,
            "changed": 0,
            "unchanged": 0,
        },
    }


class RunDiffer:
    def __init__(self, db: Session) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def get_previous_run(self, target_id: int, current_run_id: int) -> Run | None:
        """Find the most recent SUCCEEDED run for the same target older than current_run_id."""
        return (
            self.db.query(Run)
            .filter(
                Run.target_id == target_id,
                Run.status == RunStatus.SUCCEEDED,
                Run.id < current_run_id,
            )
            .order_by(Run.id.desc())
            .first()
        )

    def diff_assets(
        self,
        target_id: int,
        current_run_id: int,
        previous_run_id: int,
    ) -> dict:
        """Compare assets between two runs for the same target.

        Returns a dict with new_assets, removed_assets, changed_assets,
        unchanged_count, and a summary.  Each entry in changed_assets is a
        dict with ``"current"`` (the current Asset) and ``"changes"`` (a
        mapping of field name to ``{"old": ..., "new": ...}``).
        """
        current_assets = (
            self.db.query(Asset)
            .filter(Asset.target_id == target_id, Asset.run_id == current_run_id)
            .all()
        )
        previous_assets = (
            self.db.query(Asset)
            .filter(Asset.target_id == target_id, Asset.run_id == previous_run_id)
            .all()
        )

        current_map: dict[tuple, Asset] = {
            (a.asset_type, a.value): a for a in current_assets
        }
        previous_map: dict[tuple, Asset] = {
            (a.asset_type, a.value): a for a in previous_assets
        }

        new_assets = [a for k, a in current_map.items() if k not in previous_map]
        removed_assets = [a for k, a in previous_map.items() if k not in current_map]

        changed_assets: list[dict] = []
        unchanged_count = 0

        for key, curr in current_map.items():
            if key in previous_map:
                changes = _fields_changed(curr, previous_map[key], _ASSET_COMPARE_FIELDS)
                if changes:
                    changed_assets.append({"current": curr, "changes": changes})
                else:
                    unchanged_count += 1

        logger.debug(
            "diff_assets target_id=%d current_run=%d previous_run=%d "
            "new=%d removed=%d changed=%d unchanged=%d",
            target_id,
            current_run_id,
            previous_run_id,
            len(new_assets),
            len(removed_assets),
            len(changed_assets),
            unchanged_count,
        )

        return {
            "new_assets": new_assets,
            "removed_assets": removed_assets,
            "changed_assets": changed_assets,
            "unchanged_count": unchanged_count,
            "summary": {
                "new": len(new_assets),
                "removed": len(removed_assets),
                "changed": len(changed_assets),
                "unchanged": unchanged_count,
            },
        }

    def diff_endpoints(
        self,
        target_id: int,
        current_run_id: int,
        previous_run_id: int,
    ) -> dict:
        """Compare endpoints between two runs for the same target.

        Endpoints are matched by ``(url, method)``.  Each entry in
        changed_endpoints is a dict with ``"current"`` (the current Endpoint)
        and ``"changes"`` (a mapping of field name to ``{"old": ..., "new":
        ...}``).
        """
        current_eps = (
            self.db.query(Endpoint)
            .filter(Endpoint.target_id == target_id, Endpoint.run_id == current_run_id)
            .all()
        )
        previous_eps = (
            self.db.query(Endpoint)
            .filter(Endpoint.target_id == target_id, Endpoint.run_id == previous_run_id)
            .all()
        )

        current_map: dict[tuple, Endpoint] = {
            (e.url, e.method): e for e in current_eps
        }
        previous_map: dict[tuple, Endpoint] = {
            (e.url, e.method): e for e in previous_eps
        }

        new_endpoints = [e for k, e in current_map.items() if k not in previous_map]
        removed_endpoints = [e for k, e in previous_map.items() if k not in current_map]

        changed_endpoints: list[dict] = []
        unchanged_count = 0

        for key, curr in current_map.items():
            if key in previous_map:
                changes = _fields_changed(curr, previous_map[key], _ENDPOINT_COMPARE_FIELDS)
                if changes:
                    changed_endpoints.append({"current": curr, "changes": changes})
                else:
                    unchanged_count += 1

        logger.debug(
            "diff_endpoints target_id=%d current_run=%d previous_run=%d "
            "new=%d removed=%d changed=%d unchanged=%d",
            target_id,
            current_run_id,
            previous_run_id,
            len(new_endpoints),
            len(removed_endpoints),
            len(changed_endpoints),
            unchanged_count,
        )

        return {
            "new_endpoints": new_endpoints,
            "removed_endpoints": removed_endpoints,
            "changed_endpoints": changed_endpoints,
            "unchanged_count": unchanged_count,
            "summary": {
                "new": len(new_endpoints),
                "removed": len(removed_endpoints),
                "changed": len(changed_endpoints),
                "unchanged": unchanged_count,
            },
        }

    def diff_full(
        self,
        target_id: int,
        current_run_id: int,
        previous_run_id: int,
    ) -> dict:
        """Run both diff_assets and diff_endpoints and combine into a single report.

        When previous_run_id is 0 or does not match any run, all current
        assets and endpoints are treated as new (an "all new" diff).
        """
        logger.info(
            "diff_full target_id=%d current_run=%d previous_run=%d",
            target_id,
            current_run_id,
            previous_run_id,
        )

        if previous_run_id and previous_run_id > 0:
            asset_diff = self.diff_assets(target_id, current_run_id, previous_run_id)
            endpoint_diff = self.diff_endpoints(target_id, current_run_id, previous_run_id)
        else:
            # No previous run — everything is new.
            current_assets = (
                self.db.query(Asset)
                .filter(Asset.target_id == target_id, Asset.run_id == current_run_id)
                .all()
            )
            current_eps = (
                self.db.query(Endpoint)
                .filter(Endpoint.target_id == target_id, Endpoint.run_id == current_run_id)
                .all()
            )
            asset_diff = _build_all_new_asset_diff(current_assets)
            endpoint_diff = _build_all_new_endpoint_diff(current_eps)

        highlights = _build_highlights(asset_diff, endpoint_diff)

        return {
            "target_id": target_id,
            "current_run_id": current_run_id,
            "previous_run_id": previous_run_id,
            "assets": asset_diff,
            "endpoints": endpoint_diff,
            "highlights": highlights,
        }


# ------------------------------------------------------------------
# internal helpers
# ------------------------------------------------------------------


def _build_highlights(asset_diff: dict, endpoint_diff: dict) -> list[str]:
    highlights: list[str] = []

    # New subdomains
    new_subdomains = [
        a for a in asset_diff["new_assets"] if a.asset_type == "subdomain"
    ]
    if new_subdomains:
        n = len(new_subdomains)
        highlights.append(
            f"{n} new subdomain{'s' if n != 1 else ''} discovered"
        )

    # Assets that went from alive to dead
    alive_to_dead = sum(
        1
        for entry in asset_diff["changed_assets"]
        if entry["changes"].get("is_alive", {}).get("old") is True
        and entry["changes"]["is_alive"].get("new") is False
    )
    if alive_to_dead:
        highlights.append(
            f"{alive_to_dead} asset{'s' if alive_to_dead != 1 else ''} went from alive to dead"
        )

    # New endpoints
    new_ep_count = len(endpoint_diff["new_endpoints"])
    if new_ep_count:
        highlights.append(
            f"{new_ep_count} new endpoint{'s' if new_ep_count != 1 else ''} found"
        )

    # New interesting parameters (params in new endpoints)
    new_param_count = 0
    for ep in endpoint_diff["new_endpoints"]:
        try:
            params = json.loads(ep.params_json or "[]")
        except (json.JSONDecodeError, TypeError):
            params = []
        new_param_count += len(params)
    if new_param_count:
        highlights.append(
            f"{new_param_count} new interesting parameter{'s' if new_param_count != 1 else ''} detected"
        )

    return highlights
