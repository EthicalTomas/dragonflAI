import datetime
import json
import logging
import urllib.parse

from sqlalchemy.orm import Session

from backend.app.models.asset import Asset
from backend.app.models.endpoint import Endpoint

logger = logging.getLogger(__name__)


class EndpointService:
    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _merge_params(existing_json: str, new_params: list[dict]) -> str:
        """Merge two param lists, deduplicating by (name, type)."""
        try:
            existing: list[dict] = json.loads(existing_json or "[]")
        except (json.JSONDecodeError, TypeError):
            existing = []

        seen: set[tuple] = {(p.get("name"), p.get("type")) for p in existing}
        for p in new_params:
            key = (p.get("name"), p.get("type"))
            if key not in seen:
                existing.append(p)
                seen.add(key)
        return json.dumps(existing)

    @staticmethod
    def _params_from_url(url: str) -> list[dict]:
        """Extract query parameters from a URL as param dicts."""
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params: list[dict] = []
        for name, values in qs.items():
            for val in values:
                params.append({"name": name, "value": val, "type": "query"})
        return params

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    @staticmethod
    def _like_escape(value: str) -> str:
        """Escape LIKE special characters so user input is treated literally."""
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    def upsert_endpoint(self, db: Session, data: dict) -> Endpoint:
        target_id = data["target_id"]
        url: str = data["url"]
        method: str = data.get("method", "GET").upper()
        source: str = data.get("source", "")

        explicit_params: list[dict] = data.get("params", [])

        existing: Endpoint | None = (
            db.query(Endpoint)
            .filter(
                Endpoint.target_id == target_id,
                Endpoint.url == url,
                Endpoint.method == method,
            )
            .first()
        )

        if existing is not None:
            # Update last_seen_at and is_new
            existing.last_seen_at = datetime.datetime.utcnow()
            existing.is_new = False

            # Merge params
            existing.params_json = self._merge_params(existing.params_json, explicit_params)

            # Update optional fields only when new values are provided
            if data.get("status_code") is not None:
                existing.status_code = data["status_code"]
            if data.get("content_type") is not None:
                existing.content_type = data["content_type"]
            if data.get("content_length") is not None:
                existing.content_length = data["content_length"]

            # If a different source discovered this endpoint, keep original
            # source but note the new source in tags.
            if source and existing.source != source:
                try:
                    tags: list = json.loads(existing.tags_json or "[]")
                except (json.JSONDecodeError, TypeError):
                    tags = []
                tag = f"also-seen-by:{source}"
                if tag not in tags:
                    tags.append(tag)
                    existing.tags_json = json.dumps(tags)

            logger.debug("Updated endpoint id=%s url=%s", existing.id, url)
            return existing

        # ---- create new endpoint ----------------------------------------
        parsed = urllib.parse.urlparse(url)
        scheme: str | None = parsed.scheme or None
        host: str = parsed.hostname or parsed.netloc or ""
        port: int | None = parsed.port

        # path defaults to "/" when empty so we preserve None when absent
        path: str | None = parsed.path if parsed.path else None

        # Merge URL query params with explicit params
        url_params = self._params_from_url(url)
        all_params = url_params[:]
        seen: set[tuple] = {(p.get("name"), p.get("type")) for p in all_params}
        for p in explicit_params:
            key = (p.get("name"), p.get("type"))
            if key not in seen:
                all_params.append(p)
                seen.add(key)

        tags_list: list = data.get("tags", [])

        endpoint = Endpoint(
            target_id=target_id,
            asset_id=data.get("asset_id"),
            run_id=data.get("run_id"),
            url=url,
            scheme=scheme,
            host=host,
            port=port,
            path=path,
            method=method,
            params_json=json.dumps(all_params),
            status_code=data.get("status_code"),
            content_type=data.get("content_type"),
            content_length=data.get("content_length"),
            source=source,
            is_new=True,
            tags_json=json.dumps(tags_list),
            notes=data.get("notes"),
        )
        db.add(endpoint)
        logger.debug("Created endpoint url=%s method=%s", url, method)
        return endpoint

    def upsert_bulk(self, db: Session, endpoints: list[dict]) -> dict:
        created = 0
        updated = 0
        for item in endpoints:
            # Check existence before upsert to reliably distinguish create vs update
            target_id = item["target_id"]
            url = item["url"]
            method = item.get("method", "GET").upper()
            exists = (
                db.query(Endpoint.id)
                .filter(
                    Endpoint.target_id == target_id,
                    Endpoint.url == url,
                    Endpoint.method == method,
                )
                .first()
                is not None
            )
            self.upsert_endpoint(db, item)
            if exists:
                updated += 1
            else:
                created += 1
        total = created + updated
        return {"created": created, "updated": updated, "total": total}

    def link_to_asset(self, db: Session, endpoint: Endpoint) -> None:
        if endpoint.asset_id is not None:
            return

        asset: Asset | None = (
            db.query(Asset)
            .filter(
                Asset.target_id == endpoint.target_id,
                Asset.value == endpoint.host,
            )
            .first()
        )
        if asset is not None:
            endpoint.asset_id = asset.id
            logger.debug(
                "Linked endpoint id=%s to asset id=%s", endpoint.id, asset.id
            )

    def search_endpoints(self, db: Session, filters: dict) -> list[Endpoint]:
        query = db.query(Endpoint)

        if filters.get("target_id") is not None:
            query = query.filter(Endpoint.target_id == filters["target_id"])
        if filters.get("asset_id") is not None:
            query = query.filter(Endpoint.asset_id == filters["asset_id"])
        if filters.get("source") is not None:
            query = query.filter(Endpoint.source == filters["source"])
        if filters.get("method") is not None:
            query = query.filter(Endpoint.method == filters["method"])
        if filters.get("is_interesting") is not None:
            query = query.filter(Endpoint.is_interesting == filters["is_interesting"])
        if filters.get("status_code_min") is not None:
            query = query.filter(Endpoint.status_code >= filters["status_code_min"])
        if filters.get("status_code_max") is not None:
            query = query.filter(Endpoint.status_code <= filters["status_code_max"])
        if filters.get("path_contains") is not None:
            escaped = self._like_escape(filters["path_contains"])
            query = query.filter(Endpoint.path.like(f"%{escaped}%", escape="\\"))
        if filters.get("param_name_contains") is not None:
            escaped = self._like_escape(filters["param_name_contains"])
            query = query.filter(
                Endpoint.params_json.like(f"%{escaped}%", escape="\\")
            )

        return query.order_by(Endpoint.last_seen_at.desc()).all()
