import datetime
import json
import logging

from sqlalchemy.orm import Session

from backend.app.models.asset import Asset

logger = logging.getLogger(__name__)


class AssetService:
    def upsert_asset(self, db: Session, data: dict) -> Asset:
        target_id = data["target_id"]
        asset_type = data["asset_type"]
        value = data["value"]

        existing = (
            db.query(Asset)
            .filter(
                Asset.target_id == target_id,
                Asset.asset_type == asset_type,
                Asset.value == value,
            )
            .first()
        )

        now = datetime.datetime.utcnow()

        if existing is not None:
            existing.last_seen_at = now
            existing.is_new = False

            # Merge list fields without overwriting
            for json_field, data_key in (
                ("resolved_ips_json", "resolved_ips"),
                ("tech_json", "tech"),
                ("ports_json", "ports"),
                ("tags_json", "tags"),
            ):
                incoming = data.get(data_key, [])
                if incoming:
                    current = json.loads(getattr(existing, json_field) or "[]")
                    if isinstance(incoming[0], dict):
                        # For list-of-dicts (ports), deduplicate by converting to/from JSON strings
                        existing_set = {json.dumps(item, sort_keys=True) for item in current}
                        for item in incoming:
                            key = json.dumps(item, sort_keys=True)
                            if key not in existing_set:
                                current.append(item)
                                existing_set.add(key)
                    else:
                        existing_set = set(current)
                        for item in incoming:
                            if item not in existing_set:
                                current.append(item)
                                existing_set.add(item)
                    setattr(existing, json_field, json.dumps(current))

            # Update scalar fields only if provided in data
            for field in ("run_id", "is_alive", "status_code", "title", "web_server", "content_length", "cdn", "notes"):
                if field in data and data[field] is not None:
                    setattr(existing, field, data[field])

            logger.debug("Updated asset target_id=%d type=%s value=%s", target_id, asset_type, value)
            return existing

        # Create new asset
        asset = Asset(
            target_id=target_id,
            asset_type=asset_type,
            value=value,
            run_id=data.get("run_id"),
            is_alive=data.get("is_alive"),
            status_code=data.get("status_code"),
            title=data.get("title"),
            web_server=data.get("web_server"),
            content_length=data.get("content_length"),
            cdn=data.get("cdn"),
            notes=data.get("notes"),
            resolved_ips_json=json.dumps(list(dict.fromkeys(data.get("resolved_ips", [])))),
            tech_json=json.dumps(list(dict.fromkeys(data.get("tech", [])))),
            tags_json=json.dumps(list(dict.fromkeys(data.get("tags", [])))),
            ports_json=json.dumps(
                list({json.dumps(p, sort_keys=True): p for p in data.get("ports", [])}.values())
            ),
            is_new=True,
            first_seen_at=now,
            last_seen_at=now,
        )
        db.add(asset)
        logger.debug("Created asset target_id=%d type=%s value=%s", target_id, asset_type, value)
        return asset

    def upsert_bulk(self, db: Session, assets: list[dict]) -> dict:
        created = 0
        updated = 0
        for data in assets:
            asset = self.upsert_asset(db, data)
            if asset.is_new:
                created += 1
            else:
                updated += 1
        total = created + updated
        return {"created": created, "updated": updated, "total": total}

    def mark_stale(self, db: Session, target_id: int, run_id: int, known_values: set[str]) -> int:
        result = (
            db.query(Asset)
            .filter(
                Asset.target_id == target_id,
                Asset.value.notin_(known_values),
            )
            .update({Asset.is_alive: None}, synchronize_session="fetch")
        )
        logger.debug("Marked %d assets stale for target_id=%d run_id=%d", result, target_id, run_id)
        return result

    def get_new_assets(self, db: Session, target_id: int, since_run_id: int | None = None) -> list[Asset]:
        query = db.query(Asset).filter(
            Asset.target_id == target_id,
            Asset.is_new == True,  # noqa: E712
        )
        if since_run_id is not None:
            query = query.filter(Asset.run_id > since_run_id)
        return query.all()
