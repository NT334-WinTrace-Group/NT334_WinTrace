"""SQLite persistence and query helpers for the unified forensic timeline."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import sqlite3
from pathlib import Path
from dataclasses import fields, replace
from typing import Any, Iterable, List, Optional, Sequence, Tuple

from src.schema import ForensicEvent


PROVENANCE_FIELDS = ("timestamp_type", "evidence_reference", "validation_status", "case_id")

NULLABLE_COLUMNS = {"user_sid", "username", *PROVENANCE_FIELDS}

# Filter value selecting rows whose case_id / validation_status was never recorded.
NOT_RECORDED = "<not recorded>"


class MalformedEventError(ValueError):
    """Raised when a stored row cannot be turned into a valid event."""


class TimelineStore:
    """Stores normalized events without discarding provenance metadata."""

    def __init__(self, database_path: str, read_only: bool = False):
        self.database_path = database_path
        if read_only:
            self._open_read_only()
            return
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(database_path)
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def _open_read_only(self) -> None:
        """Open an existing v2 database without creating, migrating, or writing it."""
        path = Path(self.database_path)
        if not path.is_file():
            raise FileNotFoundError(f"Timeline database not found: {self.database_path}")
        self.connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
        self.connection.row_factory = sqlite3.Row
        try:
            columns = {
                row["name"] for row in self.connection.execute("PRAGMA table_info(events)")
            }
            required = {"id", *(field.name for field in fields(ForensicEvent))}
            missing = sorted(required - columns)
            if missing:
                raise ValueError(
                    "Not a WinTrace schema v2 timeline database; missing columns: "
                    + ", ".join(missing)
                )
        except Exception:
            self.connection.close()
            raise

    def initialize(self) -> None:
        with self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            self._initialize_schema()
            self._migrate_fingerprints()

    def _initialize_schema(self) -> None:
        self.connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                schema_version TEXT NOT NULL DEFAULT 'v2',
                event_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                timestamp_type TEXT,
                timestamp_desc TEXT NOT NULL,
                artifact_source TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                source_file TEXT NOT NULL,
                target_path TEXT NOT NULL,
                object_path TEXT NOT NULL,
                message TEXT NOT NULL,
                data_type TEXT NOT NULL,
                parser TEXT NOT NULL,
                user_sid TEXT,
                username TEXT,
                confidence_level TEXT NOT NULL,
                evidence_reference TEXT,
                validation_status TEXT,
                case_id TEXT,
                extra_attributes TEXT NOT NULL
            )
        """)
        columns = {
            row["name"] for row in self.connection.execute("PRAGMA table_info(events)")
        }
        migrations = {
            "schema_version": "TEXT NOT NULL DEFAULT 'v2'",
            "timestamp_type": "TEXT",
            "artifact_type": "TEXT NOT NULL DEFAULT ''",
            "object_path": "TEXT NOT NULL DEFAULT ''",
            "evidence_reference": "TEXT",
            "validation_status": "TEXT",
            "case_id": "TEXT",
        }
        for name, definition in migrations.items():
            if name not in columns:
                self.connection.execute(f"ALTER TABLE events ADD COLUMN {name} {definition}")
        indexes = {
            "timestamp": "timestamp",
            "artifact": "artifact_source",
            "target": "target_path",
            "username": "username",
            "validation": "validation_status",
            "case": "case_id",
            "source_file": "source_file",
        }
        for name, column in indexes.items():
            self.connection.execute(f"CREATE INDEX IF NOT EXISTS idx_events_{name} ON events({column})")
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_artifact_nocase "
            "ON events(artifact_source COLLATE NOCASE)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_case_nocase "
            "ON events(case_id COLLATE NOCASE)"
        )
        self.connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_events_case_artifact_timestamp "
            "ON events(case_id, artifact_source, timestamp)"
        )

    @staticmethod
    def _fingerprint_for(event: ForensicEvent, timestamp: str, include_identity: bool) -> str:
        case_id = event.case_id or event.extra_attributes.get("case_id") or ""
        values = (
            (event.event_id, case_id, timestamp)
            if include_identity
            else (timestamp,)
        ) + (
            event.timestamp_desc, event.artifact_source,
            event.source_file, event.target_path, event.message, event.data_type,
            event.parser, event.user_sid or "", event.username or "",
            event.confidence_level,
            json.dumps(event.extra_attributes, ensure_ascii=False, sort_keys=True),
        )
        return hashlib.sha256("\x1f".join(values).encode("utf-8")).hexdigest()

    @staticmethod
    def fingerprint(event: ForensicEvent) -> str:
        return TimelineStore._fingerprint_for(event, event.dt.isoformat(), include_identity=True)

    @staticmethod
    def legacy_fingerprint(event: ForensicEvent) -> str:
        """Fingerprint format used before event_id/case_id were added."""
        return TimelineStore._fingerprint_for(event, event.timestamp, include_identity=False)

    def _migrate_fingerprints(self) -> None:
        rows = self.connection.execute("""
            SELECT id, fingerprint, event_id, timestamp, timestamp_desc,
                   artifact_source, source_file, target_path, message,
                   data_type, parser, user_sid, username, confidence_level,
                   timestamp_type, evidence_reference, validation_status,
                   case_id, extra_attributes
            FROM events
        """).fetchall()

        for row in rows:
            data = dict(row)
            stored_fingerprint = data.pop("fingerprint")
            data.pop("id")
            stored_timestamp = data["timestamp"]
            extra_attributes = json.loads(data.pop("extra_attributes") or "{}")
            data["extra_attributes"] = extra_attributes
            event = ForensicEvent.from_dict(data)
            legacy_fingerprint = self._fingerprint_for(
                event, stored_timestamp, include_identity=False
            )
            previous_fingerprint = self._fingerprint_for(
                event, stored_timestamp, include_identity=True
            )
            new_fingerprint = self.fingerprint(event)
            needs_timestamp_migration = stored_timestamp != event.timestamp
            if (
                stored_fingerprint != legacy_fingerprint
                and stored_fingerprint != previous_fingerprint
                and stored_fingerprint != new_fingerprint
            ):
                if needs_timestamp_migration:
                    raise RuntimeError(
                        f"Cannot safely normalize timestamp for event row {row['id']}: "
                        "its fingerprint does not match a known format."
                    )
                continue

            collision = self.connection.execute(
                "SELECT 1 FROM events WHERE fingerprint = ? AND fingerprint != ?",
                (new_fingerprint, stored_fingerprint),
            ).fetchone()
            if collision is not None:
                raise RuntimeError(
                    f"Cannot safely migrate fingerprint for event row {row['id']}: "
                    "the normalized fingerprint already exists."
                )
            self.connection.execute(
                "UPDATE events SET fingerprint = ?, timestamp = ? WHERE id = ?",
                (new_fingerprint, event.timestamp, row["id"]),
            )

    def insert_events(self, events: Iterable[ForensicEvent]) -> int:
        rows = []
        provenance_rows = []
        for event in events:
            fingerprint = self.fingerprint(event)
            legacy_fingerprint = self.legacy_fingerprint(event)
            provenance = {
                field: getattr(event, field)
                for field in PROVENANCE_FIELDS
            }
            for field, value in provenance.items():
                if value is None:
                    provenance[field] = event.extra_attributes.get(field)

            exact = self.connection.execute(
                "SELECT fingerprint FROM events WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            if exact is None:
                compatible = self.connection.execute(
                    """
                    SELECT * FROM events
                    WHERE fingerprint = ?
                       OR (
                           event_id = ?
                           AND timestamp = ?
                           AND timestamp_desc = ?
                           AND artifact_source = ?
                           AND source_file = ?
                           AND target_path = ?
                           AND message = ?
                           AND data_type = ?
                           AND parser = ?
                           AND (user_sid IS ? OR user_sid = ?)
                           AND (username IS ? OR username = ?)
                           AND confidence_level = ?
                       )
                    """,
                    (
                        legacy_fingerprint,
                        event.event_id,
                        event.timestamp,
                        event.timestamp_desc,
                        event.artifact_source,
                        event.source_file,
                        event.target_path,
                        event.message,
                        event.data_type,
                        event.parser,
                        event.user_sid,
                        event.user_sid,
                        event.username,
                        event.username,
                        event.confidence_level,
                    ),
                ).fetchall()

                compatible = [
                    row for row in compatible
                    if (
                        row["case_id"] is None
                        or row["case_id"] == ""
                        or provenance["case_id"] is None
                        or row["case_id"] == provenance["case_id"]
                    )
                ]
                if len(compatible) == 1:
                    existing = compatible[0]
                    existing_extra = json.loads(existing["extra_attributes"] or "{}")
                    merged_extra = {**existing_extra, **event.extra_attributes}
                    chosen_case_id = existing["case_id"] or provenance["case_id"]
                    upgraded = replace(
                        event,
                        extra_attributes=merged_extra,
                        case_id=chosen_case_id,
                        timestamp_type=provenance["timestamp_type"] or event.timestamp_type,
                        evidence_reference=provenance["evidence_reference"] or event.evidence_reference,
                        validation_status=provenance["validation_status"] or event.validation_status,
                    )
                    new_fingerprint = self.fingerprint(upgraded)
                    collision = self.connection.execute(
                        "SELECT 1 FROM events WHERE fingerprint = ? AND id != ?",
                        (new_fingerprint, existing["id"]),
                    ).fetchone()
                    if collision is None:
                        self.connection.execute(
                            """
                            UPDATE events SET
                                fingerprint = ?,
                                timestamp_type = ?,
                                evidence_reference = ?,
                                validation_status = ?,
                                case_id = ?,
                                extra_attributes = ?
                            WHERE id = ?
                            """,
                            (
                                new_fingerprint,
                                upgraded.timestamp_type,
                                upgraded.evidence_reference,
                                upgraded.validation_status,
                                upgraded.case_id,
                                json.dumps(merged_extra, ensure_ascii=False, sort_keys=True),
                                existing["id"],
                            ),
                        )
                        continue

            if any(value is not None for value in provenance.values()):
                provenance_rows.append({"fingerprint": fingerprint, **provenance})

            rows.append((
                "v2", event.event_id, fingerprint, event.timestamp,
                provenance["timestamp_type"],
                event.timestamp_desc, event.artifact_source, event.artifact_source,
                event.source_file, event.target_path, event.target_path,
                event.message, event.data_type, event.parser, event.user_sid,
                event.username, event.confidence_level,
                provenance["evidence_reference"], provenance["validation_status"],
                provenance["case_id"],
                json.dumps(event.extra_attributes, ensure_ascii=False, sort_keys=True),
            ))
        with self.connection:
            inserted = self.connection.executemany("""
                INSERT OR IGNORE INTO events (
                    schema_version, event_id, fingerprint, timestamp, timestamp_type,
                    timestamp_desc, artifact_source, artifact_type, source_file,
                    target_path, object_path, message, data_type, parser, user_sid,
                    username, confidence_level, evidence_reference, validation_status,
                    case_id, extra_attributes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows).rowcount

            # Re-import can restore provenance that an older writer omitted.
            if inserted < len(rows) and provenance_rows:
                self.connection.executemany("""
                    UPDATE events SET
                        timestamp_type = COALESCE(timestamp_type, :timestamp_type),
                        evidence_reference = COALESCE(evidence_reference, :evidence_reference),
                        validation_status = COALESCE(validation_status, :validation_status),
                        case_id = COALESCE(case_id, :case_id)
                    WHERE fingerprint = :fingerprint AND (case_id IS NULL OR case_id = :case_id)
                      AND ((timestamp_type IS NULL AND :timestamp_type IS NOT NULL)
                        OR (evidence_reference IS NULL AND :evidence_reference IS NOT NULL)
                        OR (validation_status IS NULL AND :validation_status IS NOT NULL)
                        OR (case_id IS NULL AND :case_id IS NOT NULL))
                """, provenance_rows)
        return inserted

    def _where(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        artifact: Optional[str] = None,
        keyword: Optional[str] = None,
        case_id: Optional[str] = None,
        path: Optional[str] = None,
        validation_status: Optional[str] = None,
        artifacts: Optional[Sequence[str]] = None,
    ) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        parameters: List[Any] = []
        start_utc = self._utc_bound(start, "start")
        end_utc = self._utc_bound(end, "end")
        if start_utc and end_utc and start_utc > end_utc:
            raise ValueError("start must not be later than end")
        if start_utc is not None:
            clauses.append("timestamp >= ?")
            parameters.append(start_utc)
        if end_utc is not None:
            clauses.append("timestamp <= ?")
            parameters.append(end_utc)
        if artifact:
            clauses.append("artifact_source = ? COLLATE NOCASE")
            parameters.append(artifact)
        if artifacts:
            placeholders = ", ".join("?" for _ in artifacts)
            clauses.append(f"artifact_source COLLATE NOCASE IN ({placeholders})")
            parameters.extend(artifacts)
        if keyword:
            clauses.append(
                "(target_path COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR source_file COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR message COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR event_id COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR evidence_reference COLLATE NOCASE LIKE ? ESCAPE '\\')"
            )
            pattern = self._contains_pattern(keyword)
            parameters.extend([pattern] * 5)
        if path:
            clauses.append("target_path COLLATE NOCASE LIKE ? ESCAPE '\\'")
            parameters.append(self._contains_pattern(path))
        for column, value in (
            ("case_id", case_id),
            ("validation_status", validation_status),
        ):
            if value == NOT_RECORDED:
                clauses.append(f"({column} IS NULL OR {column} = '')")
            elif value:
                clauses.append(f"{column} = ? COLLATE NOCASE")
                parameters.append(value)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), parameters

    def query(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        artifact: Optional[str] = None,
        keyword: Optional[str] = None,
        case_id: Optional[str] = None,
        limit: Optional[int] = None,
        path: Optional[str] = None,
        validation_status: Optional[str] = None,
        artifacts: Optional[Sequence[str]] = None,
        offset: int = 0,
        malformed: Optional[List[str]] = None,
    ) -> List[ForensicEvent]:
        """Return matching events in time order.

        A row that cannot be read raises MalformedEventError, unless a
        ``malformed`` list is given to collect the messages instead.
        """
        where, parameters = self._where(
            start=start, end=end, artifact=artifact, keyword=keyword,
            case_id=case_id, path=path, validation_status=validation_status,
            artifacts=artifacts,
        )
        if limit is not None and limit < 1:
            raise ValueError("limit must be positive")
        if offset < 0:
            raise ValueError("offset must be non-negative")
        sql = "SELECT * FROM events" + where + " ORDER BY timestamp, id"
        if limit is not None or offset:
            sql += " LIMIT ? OFFSET ?"
            parameters.extend([-1 if limit is None else limit, offset])
        return self._read_events(self.connection.execute(sql, parameters), malformed)

    def _read_events(
        self, rows: Iterable[sqlite3.Row], malformed: Optional[List[str]] = None
    ) -> List[ForensicEvent]:
        events = []
        for row in rows:
            try:
                events.append(self._row_to_event(row))
            except MalformedEventError as exc:
                if malformed is None:
                    raise
                malformed.append(str(exc))
        return events

    def events_by_id(
        self, event_ids: Sequence[str], malformed: Optional[List[str]] = None
    ) -> List[ForensicEvent]:
        """Return every stored event with one of these IDs, in any case."""
        events: List[ForensicEvent] = []
        for start in range(0, len(event_ids), 500):
            chunk = list(event_ids[start:start + 500])
            placeholders = ", ".join("?" for _ in chunk)
            rows = self.connection.execute(
                f"SELECT * FROM events WHERE event_id IN ({placeholders}) ORDER BY timestamp, id",
                chunk,
            )
            events.extend(self._read_events(rows, malformed))
        return events

    def count_matching(self, **filters: Any) -> int:
        """Count every row the same filters would return from query()."""
        where, parameters = self._where(**filters)
        return int(
            self.connection.execute("SELECT COUNT(*) FROM events" + where, parameters).fetchone()[0]
        )

    def distinct_values(self, column: str) -> List[Optional[str]]:
        """Return sorted distinct values; missing values are reported as None."""
        if column not in {"case_id", "artifact_source", "validation_status"}:
            raise ValueError(f"Unsupported column: {column!r}")
        rows = self.connection.execute(f"SELECT DISTINCT {column} FROM events")
        # Non-text values belong to malformed rows and cannot be offered as filters.
        values = {row[0] or None for row in rows if row[0] is None or isinstance(row[0], str)}
        return sorted(values, key=lambda value: (value is None, value or ""))

    @staticmethod
    def _utc_bound(value: Optional[datetime], name: str) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, datetime):
            raise TypeError(f"{name} must be a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _contains_pattern(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        return f"%{escaped}%"

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> ForensicEvent:
        data = dict(row)
        try:
            for field in fields(ForensicEvent):
                value = data[field.name]
                if value is None and field.name not in NULLABLE_COLUMNS:
                    raise ValueError(f"{field.name} is missing")
                if value is not None and not isinstance(value, str):
                    raise ValueError(f"{field.name} is not text")
            data["extra_attributes"] = json.loads(data["extra_attributes"])
            if not isinstance(data["extra_attributes"], dict):
                raise ValueError("extra_attributes is not a JSON object")
            for name in PROVENANCE_FIELDS:
                if data[name] is None:
                    data[name] = data["extra_attributes"].get(name)
            return ForensicEvent.from_dict(data)
        except (TypeError, ValueError, AttributeError) as exc:
            raise MalformedEventError(
                f"Event {data.get('event_id')!r} (database row {data.get('id')}) "
                f"cannot be read: {exc}"
            ) from exc

    def count(self) -> int:
        return int(self.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def case_ids(self) -> List[str]:
        """Return distinct, non-empty case identifiers for UI scoping."""
        rows = self.connection.execute(
            "SELECT DISTINCT case_id FROM events "
            "WHERE case_id IS NOT NULL AND trim(case_id) != '' ORDER BY case_id COLLATE NOCASE"
        ).fetchall()
        return [str(row[0]) for row in rows]

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "TimelineStore":
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()
