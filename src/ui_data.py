"""Streamlit-independent data helpers for the investigation dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from src.schema import ForensicEvent, normalize_windows_path
from src.storage import NOT_RECORDED, TimelineStore

TIMELINE_COLUMNS = [
    "Event ID",
    "Timestamp (UTC)",
    "Timestamp type",
    "Artifact",
    "Validation",
    "Path",
    "Description",
    "Source file",
    "Source record",
    "Data source",
    "Case",
]


def parse_utc_input(text: str, *, end_of_range: bool = False) -> Optional[datetime]:
    """Parse an investigator-entered UTC bound.

    A date-only end covers the whole day and a whole-second end covers that
    second, so events with sub-second precision are not silently dropped.
    """
    value = text.strip()
    if not value:
        return None
    value = re.sub(r"\s*(?:UTC|Z)$", "+00:00", value, flags=re.IGNORECASE)
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
            day = datetime.fromisoformat(value).date()
            return datetime.combine(
                day, time.max if end_of_range else time.min, tzinfo=timezone.utc
            )
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError(
            f"{text.strip()!r} is not a valid UTC time. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS."
        ) from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if end_of_range and "." not in value:
        has_seconds = re.search(r"\d{2}:\d{2}:\d{2}", value.split("+")[0]) is not None
        parsed = parsed.replace(
            second=parsed.second if has_seconds else 59, microsecond=999999
        )
    return parsed


def build_filters(
    case_id: Optional[str] = None,
    start_text: str = "",
    end_text: str = "",
    path: str = "",
    keyword: str = "",
    artifacts: Optional[List[str]] = None,
    validation_status: Optional[str] = None,
) -> Dict[str, Any]:
    """Translate form values into TimelineStore filter arguments."""
    start = parse_utc_input(start_text)
    end = parse_utc_input(end_text, end_of_range=True)
    if start and end and start > end:
        raise ValueError("The start time must not be later than the end time.")
    return {
        "case_id": case_id,
        "start": start,
        "end": end,
        "path": normalize_windows_path(path) or None,
        "keyword": keyword.strip() or None,
        "artifacts": artifacts or None,
        "validation_status": validation_status,
    }


@dataclass(frozen=True)
class DatabaseSummary:
    total: int
    case_ids: List[Optional[str]]
    artifacts: List[str]
    validation_statuses: List[Optional[str]]


@dataclass(frozen=True)
class TimelinePage:
    events: List[ForensicEvent]
    total: int
    page: int
    page_count: int
    first: int
    last: int


def load_summary(database_path: str) -> DatabaseSummary:
    with TimelineStore(database_path, read_only=True) as store:
        return DatabaseSummary(
            total=store.count(),
            case_ids=store.distinct_values("case_id"),
            artifacts=[value for value in store.distinct_values("artifact_source") if value],
            validation_statuses=store.distinct_values("validation_status"),
        )


def load_page(
    database_path: str, filters: Dict[str, Any], page: int, page_size: int
) -> TimelinePage:
    """Load one page; an out-of-range page is clamped to the nearest valid page."""
    if page_size < 1:
        raise ValueError("page_size must be positive")
    with TimelineStore(database_path, read_only=True) as store:
        total = store.count_matching(**filters)
        page_count = max(1, (total + page_size - 1) // page_size)
        page = min(max(page, 1), page_count)
        offset = (page - 1) * page_size
        events = store.query(**filters, limit=page_size, offset=offset)
    return TimelinePage(
        events=events,
        total=total,
        page=page,
        page_count=page_count,
        first=offset + 1 if events else 0,
        last=offset + len(events),
    )


def load_matching(database_path: str, filters: Dict[str, Any]) -> List[ForensicEvent]:
    with TimelineStore(database_path, read_only=True) as store:
        return store.query(**filters)


def load_findings(
    path: str, case_ids: List[Optional[str]]
) -> Tuple[List[Dict[str, Any]], int]:
    """Return findings belonging to case_ids and how many others were excluded."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
        raise ValueError("The findings file must contain a JSON array of objects.")
    allowed = {case_id or None for case_id in case_ids}
    kept = [item for item in data if (item.get("case_id") or None) in allowed]
    return kept, len(data) - len(kept)


def format_utc(event: ForensicEvent) -> str:
    """Render UTC without rounding sub-second precision."""
    return event.dt.replace(tzinfo=None).isoformat(sep=" ") + " UTC"


def timeline_row(event: ForensicEvent) -> Dict[str, str]:
    extra = event.extra_attributes
    return {
        "Event ID": event.event_id,
        "Timestamp (UTC)": format_utc(event),
        "Timestamp type": event.timestamp_type or "Not recorded",
        "Artifact": event.artifact_source,
        "Validation": event.validation_status or "Not recorded",
        "Path": event.target_path or "Not recorded",
        "Description": event.message,
        "Source file": event.source_file or "Not recorded",
        "Source record": str(extra.get("source_line") or "Not recorded"),
        "Data source": str(extra.get("source_label") or event.parser),
        "Case": event.case_id or "Unspecified",
    }


__all__ = [
    "NOT_RECORDED", "TIMELINE_COLUMNS", "DatabaseSummary", "TimelinePage",
    "build_filters", "format_utc", "load_findings", "load_matching", "load_page",
    "load_summary", "parse_utc_input", "timeline_row",
]
