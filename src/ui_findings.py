"""Display helpers for correlation findings (UI contract section 4).

Review status comes only from finding.validation_status. Scores, rules and the
status of linked events never change it, and nothing here writes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.schema import ForensicEvent
from src.storage import TimelineStore
from src.ui_evidence import evidence_basis, normalized_path_text

Finding = Dict[str, Any]
EventKey = Tuple[Optional[str], str]
EventIndex = Dict[EventKey, List[ForensicEvent]]

RULES = {
    "R01": "Temporal proximity: the events fall inside the correlation window.",
    "R02": "Object association: the events refer to the same or a parent/child path.",
    "R03": "Cross-artifact support: the related events come from different artifact types.",
    "R04": "Program-file association: a program artifact references the file directly.",
    "R05": "Deletion context: recorded interaction precedes deletion of the same path.",
}
REVIEW_LABELS = {
    "unverified": "Candidate",
    "verified": "Validated",
    "disputed": "Unresolved",
    "synthetic": "Synthetic",
}
UNRECOGNIZED = "Unrecognized status"
SORT_ORDERS = ["Highest score", "Shortest time gap", "Earliest event", "File order"]
FINDING_COLUMNS = [
    "Finding ID", "Review status", "Rules", "Score", "Time window (UTC)", "Gap (s)",
    "Event IDs", "Artifacts", "Evidence basis", "Path", "Case",
]


def as_list(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [] if value in (None, "") else [str(value)]


def review_status(finding: Finding) -> str:
    """A missing status is a candidate; an unknown one is never promoted."""
    status = finding.get("validation_status")
    if status in (None, ""):
        return "Candidate"
    return REVIEW_LABELS.get(str(status), UNRECOGNIZED)


def event_ids(finding: Finding) -> List[str]:
    ids = as_list(finding.get("event_ids"))
    if not ids:
        ids = as_list(finding.get("event_a_id")) + as_list(finding.get("event_b_id"))
    return list(dict.fromkeys(ids))


def event_key(finding: Finding, event_id: str) -> EventKey:
    return (finding.get("case_id") or None, event_id)


def load_event_index(database_path: str, findings: Sequence[Finding]) -> EventIndex:
    """Find every event the findings cite, regardless of timeline filters."""
    wanted = sorted({eid for finding in findings for eid in event_ids(finding)})
    index: EventIndex = {}
    with TimelineStore(database_path, read_only=True) as store:
        for event in store.events_by_id(wanted):
            index.setdefault((event.case_id or None, event.event_id), []).append(event)
    return index


def linked_events(finding: Finding, index: EventIndex) -> List[ForensicEvent]:
    """Return events that resolve to exactly one record, in finding order."""
    events = []
    for event_id in event_ids(finding):
        matches = index.get(event_key(finding, event_id), [])
        if len(matches) == 1:
            events.append(matches[0])
    return events


def problems(finding: Finding, index: EventIndex) -> List[str]:
    messages = []
    ids = event_ids(finding)
    if not finding.get("finding_id"):
        messages.append("This finding has no finding ID.")
    if len(ids) < 2:
        messages.append("This finding cites fewer than two source events.")
    for event_id in ids:
        count = len(index.get(event_key(finding, event_id), []))
        if count == 0:
            messages.append(
                f"Source event {event_id} is not in this database for case "
                f"{finding.get('case_id') or 'Unspecified'}."
            )
        elif count > 1:
            messages.append(f"Source event {event_id} matches {count} database records.")
    if not as_list(finding.get("matched_rules")):
        messages.append("No matched rules are recorded.")
    references = as_list(finding.get("evidence_references"))
    events = linked_events(finding, index)
    if not references:
        messages.append("No evidence references are recorded.")
    elif len(events) == len(ids):
        stored = {event.evidence_reference for event in events if event.evidence_reference}
        if set(references) != stored:
            messages.append("The evidence references differ from those of the source events.")
    if review_status(finding) == UNRECOGNIZED:
        messages.append("The stored validation status is not part of the schema.")
    return messages


def time_window(events: Sequence[ForensicEvent]) -> str:
    if not events:
        return "Not available"
    first = min(event.dt for event in events).replace(tzinfo=None)
    last = max(event.dt for event in events).replace(tzinfo=None)
    if first == last:
        return first.isoformat(sep=" ")
    end = last.time().isoformat() if first.date() == last.date() else last.isoformat(sep=" ")
    return f"{first.isoformat(sep=' ')} to {end}"


def number(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def finding_row(finding: Finding, index: EventIndex) -> Dict[str, Any]:
    events = linked_events(finding, index)

    def joined(values):
        return " + ".join(dict.fromkeys(values)) or "Not available"

    return {
        "Finding ID": str(finding.get("finding_id") or "Not recorded"),
        "Review status": review_status(finding),
        "Rules": ", ".join(as_list(finding.get("matched_rules"))) or "Not recorded",
        "Score": number(finding.get("confidence_score")),
        "Time window (UTC)": time_window(events),
        "Gap (s)": number(finding.get("time_delta_seconds")),
        "Event IDs": ", ".join(event_ids(finding)),
        "Artifacts": joined(event.artifact_source for event in events),
        "Evidence basis": joined(evidence_basis(event).label for event in events),
        "Path": joined(normalized_path_text(event) for event in events),
        "Case": finding.get("case_id") or "Unspecified",
    }


@dataclass(frozen=True)
class FindingFilter:
    text: str = ""
    statuses: Tuple[str, ...] = ()
    rules: Tuple[str, ...] = ()
    exclude_limited: bool = False


def _search_text(finding: Finding, events: Sequence[ForensicEvent]) -> str:
    parts = [str(finding.get("finding_id") or ""), str(finding.get("explanation") or "")]
    parts += event_ids(finding) + as_list(finding.get("evidence_references"))
    for event in events:
        parts += [event.target_path, normalized_path_text(event), event.source_file]
    return "\n".join(parts).casefold()


def select_findings(
    findings: Sequence[Finding], index: EventIndex, criteria: FindingFilter, sort: str
) -> List[Finding]:
    """Filter and sort; every search word and every chosen rule must match."""
    words = criteria.text.casefold().split()
    selected = []
    for finding in findings:
        if criteria.statuses and review_status(finding) not in criteria.statuses:
            continue
        if not set(criteria.rules) <= set(as_list(finding.get("matched_rules"))):
            continue
        events = linked_events(finding, index)
        if criteria.exclude_limited and (
            len(events) != len(event_ids(finding))
            or any(evidence_basis(event).tone == "limited" for event in events)
        ):
            continue
        if words:
            text = _search_text(finding, events)
            if not all(word in text for word in words):
                continue
        selected.append(finding)

    infinity = float("inf")
    if sort == "Highest score":
        selected.sort(key=lambda f: -(number(f.get("confidence_score")) or 0))
    elif sort == "Shortest time gap":
        def gap(finding):
            value = number(finding.get("time_delta_seconds"))
            return infinity if value is None else value
        selected.sort(key=gap)
    elif sort == "Earliest event":
        def earliest(finding):
            events = linked_events(finding, index)
            return min((e.dt.timestamp() for e in events), default=infinity)
        selected.sort(key=earliest)
    elif sort != "File order":
        raise ValueError(f"Unsupported sort order: {sort!r}")
    return selected
