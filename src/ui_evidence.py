"""Display-only interpretation of event provenance (UI contract section 3).

Nothing here writes to, or upgrades, the stored validation status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional

from src.schema import ForensicEvent

NOT_RECORDED_TEXT = "Not recorded"


@dataclass(frozen=True)
class EvidenceBasis:
    label: str
    explanation: str
    tone: str  # "evidence", "inferred" or "limited"


METADATA_ONLY = EvidenceBasis(
    "Metadata only",
    "This timestamp describes the target object. It does not show a user action.",
    "limited",
)
REGISTRY_WRITE = EvidenceBasis(
    "Registry write",
    "A registry key was written at this time. The write is not attributed to a user action.",
    "limited",
)
APPROXIMATE_EXECUTION = EvidenceBasis(
    "Approximate execution",
    "The Prefetch file creation time only approximates an early program run.",
    "inferred",
)
INFERRED_INTERACTION = EvidenceBasis(
    "Inferred interaction",
    "The time is inferred from a parent key write and MRU position 0.",
    "inferred",
)
INTERACTION = EvidenceBasis(
    "Interaction evidence",
    "The artifact supports Shell or application interaction with this path. "
    "It does not show copying or intent.",
    "evidence",
)
EXECUTION = EvidenceBasis(
    "Program execution evidence",
    "The artifact records a program run. It does not identify who started it.",
    "evidence",
)
DEVICE = EvidenceBasis(
    "Device connection evidence",
    "Recorded at machine level. It does not identify who connected the device.",
    "evidence",
)
NOT_CLASSIFIED = EvidenceBasis(
    "Not classified",
    "The source supplied no evidence classification. Do not infer an action from it.",
    "limited",
)


def evidence_basis(event: ForensicEvent) -> EvidenceBasis:
    """Apply the contract's ordered classification; unknown values stay unclassified."""
    semantic_class = event.extra_attributes.get("semantic_class")
    if semantic_class == "target_metadata":
        return METADATA_ONLY
    if semantic_class in ("registry_write_unattributed", "registry_write_context"):
        return REGISTRY_WRITE
    if semantic_class == "program_execution_approx":
        return APPROXIMATE_EXECUTION
    if event.extra_attributes.get("semantic_basis") == "mru0_inference":
        return INFERRED_INTERACTION
    if semantic_class == "user_interaction":
        return INTERACTION
    if semantic_class == "program_execution":
        return EXECUTION
    if semantic_class == "device_first_connection":
        return DEVICE
    return NOT_CLASSIFIED


def source_path(event: ForensicEvent) -> Optional[str]:
    """Return the path as the artifact recorded it."""
    extra = event.extra_attributes
    for key in ("shellbag_path", "raw_full_path", "raw_path"):
        if extra.get(key):
            return str(extra[key])
    return None


def normalized_path(event: ForensicEvent) -> Optional[str]:
    """Return the filesystem path, or None when there is none."""
    if "fs_path" in event.extra_attributes:
        return event.extra_attributes["fs_path"] or None
    return event.target_path or None


def normalized_path_text(event: ForensicEvent) -> str:
    path = normalized_path(event)
    if path:
        return path
    if event.extra_attributes.get("fs_path_basis") == "virtual":
        return "No filesystem path (virtual Shell item)"
    return NOT_RECORDED_TEXT


def _as_list(value: Any) -> List[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [str(value)] if value else []


def source_records(event: ForensicEvent) -> List[str]:
    extra = event.extra_attributes

    records = _as_list(extra.get("source_line"))

    if not records and extra.get("source_record") is not None:
        records = [
            f"record={extra['source_record']}"
        ]

    return records + _as_list(
        extra.get("also_source_lines")
    )


def warnings(event: ForensicEvent) -> List[str]:
    """Provenance problems the investigator must resolve before relying on an event."""
    messages = []
    if not event.evidence_reference:
        messages.append("No evidence reference is recorded; this event cannot be traced to its source.")
    if not source_records(event):
        messages.append("No source record is recorded for this event.")
    if not event.timestamp_type:
        messages.append("No timestamp type is recorded; the meaning of this time is unknown.")
    if not event.case_id:
        messages.append("No case ID is recorded.")
    if event.validation_status == "synthetic":
        messages.append("Synthetic test data. Do not use it as evidence.")
    if event.validation_status == "disputed":
        messages.append("This event is disputed. Review the conflicting sources.")
    if (
        event.validation_status != "verified"
        and "verified:" in (event.evidence_reference or "").lower()
    ):
        messages.append(
            "The reference mentions a tool check of the recorded value. "
            f"The event status remains {event.validation_status or 'not recorded'}."
        )
    return messages


def limitations(event: ForensicEvent) -> List[str]:
    """Interpretation limits stated by, or directly following from, stored provenance."""
    extra = event.extra_attributes
    notes = []
    if extra.get("actor_basis") == "machine_level_unattributed":
        notes.append("Machine-level artifact; not attributed to a user account.")
    if extra.get("fs_path_basis") == "user_profile_inferred":
        notes.append("The filesystem path is inferred from the user profile.")
    if extra.get("timestamp_precision") == "fat_2s":
        notes.append("FAT timestamp with two-second resolution.")
    elif extra.get("timestamp_precision") == "fat_date_only":
        notes.append("FAT access date only; the time of day is not recorded.")
    if extra.get("cdburn_staging"):
        notes.append("CD burning staging folder; not proof that data was written to a disc.")
    twins = _as_list(extra.get("cross_hive_twin_ids"))
    if twins:
        notes.append(
            "Same activity recorded in another hive, not independent evidence: " + ", ".join(twins)
        )
    for key in ("caveat", "registry_timestamp_meaning", "verification_note"):
        if extra.get(key):
            notes.append(str(extra[key]))
    return notes
