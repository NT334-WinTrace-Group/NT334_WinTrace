"""Evidence-aware validation of cross-artifact hypotheses H1 through H4."""

from typing import Any, Dict, List
from pathlib import PureWindowsPath

from src.correlation import path_relation
from src.schema import ForensicEvent

H1_MAX_GAP_MINUTES = 10.0
H2_MAX_GAP_MINUTES = 10.0


def _result(hypothesis: str, status: str, details: list, **counts: int) -> Dict[str, Any]:
    return {
        "hypothesis": hypothesis,
        "status": status,
        "matches_count": len(details),
        "details": details,
        **counts,
    }


def _is_user_interaction(event: ForensicEvent) -> bool:
    semantic_class = event.extra_attributes.get("semantic_class")
    if semantic_class:
        return semantic_class == "user_interaction"
    typed_interactions = {
        "ShellBag_FirstInteracted", "ShellBag_LastInteracted",
        "LNK_TargetAccessed", "JumpList_TargetAccessed",
    }
    if event.timestamp_type:
        return event.timestamp_type in typed_interactions

    legacy_descriptions = {
        "shellbags": {"bagmru first interacted", "bagmru last interacted", "last time visited"},
        "lnk": {"lnk target accessed", "lnk target file accessed", "file last access time"},
        "jumplists": {"jumplist target accessed", "target accessed"},
    }
    allowed = legacy_descriptions.get(event.artifact_source.casefold(), set())
    return event.timestamp_desc.strip().casefold() in allowed


def _references_path(program: ForensicEvent, document: ForensicEvent) -> bool:
    references = program.extra_attributes.get("files_loaded_user", [])
    if not isinstance(references, list):
        return False
    document_path = document.extra_attributes.get("fs_path") or document.target_path
    for reference in references:
        if not isinstance(reference, str):
            continue
        if path_relation(reference, document_path) == "Same path":
            return True
    return False


def _folder_is_parent(folder: str, target: str) -> bool:
    """Return true only when folder is a strict ancestor of target."""
    parent = PureWindowsPath(folder)
    child = PureWindowsPath(target)
    if not parent.is_absolute() or not child.is_absolute():
        return False
    parent_parts = tuple(part.casefold() for part in parent.parts)
    child_parts = tuple(part.casefold() for part in child.parts)
    return len(parent_parts) < len(child_parts) and child_parts[:len(parent_parts)] == parent_parts


def _is_deletion_event(event: ForensicEvent) -> bool:
    if event.artifact_source != "RecycleBin":
        return False
    if event.timestamp_type == "RecycleBin_DeletionTime":
        return True
    return event.extra_attributes.get("semantic_class") == "deletion"


def _same_object_lifecycle(left: ForensicEvent, right: ForensicEvent) -> bool:
    left_attrs = left.extra_attributes
    right_attrs = right.extra_attributes
    identity_keys = ("file_id", "object_id", "ntfs_file_reference")
    lifecycle_keys = ("lifecycle_id", "file_lifecycle_id")
    same_identity = any(
        left_attrs.get(key) and right_attrs.get(key)
        and str(left_attrs[key]).casefold() == str(right_attrs[key]).casefold()
        for key in identity_keys
    )
    same_lifecycle = any(
        left_attrs.get(key) and right_attrs.get(key)
        and str(left_attrs[key]).casefold() == str(right_attrs[key]).casefold()
        for key in lifecycle_keys
    )
    return same_identity and same_lifecycle


class CrossValidator:
    """Returns PASS only when the corresponding evidence supports a hypothesis."""

    def __init__(self, events: List[ForensicEvent]):
        case_ids = {event.case_id for event in events}
        if len(case_ids) > 1:
            raise ValueError(
                "CrossValidator accepts events from exactly one case; "
                "partition events by case_id before validation"
            )
        self.events = sorted(events, key=lambda event: event.dt)

    def validate_navigation_to_file(self) -> Dict[str, Any]:
        shellbags = [
            event for event in self.events
            if event.artifact_source == "ShellBags" and _is_user_interaction(event)
        ]
        interactions = [
            event for event in self.events
            if event.artifact_source in {"LNK", "JumpLists"} and _is_user_interaction(event)
        ]
        details = []
        for folder in shellbags:
            for interaction in interactions:
                if not _folder_is_parent(folder.target_path, interaction.target_path):
                    continue
                delta = (interaction.dt - folder.dt).total_seconds() / 60
                if abs(delta) > H1_MAX_GAP_MINUTES:
                    continue
                details.append({
                    "folder_event": folder.event_id,
                    "file_event": interaction.event_id,
                    "folder_path": folder.target_path,
                    "file_path": interaction.target_path,
                    "time_diff_minutes": round(delta, 2),
                    "logical_order": delta >= 0,
                    "evidence_references": [folder.evidence_reference, interaction.evidence_reference],
                    "case_id": folder.case_id,
                })
        ordered = [item for item in details if item["logical_order"]]
        reversed_order = [item for item in details if not item["logical_order"]]
        status = (
            "PARTIAL" if ordered and reversed_order
            else "PASS" if ordered
            else "CONTRADICTION_FOUND" if reversed_order
            else "NO_DATA"
        )
        return _result(
            "H1_User_Navigation", status, details,
            supported_count=len(ordered), reversed_order_count=len(reversed_order),
        )

    def validate_document_execution(self) -> Dict[str, Any]:
        links = [event for event in self.events if event.artifact_source == "LNK"]
        prefetch = [event for event in self.events if event.artifact_source == "Prefetch"]
        details = []
        compatible_count = 0
        direct_reference_count = 0
        outside_window_count = 0
        for link in links:
            extension = PureWindowsPath(link.target_path).suffix.casefold()
            for program in prefetch:
                name = PureWindowsPath(program.target_path).name.casefold()
                compatible = (
                    (extension in {".doc", ".docx"} and "winword" in name)
                    or (extension == ".pdf" and ("acrobat" in name or "acro" in name))
                    or (extension in {".txt", ".log"} and "notepad" in name)
                )
                if not compatible:
                    continue
                compatible_count += 1
                if not _references_path(program, link):
                    continue
                direct_reference_count += 1
                delta = abs((program.dt - link.dt).total_seconds()) / 60
                if delta > H2_MAX_GAP_MINUTES:
                    outside_window_count += 1
                    continue
                details.append({
                    "lnk_event": link.event_id,
                    "prefetch_event": program.event_id,
                    "document": link.target_path,
                    "executable": program.target_path,
                    "time_diff_minutes": round(delta, 2),
                    "direct_file_reference": True,
                    "claim_scope": "application_reference_to_document",
                    "user_interaction_proven": False,
                    "interpretation": (
                        "Prefetch references this document in the application context; "
                        "this does not by itself prove a person opened it."
                    ),
                    "evidence_references": [link.evidence_reference, program.evidence_reference],
                    "case_id": link.case_id,
                })
        status = "PASS" if details else ("UNRESOLVED" if compatible_count else "NO_DATA")
        return _result(
            "H2_Document_Execution", status, details,
            compatible_pairs=compatible_count,
            direct_reference_pairs=direct_reference_count,
            outside_window_pairs=outside_window_count,
        )

    def validate_file_deletion_lifecycle(self) -> Dict[str, Any]:
        deletions = [event for event in self.events if _is_deletion_event(event)]
        interactions = [event for event in self.events if _is_user_interaction(event)]
        lifecycle, anomalies = [], []
        for deletion in deletions:
            for interaction in interactions:
                if path_relation(deletion.target_path, interaction.target_path) != "Same path":
                    continue
                delta = (deletion.dt - interaction.dt).total_seconds() / 60
                item = {
                    "deletion_event": deletion.event_id,
                    "prior_event": interaction.event_id,
                    "prior_source": interaction.artifact_source,
                    "time_to_deletion_minutes": round(delta, 2),
                    "evidence_references": [interaction.evidence_reference, deletion.evidence_reference],
                }
                if delta > 0:
                    lifecycle.append(item)
                elif delta < 0:
                    anomalies.append({
                        **item,
                        "type": "TEMPORAL_ANOMALY",
                        "review_status": "REVIEW_REQUIRED",
                        "message": (
                            f"Interaction {interaction.event_id} is later than deletion "
                            f"{deletion.event_id}; the file may have been recreated, so "
                            "this is not a confirmed contradiction."
                        ),
                    })
        status = (
            "PARTIAL" if anomalies and lifecycle
            else "REVIEW_REQUIRED" if anomalies
            else "PASS" if lifecycle
            else "NO_DATA" if not deletions
            else "UNRESOLVED"
        )
        return _result(
            "H3_File_Deletion_Lifecycle", status, lifecycle,
            temporal_anomalies=anomalies,
            contradictions=[],
        )

    def validate_user_attribution(self) -> Dict[str, Any]:
        deletions = [event for event in self.events if _is_deletion_event(event)]
        attributed = [event for event in self.events if _is_user_interaction(event)]
        matches, unresolved = [], []
        for deletion in deletions:
            for prior in attributed:
                if path_relation(deletion.target_path, prior.target_path) != "Same path":
                    continue
                if deletion.dt <= prior.dt:
                    continue
                detail = {
                    "deletion_event": deletion.event_id,
                    "prior_event": prior.event_id,
                    "deletion_sid": deletion.user_sid,
                    "prior_sid": prior.user_sid,
                    "evidence_references": [prior.evidence_reference, deletion.evidence_reference],
                }
                if not deletion.user_sid or not prior.user_sid:
                    unresolved.append(detail)
                elif not _same_object_lifecycle(deletion, prior):
                    detail["review_status"] = "REVIEW_REQUIRED"
                    detail["reason"] = (
                        "Matching path/time/SID is insufficient without a shared stable "
                        "file identity and lifecycle identifier."
                    )
                    unresolved.append(detail)
                elif deletion.user_sid.casefold() == prior.user_sid.casefold():
                    matches.append(detail)
                else:
                    detail["review_status"] = "REVIEW_REQUIRED"
                    detail["reason"] = (
                        "Different SIDs on path/time-correlated records do not establish "
                        "the same file lifecycle or a false attribution."
                    )
                    unresolved.append(detail)
        status = (
            "PASS" if matches and not unresolved
            else "REVIEW_REQUIRED" if unresolved
            else "NO_DATA" if not deletions
            else "NO_DATA"
        )
        return _result(
            "H4_User_Attribution", status, matches,
            unresolved=unresolved, contradictions=[],
        )

    def run_all_checks(self) -> Dict[str, Any]:
        checks = {
            "navigation": self.validate_navigation_to_file(),
            "document_execution": self.validate_document_execution(),
            "deletion_lifecycle": self.validate_file_deletion_lifecycle(),
            "user_attribution": self.validate_user_attribution(),
        }
        statuses = [check["status"] for check in checks.values()]
        if "CONTRADICTION_FOUND" in statuses:
            summary = "CONTRADICTION_FOUND"
        elif all(status == "PASS" for status in statuses):
            summary = "PASS"
        elif all(status == "NO_DATA" for status in statuses):
            summary = "NO_DATA"
        else:
            summary = "PARTIAL"
        return {
            "summary_status": summary,
            "total_events_checked": len(self.events),
            "checks": checks,
            "verified": False,
            "verification_note": "Cross-validation results are not ground-truth verification.",
        }
