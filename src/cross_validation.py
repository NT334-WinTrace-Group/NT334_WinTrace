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


class CrossValidator:
    """Returns PASS only when the corresponding evidence supports a hypothesis."""

    def __init__(self, events: List[ForensicEvent]):
        self.events = sorted(events, key=lambda event: event.dt)

    def validate_navigation_to_file(self) -> Dict[str, Any]:
        shellbags = [event for event in self.events if event.artifact_source == "ShellBags"]
        interactions = [
            event for event in self.events
            if event.artifact_source in {"LNK", "JumpLists"} and _is_user_interaction(event)
        ]
        details = []
        for folder in shellbags:
            for interaction in interactions:
                if path_relation(folder.target_path, interaction.target_path) != "Parent-child path":
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
                    "evidence_references": [link.evidence_reference, program.evidence_reference],
                })
        status = "PASS" if details else ("UNRESOLVED" if compatible_count else "NO_DATA")
        return _result(
            "H2_Document_Execution", status, details,
            compatible_pairs=compatible_count,
            direct_reference_pairs=direct_reference_count,
            outside_window_pairs=outside_window_count,
        )

    def validate_file_deletion_lifecycle(self) -> Dict[str, Any]:
        deletions = [event for event in self.events if event.artifact_source == "RecycleBin"]
        interactions = [event for event in self.events if _is_user_interaction(event)]
        lifecycle, contradictions = [], []
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
                    contradictions.append({
                        **item,
                        "type": "TEMPORAL_ANOMALY",
                        "message": f"Recorded interaction {interaction.event_id} is later than deletion {deletion.event_id}",
                    })
        status = (
            "CONTRADICTION_FOUND" if contradictions
            else "PASS" if lifecycle
            else "NO_DATA" if not deletions
            else "UNRESOLVED"
        )
        return _result(
            "H3_File_Deletion_Lifecycle", status, lifecycle,
            contradictions=contradictions,
        )

    def validate_user_attribution(self) -> Dict[str, Any]:
        deletions = [event for event in self.events if event.artifact_source == "RecycleBin"]
        attributed = [event for event in self.events if _is_user_interaction(event)]
        matches, conflicts, unresolved = [], [], []
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
                elif deletion.user_sid.casefold() == prior.user_sid.casefold():
                    matches.append(detail)
                else:
                    conflicts.append(detail)
        status = (
            "CONTRADICTION_FOUND" if conflicts
            else "PASS" if matches
            else "NO_DATA" if not deletions
            else "UNRESOLVED" if unresolved
            else "NO_DATA"
        )
        return _result(
            "H4_User_Attribution", status, matches,
            unresolved=unresolved, contradictions=conflicts,
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
