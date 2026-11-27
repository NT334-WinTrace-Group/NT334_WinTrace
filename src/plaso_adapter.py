
"""Adapter for CASE01 psort CSV records after timestamp validation."""

import re

from src.schema import ForensicEvent, parse_iso_utc


LNK_TYPES = {
    "Creation Time": "LNK_TargetCreated",
    "Content Modification Time": "LNK_TargetModified",
    "Last Access Time": "LNK_TargetAccessed",
    "File Creation Time": "LNK_TargetCreated",
    "File Last Modification Time": "LNK_TargetModified",
    "File Last Access Time": "LNK_TargetAccessed",
}

PREFETCH_TYPES = {
    "Last Time Executed": "Prefetch_LastRun",
    "Previous Last Time Executed": "Prefetch_PreviousRun",
}


def classify_artifact(data_type, parser):
    if data_type == "windows:prefetch:execution":
        return "Prefetch"

    if data_type == "windows:lnk:link":
        return "LNK"

    if data_type == "olecf:dest_list:entry":
        return "JumpLists"

    if data_type == "windows:registry:bagmru":
        return "ShellBags"

    if data_type == "windows:registry:userassist":
        return "UserAssist"

    if data_type.startswith("windows:registry:"):
        return "Registry"

    return "Generic"


def classify_timestamp(data_type, description):
    if data_type == "windows:lnk:link":
        return LNK_TYPES.get(description, "Generic")

    if data_type == "windows:prefetch:execution":
        return PREFETCH_TYPES.get(description, "Generic")

    if data_type == "olecf:dest_list:entry":
        if description == "Content Modification Time":
            return "JumpList_TargetModified"

    return "Generic"


def extract_target(data_type, message):
    if data_type == "windows:lnk:link":
        pattern = (
            r"\b(?:Local path|Network path):\s*"
            r"(.*?)(?=\s+(?:Link target|Arguments|"
            r"Working directory|Network path):|$)"
        )

    elif data_type == "olecf:dest_list:entry":
        pattern = (
            r"\bPath:\s*(.*?)"
            r"(?=\s+(?:Droid volume identifier|"
            r"Droid file identifier|Birth droid):|$)"
        )

    else:
        return ""

    match = re.search(pattern, message, re.IGNORECASE)

    if not match:
        return ""

    path = match.group(1).strip()

    if re.match(r"^[A-Za-z]:\\", path):
        return path

    if path.startswith("\\\\"):
        return path

    return ""


def normalize_plaso_export_record(row, case_id=None):
    case_id = case_id or "CASE01"

    source_record = int(row["source_record"])

    if source_record <= 0:
        raise ValueError("Invalid source record")

    timestamp = parse_iso_utc(row["datetime"])
    data_type = row["data_type"]
    description = row["timestamp_desc"]
    parser = row["parser"]
    message = row.get("message", "")
    display_name = row.get("display_name", "")

    artifact = classify_artifact(data_type, parser)

    timestamp_type = classify_timestamp(
        data_type, description
    )

    target_path = extract_target(data_type, message)

    extra = {
        "source_record": source_record,
        "source_csv": "CASE01_plaso_full.csv",
        "raw_display_name": display_name,
        "raw_timestamp": row["datetime"],
        "raw_timestamp_desc": description,
        "raw_data_type": data_type,
        "raw_source": row.get("source", ""),
        "raw_source_long": row.get("source_long", ""),
        "raw_tag": row.get("tag", ""),
        "origin": "plaso_raw_artifact_export",
        "raw_path": target_path,
        "actor_basis": "unattributed",
    }

    if data_type == "olecf:dest_list:entry":
        extra["timestamp_semantics"] = (
            "DestList entry modification time, "
            "not target file content modification"
        )

    if timestamp.year == 1980:
        extra["timestamp_quality"] = "requires_review"

    if artifact == "Prefetch":
        patterns = {
            "executable": r"Prefetch \[([^\]]+)\]",
            "prefetch_hash": r"\bhash:\s*(0x[0-9a-f]+)",
            "run_count": r"\brun count\s+(\d+)",
            "path_hint": r"path hints:\s*(.*?)(?=\s+hash:|$)",
        }

        for name, pattern in patterns.items():
            match = re.search(pattern, message, re.IGNORECASE)

            if match:
                value = match.group(1).strip()

                extra[name] = (
                    int(value) if name == "run_count" else value
                )

    if artifact == "LNK":
        match = re.search(
            r"Drive serial number:\s*(0x[0-9a-f]+)",
            message,
            re.IGNORECASE,
        )

        if match:
            extra["volume_serial"] = (
                match.group(1)[2:].upper()
            )

    return ForensicEvent(
        event_id=f"{case_id}-PLASO-{source_record:06d}",
        timestamp=timestamp.isoformat(),
        timestamp_desc=description,
        artifact_source=artifact,
        source_file=display_name,
        target_path=target_path,
        message=message,
        data_type=data_type,
        parser=parser,
        username=None,
        user_sid=None,
        confidence_level="MEDIUM",
        timestamp_type=timestamp_type,
        validation_status="unverified",
        case_id=case_id,
        evidence_reference=(
            f"CASE01_plaso_full.csv:record={source_record}"
            f" | parser={parser}"
            f" | display_name={display_name}"
        ),
        extra_attributes=extra,
    )
