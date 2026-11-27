
import pytest

from src.normalizer import PlasoNormalizer


def make_row(data_type, description, message="", parser=""):
    return {
        "source_record": "37",
        "datetime": "2015-03-25T15:29:08.934806+00:00",
        "data_type": data_type,
        "timestamp_desc": description,
        "parser": parser,
        "display_name": "OS:/evidence/test",
        "message": message,
    }


@pytest.mark.parametrize(
    "data_type,description,artifact,expected_type",
    [
        (
            "windows:lnk:link",
            "Creation Time",
            "LNK",
            "LNK_TargetCreated",
        ),
        (
            "windows:lnk:link",
            "Content Modification Time",
            "LNK",
            "LNK_TargetModified",
        ),
        (
            "windows:lnk:link",
            "Last Access Time",
            "LNK",
            "LNK_TargetAccessed",
        ),
        (
            "olecf:dest_list:entry",
            "Content Modification Time",
            "JumpLists",
            "JumpList_TargetModified",
        ),
        (
            "windows:registry:userassist",
            "Last Time Executed",
            "UserAssist",
            "Generic",
        ),
        (
            "windows:registry:appcompatcache",
            "File Last Modification Time",
            "Registry",
            "Generic",
        ),
        (
            "windows:registry:bagmru",
            "Content Modification Time",
            "ShellBags",
            "Generic",
        ),
        (
            "windows:volume:creation",
            "Creation Time",
            "Generic",
            "Generic",
        ),
        (
            "windows:registry:key_value",
            "Content Modification Time",
            "Registry",
            "Generic",
        ),
        (
            "windows:prefetch:execution",
            "Last Time Executed",
            "Prefetch",
            "Prefetch_LastRun",
        ),
    ],
)
def test_semantic_mapping(
    data_type, description, artifact, expected_type
):
    row = make_row(data_type, description)

    event = PlasoNormalizer.normalize_record(
        row, 1, case_id="CASE01"
    )

    assert event.artifact_source == artifact
    assert event.timestamp_type == expected_type
    assert event.validation_status == "unverified"


def test_lnk_path_is_not_contaminated():
    row = make_row(
        "windows:lnk:link",
        "Creation Time",
        r"Drive serial number: 0x5c754d3e "
        r"Local path: E:\\ Link target: <My Computer> E:\\",
    )

    event = PlasoNormalizer.normalize_record(row, 1)

    assert event.target_path == "E:\\"
    assert event.extra_attributes["volume_serial"] == "5C754D3E"


def test_jumplist_path_with_spaces():
    path = r"V:\Secret Project Data\final\final_meeting.pptx"

    row = make_row(
        "olecf:dest_list:entry",
        "Content Modification Time",
        f"Entry: 2 Path: {path} Droid volume identifier: test",
    )

    event = PlasoNormalizer.normalize_record(row, 1)

    assert event.target_path == path


def test_jumplist_unc_path():
    path = r"\\10.11.11.128\secured_drive\Secret Project Data"

    row = make_row(
        "olecf:dest_list:entry",
        "Content Modification Time",
        f"Path: {path} Droid volume identifier: test",
    )

    event = PlasoNormalizer.normalize_record(row, 1)

    assert event.target_path == path


def test_provenance_is_preserved():
    row = make_row(
        "windows:lnk:link",
        "Creation Time",
    )

    event = PlasoNormalizer.normalize_record(
        row, 999, case_id="CASE01"
    )

    assert event.event_id == "CASE01-PLASO-000037"
    assert event.extra_attributes["source_record"] == 37
    assert "record=37" in event.evidence_reference
    assert event.username is None
    assert event.user_sid is None


def test_prefetch_run_count():
    row = make_row(
        "windows:prefetch:execution",
        "Last Time Executed",
        r"Prefetch [WINWORD.EXE] was executed - run count 3 "
        r"path hints: \PROGRAM FILES\MICROSOFT OFFICE\OFFICE15\WINWORD.EXE "
        r"hash: 0xCECBA770 volume: 1",
        "prefetch",
    )

    event = PlasoNormalizer.normalize_record(row, 1)

    assert event.extra_attributes["run_count"] == 3
    assert event.extra_attributes["executable"] == "WINWORD.EXE"
    assert event.extra_attributes["prefetch_hash"] == "0xCECBA770"
    assert event.target_path == ""
    assert "files_loaded_user" not in event.extra_attributes
