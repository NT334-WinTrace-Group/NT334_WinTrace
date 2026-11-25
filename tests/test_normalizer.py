"""
Unit tests for PlasoNormalizer and ShellBagsNormalizer modules (v2).
Compatible with both unittest and pytest.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from src.normalizer import PlasoNormalizer, ShellBagsNormalizer
from src.schema import ForensicEvent
from src.timeline_parser import TimelineParser


class TestNormalizer(unittest.TestCase):

    def test_detect_artifact_source(self):
        self.assertEqual(PlasoNormalizer.detect_artifact_source("winreg/shellbags", "REG", "ShellBags", ""), "ShellBags")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("prefetch", "FILE", "Prefetch", ""), "Prefetch")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("lnk", "LNK", "Shortcut", ""), "LNK")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("recycle_bin", "FILE", "Recycle Bin", ""), "RecycleBin")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("winevtx", "LOG", "Event Log", ""), "EVTX")
        self.assertEqual(PlasoNormalizer.detect_artifact_source("jump_list", "FILE", "Jump List", ""), "JumpLists")

    def test_extract_windows_path(self):
        msg = "[4688] Process Creation: New Process Name: C:\\Windows\\System32\\cmd.exe PID: 1234"
        path = PlasoNormalizer.extract_windows_path(msg, "")
        self.assertEqual(path, "C:\\Windows\\System32\\cmd.exe")

        msg2 = "Deleted file: C:\\Users\\Alice\\Documents\\test.docx"
        path2 = PlasoNormalizer.extract_windows_path(msg2, "")
        self.assertEqual(path2, "C:\\Users\\Alice\\Documents\\test.docx")

    def test_extract_user_info(self):
        msg = "[4624] Strings: [User: Alice, LogonType: 2, UserSid: S-1-5-21-3928172839-1002]"
        username, sid = PlasoNormalizer.extract_user_info(msg, "")
        self.assertEqual(username, "Alice")
        self.assertEqual(sid, "S-1-5-21-3928172839-1002")

    def test_normalize_record(self):
        raw_row = {
            "datetime": "2026-10-25T02:14:00.000000+00:00",
            "timestamp_desc": "Last Time Executed",
            "source": "FILE",
            "source_long": "Windows Prefetch",
            "message": "[WINWORD.EXE-5C48A1B2.pf] Executed 14 times Path: C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE Hash: 0x5C48A1B2",
            "parser": "prefetch",
            "display_name": "C:\\Windows\\Prefetch\\WINWORD.EXE-5C48A1B2.pf"
        }

        event = PlasoNormalizer.normalize_record(raw_row, 1, case_id="CASE01")
        self.assertEqual(event.event_id, "EVT-0001")
        self.assertEqual(event.artifact_source, "Prefetch")
        self.assertEqual(event.target_path, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE")
        self.assertEqual(event.extra_attributes.get("run_count"), 14)
        self.assertEqual(event.extra_attributes.get("prefetch_hash"), "0x5C48A1B2")
        self.assertEqual(event.timestamp_type, "Prefetch_LastRun")
        self.assertEqual(event.case_id, "CASE01")
        self.assertIn("plaso:prefetch", event.evidence_reference)

    def test_normalize_record_preserves_raw_path(self):
        raw_path = "E:/Evidence//Nguyễn/資料/file.raw"
        event = PlasoNormalizer.normalize_record({
            "datetime": "2026-10-25T02:14:00+00:00",
            "target_path": raw_path,
            "raw_path": raw_path,
            "parser": "file",
            "artifact_source": "Generic",
        }, 1)

        self.assertEqual(event.target_path, "E:\\Evidence\\Nguyễn\\資料\\file.raw")
        self.assertEqual(event.extra_attributes["raw_path"], raw_path)

    def test_filestat_does_not_claim_parser_activity_for_an_artifact(self):
        event = PlasoNormalizer.normalize_record({
            "datetime": "2026-10-25T02:14:00+00:00",
            "parser": "filestat",
            "artifact_source": "Prefetch",
            "display_name": r"C:\Windows\Prefetch\WINWORD.EXE-5C48A1B2.pf",
        }, 1)

        self.assertEqual(event.artifact_source, "Generic")
        self.assertEqual(event.parser, "filestat")

    def test_normalizer_rejects_unsupported_explicit_artifact(self):
        with self.assertRaisesRegex(ValueError, "Unsupported artifact source"):
            PlasoNormalizer.normalize_record({
                "datetime": "2026-10-25T02:14:00+00:00",
                "artifact_source": "ImaginaryArtifact",
            }, 1)

    def test_shellbags_normalizer_preserves_raw_path(self):
        raw_path = r"\\server\\share\Folder"
        event = ShellBagsNormalizer._normalize_row({
            "event_id": "CASE01-SB-RAW",
            "timestamp": "2026-10-25T02:14:00+00:00",
            "target_path": raw_path,
            "artifact_source": "ShellBags",
        })

        self.assertEqual(event.target_path, r"\\server\share\Folder")
        self.assertEqual(event.extra_attributes["raw_path"], raw_path)

    def test_shellbags_normalizer_rejects_malformed_extra_attributes(self):
        with self.assertRaisesRegex(ValueError, "Invalid extra_attributes JSON"):
            ShellBagsNormalizer._normalize_row({
                "event_id": "CASE01-SB-INVALID",
                "timestamp": "2026-10-25T02:14:00+00:00",
                "artifact_source": "ShellBags",
                "extra_attributes": "{malformed",
            })

    def test_csv_export_and_import_preserve_raw_path(self):
        raw_path = "E:/Evidence//folder/file.raw"
        event = ForensicEvent(
            event_id="EVT-RAW-PATH",
            timestamp="2026-10-25T02:14:00+00:00",
            timestamp_desc="Created",
            artifact_source="Generic",
            source_file="evidence.raw",
            target_path=raw_path,
            message="Raw path round-trip",
            extra_attributes={"raw_path": raw_path},
        )

        with TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "raw_path_roundtrip.csv"
            TimelineParser.export_to_csv([event], str(output))
            restored = TimelineParser.load_from_csv(str(output))[0]

        self.assertEqual(restored.target_path, "E:\\Evidence\\folder\\file.raw")
        self.assertEqual(restored.extra_attributes["raw_path"], raw_path)

    def test_timeline_csv_import_rejects_missing_timestamp_and_malformed_json(self):
        cases = [
            (
                "event_id,timestamp,artifact_source,extra_attributes\n"
                "E01,,EVTX,{}\n",
                "Missing timestamp",
            ),
            (
                "event_id,timestamp,artifact_source,extra_attributes\n"
                "E01,2026-10-25T02:14:00Z,EVTX,{malformed\n",
                "Invalid extra_attributes JSON",
            ),
        ]
        with TemporaryDirectory() as temp_dir:
            for index, (contents, expected_error) in enumerate(cases):
                source = Path(temp_dir) / f"malformed_{index}.csv"
                source.write_text(contents, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, expected_error):
                    TimelineParser.load_from_csv(str(source))

    def test_shellbags_normalizer(self):
        csv_path = Path("results/case01_shellbags_events.csv")
        if csv_path.exists():
            events = ShellBagsNormalizer.normalize_file(str(csv_path))
            self.assertEqual(len(events), 383)
            # Check first event
            ev0 = events[0]
            self.assertEqual(ev0.event_id, "CASE01-SB0001")
            self.assertEqual(ev0.artifact_source, "ShellBags")
            self.assertEqual(ev0.case_id, "CASE01")
            self.assertEqual(ev0.timestamp_type, "ShellItem_FolderModified")
            self.assertEqual(ev0.validation_status, "unverified")
            self.assertIn("Deduplicated.csv", ev0.evidence_reference)


if __name__ == "__main__":
    unittest.main()
