"""
Unit tests for WinTrace Cross-Validation Module and Contradiction Detection.
Compatible with both unittest and pytest.
"""

import unittest
from src.schema import ForensicEvent
from src.cross_validation import CrossValidator


class TestCrossValidation(unittest.TestCase):

    def test_cross_validation_pass_scenario(self):
        events = [
            ForensicEvent(
                event_id="E01",
                timestamp="2026-10-25T02:10:00+00:00",
                timestamp_desc="BagMRU Last Interacted",
                artifact_source="ShellBags",
                source_file="UsrClass.dat",
                target_path="C:\\Users\\Alice\\Documents\\Project",
                message="Navigated to Project folder",
                username="Alice"
            ),
            ForensicEvent(
                event_id="E02",
                timestamp="2026-10-25T02:12:00+00:00",
                timestamp_desc="LNK Target File Accessed",
                artifact_source="LNK",
                source_file="report.docx.lnk",
                target_path="C:\\Users\\Alice\\Documents\\Project\\report.docx",
                message="Shortcut accessed",
                username="Alice"
            ),
            ForensicEvent(
                event_id="E03",
                timestamp="2026-10-25T02:14:00+00:00",
                timestamp_desc="Last Time Executed",
                artifact_source="Prefetch",
                source_file="WINWORD.EXE-5C48A1B2.pf",
                target_path="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                message="Executed WINWORD.EXE",
                username="Alice"
            ),
            ForensicEvent(
                event_id="E04",
                timestamp="2026-10-25T02:18:30+00:00",
                timestamp_desc="Deletion Timestamp",
                artifact_source="RecycleBin",
                source_file="$I39F1AA.docx",
                target_path="C:\\Users\\Alice\\Documents\\Project\\report.docx",
                message="Deleted file",
                user_sid="S-1-5-21-3928172839-1002",
                username="Alice"
            )
        ]

        validator = CrossValidator(events)
        report = validator.run_all_checks()

        self.assertEqual(report["summary_status"], "PARTIAL")
        self.assertEqual(report["checks"]["navigation"]["status"], "PASS")
        self.assertEqual(report["checks"]["document_execution"]["status"], "UNRESOLVED")
        self.assertEqual(report["checks"]["deletion_lifecycle"]["status"], "PASS")
        self.assertEqual(report["checks"]["user_attribution"]["status"], "UNRESOLVED")
        self.assertFalse(report["verified"])
        self.assertEqual(len(report["checks"]["deletion_lifecycle"]["contradictions"]), 0)

    def test_cross_validation_temporal_contradiction(self):
        # File deleted BEFORE it was created/accessed
        events = [
            ForensicEvent(
                event_id="E_DEL",
                timestamp="2026-10-25T02:00:00+00:00",
                timestamp_desc="Deletion Timestamp",
                artifact_source="RecycleBin",
                source_file="$I39F1AA.docx",
                target_path="C:\\Users\\Alice\\Documents\\tampered.docx",
                message="Deleted file"
            ),
            ForensicEvent(
                event_id="E_ACCESS",
                timestamp="2026-10-25T02:30:00+00:00",
                timestamp_desc="LNK Target File Accessed",
                artifact_source="LNK",
                source_file="tampered.docx.lnk",
                target_path="C:\\Users\\Alice\\Documents\\tampered.docx",
                message="Shortcut accessed"
            )
        ]

        validator = CrossValidator(events)
        h3 = validator.validate_file_deletion_lifecycle()

        self.assertEqual(h3["status"], "CONTRADICTION_FOUND")
        self.assertGreater(len(h3["contradictions"]), 0)
        self.assertEqual(h3["contradictions"][0]["type"], "TEMPORAL_ANOMALY")

    def test_empty_case_does_not_report_verified(self):
        report = CrossValidator([]).run_all_checks()
        self.assertEqual(report["summary_status"], "NO_DATA")
        self.assertTrue(all(
            check["status"] == "NO_DATA"
            for check in report["checks"].values()
        ))

    def test_prefetch_must_reference_document_to_pass_h2(self):
        events = [
            ForensicEvent(
                event_id="LNK", timestamp="2026-10-25T02:00:00Z",
                timestamp_desc="LNK File Modified", artifact_source="LNK",
                source_file="file.docx.lnk", target_path=r"C:\Case\file.docx",
                message="Shortcut metadata", timestamp_type="LNK_FileModified",
            ),
            ForensicEvent(
                event_id="PF", timestamp="2026-10-25T02:01:00Z",
                timestamp_desc="Last Time Executed", artifact_source="Prefetch",
                source_file="WINWORD.EXE.pf", target_path=r"C:\Office\WINWORD.EXE",
                message="Program execution",
                extra_attributes={"files_loaded_user": [r"\DEVICE\Volume2\Users\Alice\other.docx"]},
            ),
        ]
        result = CrossValidator(events).validate_document_execution()
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertEqual(result["matches_count"], 0)

    def test_h1_reversed_folder_and_file_order_is_not_a_pass(self):
        events = [
            ForensicEvent(
                event_id="FILE", timestamp="2015-01-01T10:00:00Z",
                timestamp_desc="LNK Target File Accessed", artifact_source="LNK",
                source_file="report.lnk", target_path=r"C:\Case\folder\report.docx",
                message="Shortcut target accessed", timestamp_type="LNK_TargetAccessed",
            ),
            ForensicEvent(
                event_id="FOLDER", timestamp="2015-01-01T10:05:00Z",
                timestamp_desc="BagMRU Last Interacted", artifact_source="ShellBags",
                source_file="UsrClass.dat", target_path=r"C:\Case\folder",
                message="Folder navigation", timestamp_type="ShellBag_LastInteracted",
            ),
        ]
        result = CrossValidator(events).validate_navigation_to_file()
        self.assertEqual(result["status"], "CONTRADICTION_FOUND")
        self.assertEqual(result["supported_count"], 0)

    def test_h2_direct_reference_outside_ten_minute_window_is_unresolved(self):
        path = r"C:\Case\file.docx"
        events = [
            ForensicEvent(
                event_id="LNK", timestamp="2015-01-01T10:30:00Z",
                timestamp_desc="LNK Target File Accessed", artifact_source="LNK",
                source_file="file.docx.lnk", target_path=path,
                message="Shortcut target accessed", timestamp_type="LNK_TargetAccessed",
            ),
            ForensicEvent(
                event_id="PF", timestamp="2015-01-01T10:00:00Z",
                timestamp_desc="Last Time Executed", artifact_source="Prefetch",
                source_file="WINWORD.EXE.pf", target_path=r"C:\Office\WINWORD.EXE",
                message="Program execution",
                extra_attributes={"files_loaded_user": [path]},
            ),
        ]
        result = CrossValidator(events).validate_document_execution()
        self.assertEqual(result["status"], "UNRESOLVED")
        self.assertEqual(result["outside_window_pairs"], 1)

    def test_attribution_requires_matching_sids_and_reports_conflict(self):
        common = r"C:\Case\report.docx"
        prior = ForensicEvent(
            event_id="LNK", timestamp="2026-10-25T02:00:00Z",
            timestamp_desc="LNK File Modified", artifact_source="LNK",
            source_file="report.docx.lnk", target_path=common,
            message="Shortcut record", user_sid="S-1-5-21-A",
            timestamp_type="LNK_TargetAccessed",
        )
        deletion = ForensicEvent(
            event_id="DEL", timestamp="2026-10-25T02:05:00Z",
            timestamp_desc="Deletion Timestamp", artifact_source="RecycleBin",
            source_file="$I-report.docx", target_path=common,
            message="Recycle Bin deletion", user_sid="S-1-5-21-B",
        )
        result = CrossValidator([prior, deletion]).validate_user_attribution()
        self.assertEqual(result["status"], "CONTRADICTION_FOUND")
        self.assertEqual(len(result["contradictions"]), 1)


if __name__ == "__main__":
    unittest.main()
