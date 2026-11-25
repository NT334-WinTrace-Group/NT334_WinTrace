"""CASE01 R04 integration: WINWORD Prefetch references the resignation DOCX."""
from pathlib import Path

from src.correlation import CorrelationEngine
from src.normalizer import PlasoNormalizer


ROOT = Path(__file__).resolve().parent.parent
SUPPORTING = ROOT / "analysis" / "phuc-artifacts" / "case01_supporting_events.csv"
DOCX = r"C:\Users\informant\Desktop\Resignation_Letter_(Iaman_Informant).docx"


def _load_events():
    events, errors = PlasoNormalizer.normalize_file_with_report(
        str(SUPPORTING), "supporting"
    )
    assert errors == []
    return events


def _r04_findings(events):
    return [
        finding for finding in CorrelationEngine(window_minutes=5).correlate(events)
        if "R04" in finding.matched_rules
    ]


def test_case01_winword_prefetch_correlates_to_resignation_lnk():
    events = _load_events()
    pf = next(e for e in events if e.event_id == "CASE01-PF0173")
    lnk = next(e for e in events if e.event_id == "CASE01-LNK0037")

    assert pf.timestamp_type == "Prefetch_LastRun"
    assert pf.timestamp == "2015-03-25T15:24:48+00:00"
    assert lnk.timestamp_type == "LNK_FileModified"
    assert lnk.target_path.casefold() == DOCX.casefold()
    assert any(
        {f.event_a_id, f.event_b_id} == {pf.event_id, lnk.event_id}
        for f in _r04_findings([pf, lnk])
    )


def test_case01_unrelated_docx_does_not_get_r04():
    events = _load_events()
    pf = next(e for e in events if e.event_id == "CASE01-PF0173")
    lnk = next(e for e in events if e.event_id == "CASE01-LNK0037")
    pf.extra_attributes["referenced_files"] = [r"E:\Unrelated\report.docx"]
    pf.extra_attributes["files_loaded_user"] = [r"E:\Unrelated\report.docx"]

    findings = _r04_findings([pf, lnk])
    assert not any(
        {f.event_a_id, f.event_b_id} == {pf.event_id, lnk.event_id}
        for f in findings
    )
