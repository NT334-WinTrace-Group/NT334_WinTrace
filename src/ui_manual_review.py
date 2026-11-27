import csv
import sqlite3
from pathlib import Path

import streamlit as st

from src import ui_data


ROOT = Path(__file__).resolve().parent.parent

REVIEW_FILE = (
    ROOT / "analysis/thi-timeline/week3_findings_validation.csv"
)

TITLES = {
    "CASE01-C1": "Network Share - Excel",
    "CASE01-C2": "Network Drive Alias",
    "CASE01-C5": "Word - Resignation Letter",
}


def load_manual_candidates(case_id):
    if not REVIEW_FILE.is_file():
        return []

    with REVIEW_FILE.open(
        encoding="utf-8-sig", newline=""
    ) as handle:
        return [
            row for row in csv.DictReader(handle)
            if row.get("case_id") == case_id
        ]


def split_ids(value):
    return [
        item.strip()
        for item in (value or "").split(";")
        if item.strip()
    ]


def render_manual_review(database, filters):
    st.subheader("Manual Evidence Review")

    if filters is None:
        st.info("Correct the sidebar filters first.")
        return

    case_id = filters.get("case_id")

    if not case_id or case_id == ui_data.NOT_RECORDED:
        st.info("Select one named case.")
        return

    try:
        candidates = load_manual_candidates(case_id)
        events = ui_data.load_matching(
            database, {"case_id": case_id}
        )
    except (sqlite3.Error, ValueError, OSError) as exc:
        st.error(f"Cannot load manual review: {exc}")
        return

    if not candidates:
        st.info("No manual candidates for this case.")
        return

    index = {event.event_id: event for event in events}

    st.caption(
        f"Case: {case_id} | {len(candidates)} manual candidates"
    )

    st.info(
        "Analyst-reviewed candidates are not "
        "ground-truth verified conclusions."
    )

    candidate_id = st.selectbox(
        "Manual candidate",
        [row["candidate_id"] for row in candidates],
        format_func=lambda key: (
            f"{key} - {TITLES.get(key, key)}"
        ),
        key="manual_candidate",
    )

    candidate = next(
        row for row in candidates
        if row["candidate_id"] == candidate_id
    )

    left, middle, right = st.columns(3)

    left.metric(
        "Review status",
        candidate.get("status", "Not recorded"),
    )
    middle.metric(
        "Validation",
        candidate.get("validation_status", "Not recorded"),
    )
    right.metric(
        "Time gap (seconds)",
        candidate.get("time_delta_seconds", "N/A"),
    )

    st.caption("Independent review")
    st.text(candidate.get("independent_review", ""))

    for label, key in [
        ("Supported observation", "supported_observation"),
        ("Safe interpretation", "safe_interpretation"),
        ("Not proven", "not_proven"),
        ("Forensic limitations", "caveat"),
        ("Candidate rules", "candidate_rules"),
    ]:
        st.markdown(f"**{label}**")
        st.text(candidate.get(key, ""))

    st.markdown("**Linked source events**")

    for role in ("primary", "context"):
        for event_id in split_ids(
            candidate.get(role + "_event_ids")
        ):
            event = index.get(event_id)

            if event is None:
                st.error(f"Missing source event: {event_id}")
                continue

            with st.expander(
                f"{role.upper()} | {event_id} | "
                f"{event.artifact_source}"
            ):
                st.text(event.timestamp)
                st.text(event.timestamp_type)
                st.text(event.validation_status or "Not recorded")
                st.code(event.target_path, language=None)
                st.code(event.evidence_reference or "Missing", language=None)

    from src.ui_enrichment import render_enrichment

    linked = [index[event_id] for event_id in dict.fromkeys(
        split_ids(candidate.get("primary_event_ids")) +
        split_ids(candidate.get("context_event_ids"))
    ) if event_id in index]
    render_enrichment(case_id, linked, candidate_id)

    st.markdown("**Original evidence references**")
    st.code(
        candidate.get("source_references", ""),
        language=None,
        wrap_lines=True,
    )

    st.caption(
        "Source events may share one underlying artifact. "
        "Do not count every linked event as independent evidence."
    )



def manual_findings_for_export(events):
    case_ids = {event.case_id for event in events}

    if len(case_ids) != 1:
        return []

    case_id = next(iter(case_ids))

    if not case_id:
        return []

    available = {event.event_id for event in events}
    findings = []

    for row in load_manual_candidates(case_id):
        primary = split_ids(row.get("primary_event_ids"))
        context = split_ids(row.get("context_event_ids"))
        linked = list(dict.fromkeys(primary + context))

        if not primary or not set(linked).issubset(available):
            continue

        findings.append({
            "candidate_type": "Manual review candidate",
            "finding_id": row["candidate_id"],
            "case_id": case_id,
            "event_ids": linked,
            "validation_status": row["validation_status"],
            "confidence_level": "NOT_SCORED",
            "confidence_score": "Not assessed",
            "time_delta_minutes": round(
                float(row["time_delta_seconds"]) / 60, 2
            ),
            "matched_rules": split_ids(row["candidate_rules"]),
            "evidence_references": row["source_references"],
            "explanation": (
                f"Review: {row['status']}. "
                f"Independent review: {row['independent_review']}. "
                f"Observation: {row['supported_observation']} "
                f"Interpretation: {row['safe_interpretation']} "
                f"Not proven: {row['not_proven']}. "
                f"Limitations: {row['caveat']}"
            ),
        })

    return findings
