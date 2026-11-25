"""
WinTrace - Streamlit Investigation Dashboard (v2)
Author: Quyen (Validation & Visualization Engineer)
"""

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import ui_data
from src.report_generator import ReportGenerator

DEFAULT_DATABASE = "results/CASE01/timeline.db"
DEFAULT_FINDINGS = "results/CASE01/findings.json"
ALL = ""  # selectbox value meaning "no filter"; None would show as unselected
PAGE_SIZES = [25, 50, 100, 250]
FILTER_DEFAULTS = {
    "filter_start": "",
    "filter_end": "",
    "filter_path": "",
    "filter_keyword": "",
    "filter_artifacts": [],
    "filter_status": ALL,
}

st.set_page_config(page_title="WinTrace", layout="wide")


def first_page():
    st.session_state["page"] = 1


def reset_filters():
    for key, value in FILTER_DEFAULTS.items():
        st.session_state[key] = list(value) if isinstance(value, list) else value
    first_page()


def change_database():
    st.session_state.pop("filter_case", None)
    reset_filters()


def move_page(step):
    st.session_state["page"] = st.session_state.get("page", 1) + step


def missing_label(value, all_label, missing):
    if value == ALL:
        return all_label
    return missing if value == ui_data.NOT_RECORDED else value


def option_values(values):
    """Offer "no filter" first and give stored missing values an explicit option."""
    return [ALL] + [ui_data.NOT_RECORDED if v is None else v for v in values]


def sidebar_sources():
    st.sidebar.header("Data sources")
    database = st.sidebar.text_input(
        "Timeline database (SQLite)", value=DEFAULT_DATABASE, key="database",
        on_change=change_database, help="Opened read-only; the dashboard never changes it.",
    )
    findings = st.sidebar.text_input(
        "Correlation findings (JSON)", value=DEFAULT_FINDINGS, key="findings"
    )
    return database.strip(), findings.strip()


def load_summary(database):
    try:
        return ui_data.load_summary(database)
    except FileNotFoundError:
        st.info(f"No timeline database at `{database or '(empty path)'}`.")
        st.markdown(
            "Run the pipeline as described in the README to create it, "
            "or enter another database path in the sidebar."
        )
    except (sqlite3.Error, ValueError, OSError) as exc:
        st.error(f"Cannot read this timeline database: {exc}")
    return None


def sidebar_filters(summary):
    """Render the filters and return store arguments, or None when invalid."""
    st.sidebar.header("Filters")
    case_options = option_values(summary.case_ids)
    default_case = 1 if len(summary.case_ids) == 1 else 0
    case_id = st.sidebar.selectbox(
        "Case", case_options, index=default_case, key="filter_case", on_change=first_page,
        format_func=lambda v: missing_label(v, "All cases", "Unspecified"),
    )
    for key, value in FILTER_DEFAULTS.items():
        st.session_state.setdefault(key, list(value) if isinstance(value, list) else value)
    # The file may have been replaced since these options were chosen.
    st.session_state["filter_artifacts"] = [
        value for value in st.session_state["filter_artifacts"] if value in summary.artifacts
    ]
    status_options = option_values(summary.validation_statuses)
    if st.session_state["filter_status"] not in status_options:
        st.session_state["filter_status"] = ALL
    with st.sidebar.form("filters", border=False):
        st.text_input("From (UTC)", key="filter_start", placeholder="2015-03-23 20:24:00")
        st.text_input(
            "To (UTC)", key="filter_end", placeholder="2015-03-24",
            help="Both bounds are inclusive. A date alone covers the whole day.",
        )
        st.text_input("Path contains", key="filter_path", placeholder=r"\\10.11.11.128\secured_drive")
        st.text_input(
            "Keyword", key="filter_keyword",
            help="Searches path, source file, description, event ID and evidence reference.",
        )
        st.multiselect(
            "Artifacts", summary.artifacts, key="filter_artifacts", placeholder="All artifacts"
        )
        st.selectbox(
            "Validation status", status_options, key="filter_status",
            format_func=lambda v: missing_label(v, "All statuses", "Not recorded"),
        )
        st.form_submit_button(
            "Apply filters", type="primary", width="stretch", on_click=first_page
        )
        st.form_submit_button("Reset filters", width="stretch", on_click=reset_filters)
    try:
        return ui_data.build_filters(
            case_id=case_id or None,
            start_text=st.session_state["filter_start"],
            end_text=st.session_state["filter_end"],
            path=st.session_state["filter_path"],
            keyword=st.session_state["filter_keyword"],
            artifacts=st.session_state["filter_artifacts"],
            validation_status=st.session_state["filter_status"] or None,
        )
    except ValueError as exc:
        st.sidebar.error(str(exc))
        return None


def render_event_detail(event):
    st.subheader("Evidence detail")
    left, right = st.columns(2)
    with left:
        st.markdown(f"**Timestamp:** `{ui_data.format_utc(event)}` ({event.timestamp_type or 'Not recorded'})")
        st.markdown(f"**Artifact:** `{event.artifact_source}`")
        st.markdown(f"**Source file:** `{event.source_file}`")
        st.markdown(f"**Case ID:** `{event.case_id or 'Unspecified'}`")
    with right:
        st.markdown("**Description**")
        st.text(event.message)
        st.markdown(f"**Validation status:** `{event.validation_status or 'Not recorded'}`")
    st.markdown("**Path**")
    st.code(event.target_path or "Not recorded", language=None, wrap_lines=True)
    st.markdown("**Evidence reference**")
    st.code(event.evidence_reference or "Not recorded", language=None, wrap_lines=True)
    with st.expander("Extra attributes"):
        st.json(event.extra_attributes)


def render_timeline(database, filters, summary):
    if filters is None:
        st.warning("Correct the filter shown in the sidebar to load events.")
        return
    size_column, _ = st.columns([1, 4])
    page_size = size_column.selectbox(
        "Rows per page", PAGE_SIZES, index=1, key="page_size", on_change=first_page
    )
    try:
        result = ui_data.load_page(
            database, filters, st.session_state.get("page", 1), page_size
        )
    except (sqlite3.Error, ValueError, OSError, json.JSONDecodeError) as exc:
        st.error(f"Cannot load timeline events: {exc}")
        return
    st.session_state["page"] = result.page
    if not result.events:
        st.info("No events match these filters.")
        st.markdown(
            f"The database holds {summary.total:,} events. Widen the UTC range, "
            "shorten the path or keyword, or use **Reset filters**."
        )
        return

    st.markdown(
        f"Showing **{result.first:,}–{result.last:,}** of **{result.total:,}** matching events "
        f"({summary.total:,} in database)"
    )
    table = pd.DataFrame(
        [ui_data.timeline_row(event) for event in result.events],
        columns=ui_data.TIMELINE_COLUMNS,
    )
    st.dataframe(
        table, width="stretch", height=min(460, 38 + 35 * len(table)), hide_index=True,
        column_config={
            "Path": st.column_config.TextColumn(width="large"),
            "Description": st.column_config.TextColumn(width="medium"),
        },
    )
    previous, position, following = st.columns([1, 2, 1])
    previous.button(
        "Previous page", disabled=result.page == 1, on_click=move_page, args=(-1,),
        width="stretch", key="previous_page",
    )
    position.markdown(f"Page **{result.page:,}** of **{result.page_count:,}**")
    following.button(
        "Next page", disabled=result.page == result.page_count, on_click=move_page, args=(1,),
        width="stretch", key="next_page",
    )

    by_index = dict(enumerate(result.events))
    selected = st.selectbox(
        "Event to inspect", list(by_index),
        format_func=lambda i: f"{by_index[i].event_id} | {ui_data.format_utc(by_index[i])}",
    )
    render_event_detail(by_index[selected])


def load_findings(path, filters, summary):
    case_id = filters["case_id"] if filters else None
    if case_id == ui_data.NOT_RECORDED:
        case_ids = [None]
    else:
        case_ids = [case_id] if case_id else summary.case_ids
    try:
        findings, excluded = ui_data.load_findings(path, case_ids)
    except FileNotFoundError:
        return [], f"No findings file at `{path or '(empty path)'}`."
    except (OSError, ValueError) as exc:
        return [], f"Cannot read the findings file: {exc}"
    note = None
    if excluded:
        note = f"{excluded:,} findings from another or unspecified case are not shown."
    return findings, note


def render_findings(findings, note):
    if note:
        st.warning(note)
    if not findings:
        st.info("No correlation findings to show for this case.")
        return
    st.markdown(f"**{len(findings):,}** candidate findings")
    table = pd.DataFrame(findings)
    columns = ["finding_id", "confidence_level", "matched_rules", "time_delta_minutes", "explanation"]
    st.dataframe(table.reindex(columns=columns), width="stretch", hide_index=True)
    by_id = {str(f.get("finding_id")): f for f in findings}
    selected = st.selectbox("Finding to inspect", list(by_id))
    detail = by_id[selected]
    st.markdown(f"**Rules matched:** `{', '.join(detail.get('matched_rules') or [])}`")
    for side in ("a", "b"):
        st.markdown(f"**Event {side.upper()}:** `{detail.get(f'event_{side}_id')}`")
        st.text(str(detail.get(f"event_{side}_desc") or ""))
    for reference in detail.get("evidence_references") or []:
        st.code(reference, language=None, wrap_lines=True)


def render_reporting(database, filters, findings):
    if filters is None:
        st.warning("Correct the filter shown in the sidebar before exporting.")
        return
    if not st.button("Prepare export for all matching events"):
        return
    try:
        events = ui_data.load_matching(database, filters)
    except (sqlite3.Error, ValueError, OSError) as exc:
        st.error(f"Cannot prepare the export: {exc}")
        return
    if not events:
        st.info("No matching events to export.")
        return
    st.markdown(f"Export contains **{len(events):,}** matching events.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    st.download_button(
        "Download HTML report",
        ReportGenerator.generate_html_report(events, findings),
        file_name=f"wintrace_report_{stamp}.html", mime="text/html", on_click="ignore",
    )
    st.download_button(
        "Download filtered timeline (CSV)",
        pd.DataFrame([event.to_dict() for event in events]).to_csv(index=False).encode("utf-8"),
        file_name=f"filtered_timeline_{stamp}.csv", mime="text/csv", on_click="ignore",
    )


def main():
    st.html("<style>.block-container {padding-top: 2.5rem;}</style>")
    st.title("WinTrace")
    st.caption("Windows super timeline analysis. All times are UTC.")
    database, findings_path = sidebar_sources()
    summary = load_summary(database)
    if summary is None:
        return
    if summary.total == 0:
        st.info("This timeline database contains no events. Import a case with the pipeline first.")
        return
    filters = sidebar_filters(summary)
    findings, findings_note = load_findings(findings_path, filters, summary)

    timeline_tab, findings_tab, report_tab = st.tabs(
        ["Timeline", "Correlation findings", "Reporting"]
    )
    with timeline_tab:
        render_timeline(database, filters, summary)
    with findings_tab:
        render_findings(findings, findings_note)
    with report_tab:
        render_reporting(database, filters, findings)


if __name__ == "__main__":
    main()
