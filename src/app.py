"""
WinTrace - Streamlit Investigation Dashboard (v2)
Author: Quyen (Validation & Visualization Engineer)
"""

import json
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src import ui_data, ui_evidence, ui_export, ui_findings
from src.report_generator import ReportGenerator
from src.cross_validation import CrossValidator
from src.ui_manual_review import (
    render_manual_review,
    manual_findings_for_export,
)
from src.schema import VALID_VALIDATION_STATUSES

DEFAULT_DATABASE = "results/CASE01/timeline.db"
DEFAULT_FINDINGS = "results/CASE01/findings.json"
ALL = ""  # selectbox value meaning "no filter"; None would show as unselected
# Streamlit's faded captions, badges and alerts fall short of 4.5:1 contrast.
STYLE = """<style>
.block-container {padding-top: 2.5rem;}
[data-testid="stCaptionContainer"] {opacity: 1;}
[data-testid="stCaptionContainer"] p {color: #475569; opacity: 1;}
.stMarkdownBadge, [data-testid="stAlert"] p {color: #0F172A !important;}
/* The grid's own CSV button would bypass the validated export. */
[data-testid="stElementToolbar"] {display: none;}
</style>"""
FINDINGS_PER_PAGE = 50
MAX_LISTED_ERRORS = 100
PAGE_SIZES = [25, 50, 100, 250]
STATUS_COLORS = {"verified": "green", "disputed": "red", "synthetic": "violet"}
TONE_COLORS = {"evidence": "blue", "inferred": "orange", "limited": "gray"}
REVIEW_COLORS = {"Candidate": "gray", "Validated": "green", "Unresolved": "orange", "Synthetic": "violet"}
FINDING_FILTER_KEYS = [
    "finding_text", "finding_statuses", "finding_rules", "finding_exclude_limited", "finding_sort",
]
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
    reset_finding_filters()


def move_page(step, key="page"):
    st.session_state[key] = st.session_state.get(key, 1) + step


def first_finding_page():
    st.session_state["finding_page"] = 1


def reset_finding_filters():
    for key in FINDING_FILTER_KEYS:
        st.session_state.pop(key, None)
    first_finding_page()


def file_signature(path):
    """Change whenever the file is rewritten, so cached results cannot go stale."""
    status = Path(path).stat()
    return status.st_mtime_ns, status.st_size


# Shared, read-only results: callers must not modify the returned objects.
@st.cache_resource(max_entries=4, show_spinner="Loading findings")
def cached_findings(path, signature, case_ids):
    return ui_data.load_findings(path, list(case_ids))


@st.cache_resource(max_entries=4, show_spinner="Linking findings to events")
def cached_event_index(database, database_signature, findings_path, findings_signature, case_ids, _findings):
    malformed = []
    return ui_findings.load_event_index(database, _findings, malformed), len(malformed)


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
        "Correlation findings (JSON)", value=DEFAULT_FINDINGS, key="findings",
        on_change=reset_finding_filters,
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


def page_controls(page, page_count, state_key, prefix):
    previous, position, following = st.columns([1, 2, 1])
    previous.button(
        "Previous page", disabled=page == 1, on_click=move_page, args=(-1, state_key),
        width="stretch", key=f"{prefix}previous_page",
    )
    position.markdown(f"Page **{page:,}** of **{page_count:,}**")
    following.button(
        "Next page", disabled=page == page_count, on_click=move_page, args=(1, state_key),
        width="stretch", key=f"{prefix}next_page",
    )


def field(label, value):
    """Show stored text literally; evidence must not be parsed as Markdown."""
    st.caption(label)
    st.text(value or ui_evidence.NOT_RECORDED_TEXT)


def code_field(label, value):
    st.caption(label)
    st.code(value or ui_evidence.NOT_RECORDED_TEXT, language=None, wrap_lines=True)


def render_event_detail(event):
    st.subheader("Evidence detail")
    basis = ui_evidence.evidence_basis(event)
    status = event.validation_status or ui_evidence.NOT_RECORDED_TEXT
    status_column, basis_column = st.columns([1, 2])
    with status_column:
        st.caption("Validation status")
        st.badge(status, color=STATUS_COLORS.get(status, "gray"))
    with basis_column:
        st.caption("Evidence basis")
        st.badge(basis.label, color=TONE_COLORS[basis.tone])
        st.markdown(basis.explanation)
    for message in ui_evidence.warnings(event):
        st.warning(message)

    left, middle, right = st.columns(3)
    with left:
        field("Event ID", event.event_id)
        field("Case ID", event.case_id or "Unspecified")
        field("Artifact", event.artifact_source)
    with middle:
        field("Timestamp", ui_data.format_utc(event))
        field("Timestamp type", event.timestamp_type)
        field("Timestamp meaning", event.timestamp_desc)
    with right:
        field("Source file", event.source_file)
        field("Source record", ", ".join(ui_evidence.source_records(event)))
        field("Parser", event.parser)

    source_column, normalized_column = st.columns(2)
    with source_column:
        code_field("Path recorded by the artifact", ui_evidence.source_path(event))
    with normalized_column:
        code_field("Normalized filesystem path", ui_evidence.normalized_path_text(event))
    code_field("Evidence reference", event.evidence_reference)
    code_field("Description", event.message)

    notes = ui_evidence.limitations(event)
    if notes:
        st.caption("Interpretation limits")
        for note in notes:
            st.text(note)
    with st.expander("All stored attributes"):
        st.json(event.to_dict())


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
    if result.malformed:
        st.error(f"{len(result.malformed):,} stored events on this page cannot be read.")
        for message in result.malformed[:MAX_LISTED_ERRORS]:
            st.text(message)
    if not result.total:
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
    page_controls(result.page, result.page_count, "page", "")
    if not result.events:
        return

    by_index = dict(enumerate(result.events))
    selected = st.selectbox(
        "Event to inspect", list(by_index),
        format_func=lambda i: f"{by_index[i].event_id} | {ui_data.format_utc(by_index[i])}",
    )
    render_event_detail(by_index[selected])


def load_findings(database, path, filters, summary):
    """Return (findings, index of cited events, note for the investigator)."""
    case_id = filters["case_id"] if filters else None
    if case_id == ui_data.NOT_RECORDED:
        case_ids = (None,)
    else:
        case_ids = (case_id,) if case_id else tuple(summary.case_ids)
    try:
        signature = file_signature(path)
        findings, excluded = cached_findings(path, signature, case_ids)
        index, unreadable = cached_event_index(
            database, file_signature(database), path, signature, case_ids, findings
        )
    except FileNotFoundError:
        return [], {}, f"No findings file at `{path or '(empty path)'}`."
    except (OSError, ValueError, sqlite3.Error) as exc:
        return [], {}, f"Cannot read the findings file: {exc}"
    notes = []
    if excluded:
        notes.append(f"{excluded:,} findings from another or unspecified case are not shown.")
    if unreadable:
        notes.append(f"{unreadable:,} cited events cannot be read from the database.")
    return findings, index, " ".join(notes)


def finding_filters(findings):
    statuses = sorted({ui_findings.review_status(f) for f in findings})
    rules = sorted({rule for f in findings for rule in ui_findings.as_list(f.get("matched_rules"))})
    # Keep only selections that the current findings file still offers.
    for key, options in (("finding_statuses", statuses), ("finding_rules", rules)):
        if key in st.session_state:
            st.session_state[key] = [v for v in st.session_state[key] if v in options]
    text_column, status_column, rule_column, sort_column = st.columns([3, 2, 2, 2])
    text = text_column.text_input(
        "Search findings", key="finding_text", on_change=first_finding_page,
        placeholder="CASE01-SB0133 CASE01-JL0022",
        help="Every word must appear in the IDs, paths, source files, references or explanation.",
    )
    chosen_statuses = status_column.multiselect(
        "Review status", statuses, key="finding_statuses", placeholder="All statuses",
        on_change=first_finding_page,
    )
    chosen_rules = rule_column.multiselect(
        "Must match rules", rules, key="finding_rules", placeholder="Any rules",
        on_change=first_finding_page,
    )
    sort = sort_column.selectbox(
        "Sort by", ui_findings.SORT_ORDERS, key="finding_sort", on_change=first_finding_page
    )
    exclude_limited = st.checkbox(
        "Hide findings that rely on metadata-only, registry-write or unclassified events",
        key="finding_exclude_limited", on_change=first_finding_page,
    )
    return ui_findings.FindingFilter(
        text=text, statuses=tuple(chosen_statuses), rules=tuple(chosen_rules),
        exclude_limited=exclude_limited,
    ), sort


def render_findings(findings, index, note):
    """Render the tab and return (selected findings, their filter description)."""
    if note:
        st.warning(note)
    if not findings:
        st.info("No correlation findings to show for this case.")
        return [], {}
    counts = Counter(ui_findings.review_status(f) for f in findings)
    st.markdown(
        f"**{len(findings):,}** findings: "
        + ", ".join(f"**{count:,}** {label}" for label, count in sorted(counts.items()))
    )
    st.caption(
        "Scores rank candidates for review. They do not validate a finding; "
        "the review status is read from the findings file."
    )
    criteria, sort = finding_filters(findings)
    selected = ui_findings.select_findings(findings, index, criteria, sort)
    description = {**vars(criteria), "sort": sort}
    if not selected:
        st.info("No findings match these filters.")
        st.button("Reset finding filters", on_click=reset_finding_filters)
        return [], description

    page_count = (len(selected) + FINDINGS_PER_PAGE - 1) // FINDINGS_PER_PAGE
    page = min(max(st.session_state.get("finding_page", 1), 1), page_count)
    st.session_state["finding_page"] = page
    offset = (page - 1) * FINDINGS_PER_PAGE
    visible = selected[offset:offset + FINDINGS_PER_PAGE]
    st.markdown(
        f"Showing findings **{offset + 1:,}–{offset + len(visible):,}** of **{len(selected):,}**"
    )
    rows = [ui_findings.finding_row(finding, index) for finding in visible]
    st.dataframe(
        pd.DataFrame(rows, columns=ui_findings.FINDING_COLUMNS),
        width="stretch", height=min(460, 38 + 35 * len(rows)), hide_index=True,
        column_config={"Path": st.column_config.TextColumn(width="large")},
    )
    page_controls(page, page_count, "finding_page", "finding_")
    position = st.selectbox(
        "Finding to inspect", range(len(visible)),
        format_func=lambda i: f"{rows[i]['Finding ID']} | {rows[i]['Event IDs']}",
    )
    render_finding_detail(visible[position], rows[position], index)
    return selected, description


def render_finding_detail(finding, row, index):
    st.subheader("Finding detail")
    status_column, text_column = st.columns([1, 2])
    with status_column:
        st.caption("Review status")
        st.badge(row["Review status"], color=REVIEW_COLORS.get(row["Review status"], "red"))
    with text_column:
        st.caption("Stored validation status")
        st.text(str(finding.get("validation_status") or ui_evidence.NOT_RECORDED_TEXT))
    for message in ui_findings.problems(finding, index):
        st.warning(message)

    left, middle, right = st.columns(3)
    with left:
        field("Finding ID", row["Finding ID"])
        field("Case ID", row["Case"])
    with middle:
        field("Time window (UTC)", row["Time window (UTC)"])
        gap = row["Gap (s)"]
        field("Time gap", "" if gap is None else f"{gap:g} seconds")
    with right:
        score = row["Score"]
        level = finding.get("confidence_level") or ui_evidence.NOT_RECORDED_TEXT
        field("Correlation score", "" if score is None else f"{score:g} ({level})")
        field("Artifacts", row["Artifacts"])

    st.markdown("**Why these events are linked**")
    for rule in ui_findings.as_list(finding.get("matched_rules")):
        st.text(f"{rule}: {ui_findings.RULES.get(rule, 'Rule is not documented.')}")
    code_field("Engine explanation", str(finding.get("explanation") or ""))
    if finding.get("investigation_note"):
        code_field("Investigation note", str(finding["investigation_note"]))
    references = ui_findings.as_list(finding.get("evidence_references"))
    code_field("Evidence references", "\n".join(references))

    events = ui_findings.linked_events(finding, index)
    if not events:
        return
    st.markdown("**Source events**")
    position = st.selectbox(
        "Source event to inspect", range(len(events)),
        format_func=lambda i: (
            f"{events[i].event_id} | {events[i].artifact_source} | {ui_data.format_utc(events[i])}"
        ),
    )
    render_event_detail(events[position])


def check_records(records, errors, names, label, skip_invalid):
    """Report invalid records; return (exportable records, excluded list) or None."""
    if not errors:
        return records, []
    st.error(f"{len(errors):,} of {len(records):,} {label} are not exportable.")
    listing = [
        {"Record": names[position] or "Not recorded", "Problem": " ".join(messages)}
        for position, messages in sorted(errors.items())
    ]
    st.dataframe(pd.DataFrame(listing[:MAX_LISTED_ERRORS]), width="stretch", hide_index=True)
    if len(listing) > MAX_LISTED_ERRORS:
        st.caption(f"Showing the first {MAX_LISTED_ERRORS} problems.")
    if not skip_invalid:
        st.markdown(
            "Correct the source data, or select **Leave out invalid records** and prepare again."
        )
        return None
    kept = [record for position, record in enumerate(records) if position not in errors]
    excluded = [{"record": item["Record"], "problem": item["Problem"]} for item in listing]
    return kept, excluded


def download(label, data, name, mime):
    st.download_button(label, data, file_name=name, mime=mime, on_click="ignore", key=name)


def csv_bytes(text):
    return text.encode("utf-8-sig")  # the marker lets Excel read Vietnamese text


def render_event_export(database, filters, findings, skip_invalid, stamp):
    st.subheader("Filtered timeline")
    signature = file_signature(database)
    malformed = []
    events = ui_data.load_matching(database, filters, malformed)
    source = ui_export.source_info(database)
    if file_signature(database) != signature:
        st.error("The database changed while the export was prepared. Prepare it again.")
        return
    if malformed:
        st.error(f"{len(malformed):,} stored events cannot be read.")
        for message in malformed[:MAX_LISTED_ERRORS]:
            st.text(message)
        if not skip_invalid:
            st.markdown("Select **Leave out invalid records** to export the readable events.")
            return
    if not events:
        st.info("No matching events to export.")
        return
    checked = check_records(
        events, ui_export.event_errors(events), [event.event_id for event in events],
        "events", skip_invalid,
    )
    if checked is None:
        return
    events, excluded = checked
    excluded = [{"record": None, "problem": message} for message in malformed] + excluded
    if not events:
        st.info("No valid events remain to export.")
        return
    st.markdown(f"Export contains **{len(events):,}** matching events.")
    case_id = filters["case_id"]
    case = ui_export.safe_name(None if case_id == ui_data.NOT_RECORDED else case_id)
    base = f"wintrace_{case}_timeline_{stamp}"
    download(
        "Download timeline (CSV)", csv_bytes(ui_export.events_to_csv(events)),
        f"{base}.csv", "text/csv",
    )
    download(
        "Download timeline (JSON)",
        ui_export.events_to_json(events, filters, [source], excluded),
        f"{base}.json", "application/json",
    )
    validation_report = None

    case_ids = {event.case_id for event in events}

    if len(case_ids) == 1 and None not in case_ids and "" not in case_ids:
        validation_report = CrossValidator(events).run_all_checks()
        validation_report["scope"] = "Exported timeline events only"

        # Remove SID values from the UI export.
        attribution = validation_report["checks"]["user_attribution"]

        for key in ("details", "unresolved", "contradictions"):
            for item in attribution.get(key, []):
                item.pop("deletion_sid", None)
                item.pop("prior_sid", None)    

    available_events = {
        (event.case_id, event.event_id)
        for event in events
    }

    scoped_findings = [
        finding
        for finding in findings
        if ui_findings.event_ids(finding)
        and all(
            (finding.get("case_id"), event_id)
            in available_events
            for event_id in ui_findings.event_ids(finding)
        )
    ]

    download(
        "Download HTML report",
        ReportGenerator.generate_html_report(
            events,
            scoped_findings + manual_findings_for_export(events),
            validation_report=validation_report,
        ),
        f"{base}.html",
        "text/html",
    )


def render_finding_export(database, findings_path, findings, index, description, skip_invalid, stamp):
    """Render the findings export and return the findings that passed validation."""
    st.subheader("Selected findings")
    if not findings:
        st.info("No findings to export. Check the Correlation findings tab and its filters.")
        return []
    checked = check_records(
        findings, ui_export.finding_errors(findings, index),
        [str(f.get("finding_id") or "") for f in findings], "findings", skip_invalid,
    )
    if checked is None:
        return []
    findings, excluded = checked
    if not findings:
        st.info("No valid findings remain to export.")
        return []
    st.markdown(f"Export contains **{len(findings):,}** findings.")
    sources = [ui_export.source_info(database), ui_export.source_info(findings_path)]
    cases = {f.get("case_id") for f in findings}
    case = ui_export.safe_name(cases.pop() if len(cases) == 1 else None)
    base = f"wintrace_{case}_findings_{stamp}"
    download(
        "Download findings (CSV)", csv_bytes(ui_export.findings_to_csv(findings)),
        f"{base}.csv", "text/csv",
    )
    download(
        "Download findings with source events (JSON)",
        ui_export.findings_to_json(findings, index, description, sources, excluded),
        f"{base}.json", "application/json",
    )
    return findings


def render_reporting(database, filters, findings_path, findings, index, description):
    if filters is None:
        st.warning("Correct the filter shown in the sidebar before exporting.")
        return
    st.markdown(
        "Exports follow the timeline filters in the sidebar and the filters "
        "in the Correlation findings tab. Every page is included."
    )
    st.caption(
        "User SIDs, host and volume identifiers and loaded-file lists are left out. "
        "Paths, descriptions and references are kept for traceability and may name people or devices."
    )
    skip_invalid = st.checkbox(
        "Leave out invalid records", key="skip_invalid",
        help="JSON exports list every record that was left out and why.",
    )
    if not st.button("Prepare export", type="primary"):
        return
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    try:
        valid_findings = render_finding_export(
            database, findings_path, findings, index, description, skip_invalid, stamp
        )
        render_event_export(database, filters, valid_findings, skip_invalid, stamp)
    except (sqlite3.Error, ValueError, OSError) as exc:
        st.error(f"Cannot prepare the export: {exc}")
def render_cross_validation(database, filters):
    st.subheader("Cross-validation H1-H4")

    if filters is None:
        st.info("Correct the sidebar filters first.")
        return

    case_id = filters.get("case_id")

    if not case_id or case_id == ui_data.NOT_RECORDED:
        st.info("Select one named case to run cross-validation.")
        return

    st.caption(
        f"Case: {case_id} | Scope: full case, "
        "independent of timeline filters."
    )

    try:
        events = ui_data.load_matching(
            database, {"case_id": case_id}
        )

        if not events:
            st.info("No events available for validation.")
            return

        report = CrossValidator(events).run_all_checks()

    except (sqlite3.Error, ValueError, OSError) as exc:
        st.error(f"Cannot run cross-validation: {exc}")
        return

    st.markdown(
        f"**Overall status:** {report['summary_status']}"
    )

    st.markdown(
        f"Events checked: **{report['total_events_checked']}**"
    )

    st.info(report["verification_note"])

    for name, check in report["checks"].items():
        st.markdown(
            f"**{check['hypothesis']}**: {check['status']}"
        )

        st.write("Matched pairs:", check["matches_count"])

        counts = {
            key: value
            for key, value in check.items()
            if key.endswith("_count") or key.endswith("_pairs")
        }

        st.json(counts)

        with st.expander(f"Evidence details - {name}"):
            st.json({
                "details": check.get("details", []),
                "temporal_anomalies": check.get(
                    "temporal_anomalies", []
                ),
                "unresolved": check.get("unresolved", []),
                "contradictions": check.get(
                    "contradictions", []
                ),
            })

def main():
    st.html(STYLE)
    st.title("WinTrace")
    st.caption("Windows super timeline analysis. All times are UTC.")
    database, findings_path = sidebar_sources()
    summary = load_summary(database)
    if summary is None:
        return
    if summary.total == 0:
        st.info("This timeline database contains no events. Import a case with the pipeline first.")
        return
    unknown = [
        value for value in summary.validation_statuses
        if value and value not in VALID_VALIDATION_STATUSES
    ]
    if unknown:
        st.warning(
            "This database holds validation statuses outside the schema, shown as unverified: "
            + ", ".join(f"`{value}`" for value in unknown)
        )
    filters = sidebar_filters(summary)
    if ui_data.has_plaso_export_events(database):

        st.subheader("Plaso Extended Timeline")

        st.caption(
            "Extended artifact-based timeline. All times are UTC."
        )

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total events",
            f"{summary.total:,}"
        )

        col2.metric(
            "Artifact groups",
            len(summary.artifacts)
        )

        col3.metric(
            "Dataset",
            "Plaso"
        )

        st.info(
            "Extended timeline browsing mode. "
            "Canonical findings, manual review, "
            "cross-validation and reporting are disabled "
            "for this dataset."
        )

        st.warning(
            "Registry extraction coverage may be incomplete. "
            "Unverified events do not establish user actions."
        )

        render_timeline(database, filters, summary)

        return
    findings, index, findings_note = load_findings(database, findings_path, filters, summary)

    timeline_tab, findings_tab, validation_tab, manual_tab, report_tab = st.tabs(
        [
            "Timeline",
            "Correlation findings",
            "Cross-validation",
            "Manual Review",
            "Reporting",
        ]
    )

    with timeline_tab:
        render_timeline(database, filters, summary)

    with findings_tab:
        selected, description = render_findings(
            findings, index, findings_note
        )

    with validation_tab:
        render_cross_validation(database, filters)

    with manual_tab:
        render_manual_review(database, filters)

    with report_tab:
        render_reporting(
            database, filters, findings_path,
            selected, index, description
        )


if __name__ == "__main__":
    main()