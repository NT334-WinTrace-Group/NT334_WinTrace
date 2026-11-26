"""
WinTrace - Report Generation Module
Author: Quyen (Validation & Visualization Engineer)
"""

from datetime import datetime
from html import escape
import csv
import io
import json
from typing import List, Dict, Any, Optional
from src.schema import ForensicEvent

class ReportGenerator:
    @staticmethod
    def generate_csv_report(events: List[ForensicEvent]) -> str:
        """Serialize timeline events with the schema-v2 provenance fields."""
        fieldnames = [
            "event_id", "case_id", "timestamp", "timestamp_type",
            "artifact_source", "parser", "source_file", "target_path", "message",
            "evidence_reference", "validation_status", "user_sid", "username",
            "extra_attributes",
        ]
        output = io.StringIO(newline="")
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for event in events:
            row = {name: getattr(event, name, "") or "" for name in fieldnames}
            row["extra_attributes"] = json.dumps(event.extra_attributes, ensure_ascii=False, sort_keys=True)
            writer.writerow(row)
        return output.getvalue()

    @staticmethod
    def generate_json_report(
        events: List[ForensicEvent],
        case_id: Optional[str] = None,
        review_candidates: Optional[List[Dict[str, Any]]] = None,
        rule_engine_candidates: Optional[List[Dict[str, Any]]] = None,
        validation_report: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Serialize events and candidate/validation context without promoting candidates to facts."""
        payload = {
            "case_id": case_id,
            "candidate_findings_notice": "Candidates require analyst review; they are not ground-truth verification.",
            "events": [event.to_dict() for event in events],
            "review_candidates": review_candidates or [],
            "rule_engine_candidates": rule_engine_candidates or [],
            "cross_validation": validation_report,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    @staticmethod
    def generate_html_report(events: List[ForensicEvent], findings: List[Dict[str, Any]],
                             case_id: Optional[str] = None,
                             validation_report: Optional[Dict[str, Any]] = None) -> str:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        case_ids = sorted({event.case_id for event in events if event.case_id})
        if case_ids and any(not event.case_id for event in events):
            case_ids.append("Unspecified")
        case_label = escape(", ".join(case_ids) or case_id or "Unspecified")
        
        high_conf_findings = [f for f in findings if f.get("confidence_level") == "HIGH"]
        verified_events = [e for e in events if e.validation_status == "verified"]
        validation_html = "<p>No H1–H4 validation report was supplied.</p>"
        if validation_report:
            validation_html = (
                f"<p><strong>Summary:</strong> {escape(str(validation_report.get('summary_status', 'Unknown')))}. "
                "This status is not ground-truth verification.</p>"
            )
            for name, check in validation_report.get("checks", {}).items():
                details = escape(json.dumps({
                    "details": check.get("details", []),
                    "contradictions": check.get("contradictions", []),
                    "temporal_anomalies": check.get("temporal_anomalies", []),
                    "unresolved": check.get("unresolved", []),
                }, ensure_ascii=False, indent=2))
                validation_html += (
                    f"<h3>{escape(str(check.get('hypothesis', name)))}</h3>"
                    f"<p>Status: <strong>{escape(str(check.get('status', 'Unknown')))}</strong>; "
                    f"supported/matched: {escape(str(check.get('supported_count', check.get('matches_count', 0))))}; "
                    f"reverse order: {escape(str(check.get('reversed_order_count', 0)))}; "
                    f"direct references: {escape(str(check.get('direct_reference_pairs', 0)))}; "
                    f"outside time window: {escape(str(check.get('outside_window_pairs', 0)))}</p>"
                    f"<details><summary>Event IDs and evidence references</summary><pre>{details}</pre></details>"
                )

        html_content = f"""
        <html>
        <head>
            <title>WinTrace Investigation Report - {case_label}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high-conf {{ color: #d35400; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>WinTrace Investigation Report</h1>
            <p><strong>Case ID:</strong> {case_label}</p>
            <p><strong>Generated on (local time):</strong> {now_str}</p>
            <p><strong>Interpretation:</strong> Findings below are candidates for review, not verified conclusions.</p>
            
            <h2>1. Executive Summary</h2>
            <ul>
                <li>Total Events Filtered/Analyzed: {len(events)} ({len(verified_events)} marked verified in event metadata)</li>
                <li>Candidate Findings Requiring Review: {len(findings)}</li>
                <li><span class="high-conf">High Confidence Candidates: {len(high_conf_findings)}</span></li>
            </ul>

            <h2>2. Cross-Validation H1–H4</h2>
            {validation_html}

            <h2>3. Key Correlation Findings</h2>
            <table>
                <tr>
                    <th>Candidate Type</th>
                    <th>Finding ID</th>
                    <th>Case ID</th>
                    <th>Event IDs</th>
                    <th>Evidence References</th>
                    <th>Time Delta (min)</th>
                    <th>Rules</th>
                    <th>Confidence</th>
                    <th>Validation Status</th>
                    <th>Explanation</th>
                </tr>
        """
        
        for f in findings:
            rules = ", ".join(f.get("matched_rules", []))
            event_ids = f.get("event_ids") or [
                value for value in (f.get("event_a_id"), f.get("event_b_id")) if value
            ]
            evidence_references = f.get("evidence_references") or f.get("source_references") or []
            if isinstance(evidence_references, str):
                evidence_references = [evidence_references]
            if isinstance(event_ids, str):
                event_ids = [event_ids]
            html_content += f"""
                <tr>
                    <td>{escape(str(f.get('candidate_type', 'Automated candidate')))}</td>
                    <td>{escape(str(f.get('finding_id')))}</td>
                    <td>{escape(str(f.get('case_id') or case_id or 'Unspecified'))}</td>
                    <td>{escape(', '.join(str(value) for value in event_ids))}</td>
                    <td>{escape('; '.join(str(value) for value in evidence_references))}</td>
                    <td>{escape(str(f.get('time_delta_minutes')))}</td>
                    <td>{escape(rules)}</td>
                    <td>{escape(str(f.get('confidence_level')))} ({escape(str(f.get('confidence_score')))})</td>
                    <td>{escape(str(f.get('validation_status') or f.get('status') or 'unverified'))}</td>
                    <td>{escape(str(f.get('explanation')))}</td>
                </tr>
            """
            
        html_content += """
            </table>
            <h2>4. Filtered Timeline Events</h2>
            <table>
                <tr>
                    <th>Event ID</th>
                    <th>Case ID</th>
                    <th>Timestamp (UTC)</th>
                    <th>Artifact</th>
                    <th>Message / Target Path</th>
                    <th>Source File</th>
                    <th>Evidence Ref</th>
                    <th>Validation Status</th>
                </tr>
        """
        
        for e in events:
            ref = e.evidence_reference if e.evidence_reference else "N/A"
            html_content += f"""
                <tr>
                    <td>{escape(e.event_id)}</td>
                    <td>{escape(e.case_id or "Unspecified")}</td>
                    <td>{escape(e.timestamp)}<br/><small>{escape(e.timestamp_type or "Unspecified")}</small></td>
                    <td>{escape(e.artifact_source)}</td>
                    <td>{escape(e.message)}<br/><small>{escape(e.target_path)}</small></td>
                    <td>{escape(e.source_file)}</td>
                    <td>{escape(ref)}</td>
                    <td>{escape(e.validation_status or "Unspecified")}</td>
                </tr>
            """
            
        html_content += """
            </table>
        </body>
        </html>
        """
        return html_content
