"""Optional read-only enrichment panel for canonical manual review."""
import json
import sqlite3
import streamlit as st
from src.evidence_enrichment import find_enrichment


def render_enrichment(case_id, linked_events, candidate_id):
    st.markdown('**Plaso Evidence Enrichment**')
    path = st.text_input('Plaso Extended database (SQLite)', key='enrichment_database')
    if not path.strip():
        st.caption('Optional: enter the Plaso database from the same acquisition.')
        return
    if not st.checkbox('I confirm both databases are from the same acquisition', key='enrichment_same_acquisition'):
        return
    try:
        rows = find_enrichment(path.strip(), case_id, linked_events)
    except (OSError, sqlite3.Error, ValueError) as exc:
        st.error(f'Cannot load enrichment: {exc}')
        return
    st.caption('Exact document path + Office MRU item FILETIME + application context; ±300 seconds. No score or validation promotion. Case ID alone does not authenticate acquisition identity.')
    st.metric('Complementary records (not independent actions)',len(rows))
    if not rows:
        st.info('No supported matches in the selected scope.')
        return
    for row in rows:
        with st.expander(f"{row['kind']} | {row['event_id']}"):
            st.json(row)
    st.caption('Separate enrichment JSON contains local evidence paths. Canonical report and findings are unchanged.')
    st.download_button('Download enrichment JSON',json.dumps({'candidate_id':candidate_id,'case_id':case_id,'validation_status':'unverified','records':rows},ensure_ascii=False,indent=2),file_name=f'{candidate_id}_enrichment.json',mime='application/json')
