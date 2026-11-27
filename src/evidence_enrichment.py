"""Read-only, targeted Office evidence enrichment for reviewed Jump List events.

Matches Plaso exports, not raw hives. Findings and scores are never modified.
The caller must select databases derived from the same acquisition.
"""
import ntpath
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

WINDOW = 300
OFFICE = {'.xlsx': ('excel', 'excel.exe'), '.xls': ('excel', 'excel.exe'),
          '.pptx': ('powerpoint', 'powerpnt.exe'), '.ppt': ('powerpoint', 'powerpnt.exe'),
          '.docx': ('word', 'winword.exe'), '.doc': ('word', 'winword.exe')}
KEY = re.compile(r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\\d+(?:\.\d+)?\\(Excel|PowerPoint|Word)\\File MRU\]\s*', re.I)
ITEM = re.compile(r'(?:^|  )(Item \d+): \[REG_SZ\] (.*?)(?=  Item \d+: \[REG_SZ\]|$)')
VALUE = re.compile(r'^\[F[0-9a-f]{8}\]\[T([0-9a-f]{16})\]\[O[0-9a-f]{8}\]\*(.+)$', re.I)
UA = re.compile(r'^\[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA\}\\Count\] UserAssist entry: \d+ Value name: (.+?) Count: (\d+) Application focus count: (\d+) Application focus duration: (\d+)\s*$', re.I)


def utc(value):
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError('Timezone required')
    return dt.astimezone(timezone.utc)


def full_path(value):
    if not isinstance(value, str):
        return ''
    if not re.match(r'^(?:[A-Za-z]:\\|\\\\[^\\]+\\[^\\]+\\)', value):
        return ''
    # No drive aliases or basename-only matches; reject traversal.
    if any(p in ('.', '..') for p in value.split('\\')):
        return ''
    return ntpath.normcase(value)


def source_id(row):
    return row['source_file'].replace('/', '\\').casefold()


def within(a, b):
    return abs((a - b).total_seconds()) <= WINDOW


def _row_result(row, anchor, kind, app, stamp, **details):
    return dict(kind=kind, application=app, anchor_event_id=anchor.event_id,
                event_id=row['event_id'], timestamp_utc=stamp.isoformat(),
                source_event_timestamp=row['timestamp'], source_file=row['source_file'],
                evidence_reference=row['evidence_reference'],
                delta_seconds=round((stamp-utc(anchor.timestamp)).total_seconds(), 6),
                validation_status='unverified', **details)


def find_enrichment(database, case_id, linked_events):
    """Return context records, not independent action counts or new scored findings."""
    if not case_id:
        raise ValueError('Named case required')
    anchors = [e for e in linked_events if e.case_id == case_id
               and e.artifact_source == 'JumpLists'
               and e.timestamp_type == 'JumpList_TargetModified'
               and full_path(e.target_path) and e.evidence_reference
               and ntpath.splitext(e.target_path)[1].lower() in OFFICE]
    if not anchors:
        return []
    path = Path(database).resolve(strict=True)
    db = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    results = {}
    try:
        if not db.execute('SELECT 1 FROM events WHERE case_id=? AND parser LIKE ? LIMIT 1', (case_id,'winreg/%')).fetchone():
            raise ValueError('No Plaso Registry records for selected case')
        # Query only supported artifact classes; item time can precede key LastWrite.
        rows = db.execute('''SELECT event_id,timestamp,timestamp_desc,source_file,message,
            evidence_reference, data_type,parser FROM events WHERE case_id=? AND
            ((artifact_source='Registry' AND data_type='windows:registry:key_value'
              AND parser='winreg/winreg_default' AND message LIKE '%\\File MRU]%')
             OR (artifact_source='UserAssist' AND data_type='windows:registry:userassist'
              AND parser='winreg/userassist' AND timestamp_desc='Last Time Executed'))''',(case_id,)).fetchall()
        mru, ua = [], []
        for row in rows:
            if not row['event_id'].startswith(case_id+'-PLASO-') or not row['evidence_reference'] or not source_id(row).endswith('\\ntuser.dat'):
                continue
            if row['data_type'].endswith(':userassist'):
                match = UA.fullmatch(row['message'])
                if match:
                    ua.append((row, match, utc(row['timestamp'])))
                continue
            key = KEY.match(row['message'])
            if not key or row['timestamp_desc'] != 'Content Modification Time':
                continue
            for item in ITEM.finditer(row['message'][key.end():]):
                val = VALUE.fullmatch(item[2])
                if not val or not full_path(val[2]):
                    continue
                try:
                    stamp = datetime(1601,1,1,tzinfo=timezone.utc)+timedelta(microseconds=int(val[1],16)//10)
                except OverflowError:
                    continue
                mru.append((row,key[1].lower(),item[1],val[2],stamp,val[1]))
        for anchor in anchors:
            app, exe = OFFICE[ntpath.splitext(anchor.target_path)[1].lower()]
            at = utc(anchor.timestamp)
            for row, office, item, target, stamp, raw_time in mru:
                if office != app or full_path(target) != full_path(anchor.target_path) or not within(stamp,at):
                    continue
                k = ('Office File MRU',source_id(row),app,full_path(target),stamp)
                result = _row_result(row,anchor,'Office File MRU',app,stamp,item=item,
                    document_path=target,embedded_filetime_hex=raw_time,
                    timestamp_semantics='MRU item embedded FILETIME; not proven file-open time')
                results.setdefault(k,result)
                for u, match, ut in ua:
                    if source_id(u)!=source_id(row) or ntpath.basename(match[1]).lower()!=exe or not within(ut,at) or not within(ut,stamp):
                        continue
                    k2=('UserAssist',source_id(u),exe,ut)
                    results.setdefault(k2,_row_result(u,anchor,'UserAssist',exe,ut,
                        value_name=match[1],execution_count=int(match[2]),focus_count=int(match[3]),
                        focus_duration_raw=int(match[4]),timestamp_semantics='Last Time Executed; application context only'))
    finally:
        db.close()
    return sorted(results.values(),key=lambda r:(r['timestamp_utc'],r['event_id']))
