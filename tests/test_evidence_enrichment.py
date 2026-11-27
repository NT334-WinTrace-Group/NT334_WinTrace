import sqlite3
from datetime import datetime, timezone
from types import SimpleNamespace
from src.evidence_enrichment import find_enrichment


def test_office_mru_enrichment(tmp_path):
    db=tmp_path/'test.db'
    con=sqlite3.connect(db)
    con.execute('CREATE TABLE events(case_id,event_id,timestamp,timestamp_desc,artifact_source,data_type,parser,source_file,message,evidence_reference)')
    stamp='2015-03-23T20:26:50+00:00'
    n=(datetime.fromisoformat(stamp)-datetime(1601,1,1,tzinfo=timezone.utc))
    ft=(n.days*86400+n.seconds)*10**7
    key=r'[HKEY_CURRENT_USER\Software\Microsoft\Office\15.0\Excel\File MRU] '
    path=r'V:\test\file.xlsx'
    value=f'Item 1: [REG_SZ] [F00000000][T{ft:016X}][O00000000]*{path}'
    hive=r'OS:\evidence\hives\NTUSER.DAT'
    ua=r'[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count] UserAssist entry: 1 Value name: \Office\EXCEL.EXE Count: 1 Application focus count: 0 Application focus duration: 0'
    mru=('C','C-PLASO-1',stamp,'Content Modification Time','Registry','windows:registry:key_value','winreg/winreg_default',hive,key+value,'record=1')
    user=('C','C-PLASO-2',stamp,'Last Time Executed','UserAssist','windows:registry:userassist','winreg/userassist',hive,ua,'record=2')
    for row in [mru,user,('C','C-PLASO-3',*mru[2:]),('D','D-PLASO-1',*mru[2:]),('C','C-PLASO-4',*user[2:7],r'OS:\other\NTUSER.DAT',*user[8:])]:
        con.execute('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',row)
    con.commit();con.close()
    anchor=SimpleNamespace(case_id='C',event_id='C-JL1',artifact_source='JumpLists',timestamp_type='JumpList_TargetModified',target_path=path,timestamp='2015-03-23T20:26:53+00:00',evidence_reference='source')
    before=db.read_bytes()
    rows=find_enrichment(db,'C',[anchor])
    assert {r['event_id'] for r in rows}=={'C-PLASO-1','C-PLASO-2'}
    assert all(r['validation_status']=='unverified' for r in rows)
    assert db.read_bytes()==before
    anchor.target_path=r'E:\test\file.xlsx'
    assert not find_enrichment(db,'C',[anchor])
    anchor.target_path=path
    anchor.timestamp='2015-03-24T20:26:53+00:00'
    assert not find_enrichment(db,'C',[anchor])
