# Week 3 – Path Mapping, Validation Cases & Cross-tool Matrix – CASE01

**Người thực hiện:** Phúc · **Kế hoạch:** ngày 16 (ánh xạ path), 18 (3 tình huống), 19 (kiểm chứng chéo công cụ)
**Quy ước:** giờ UTC (EDT = UTC − 4h). Observed = artifact cho thấy trực tiếp · Inferred = suy luận · Unsupported = artifact **không** chứng minh · NIST-confirmed = khớp đáp án chính thức.

---

## 1. Ánh xạ path ShellBags → filesystem (ngày 16)

Fixture với giá trị mong đợi viết **nguyên văn**: `tests/fixtures/case01_path_mapping_cases.csv` (10 case). Test: `tests/test_case01_path_mapping.py`.

| Case | ShellBags namespace | fs_path mong đợi | Trạng thái | Ghi chú |
|---|---|---|---|---|
| P01 | `Desktop\Computers and Devices\10.11.11.128\10.11.11.128\secured_drive\…\design` | `\\10.11.11.128\secured_drive\…\design` | verified | SBECmd lặp tên host; **phải giữ 2 dấu `\` đầu** |
| P02 | `…\Computers and Devices\10.11.11.128` | *(rỗng)* | verified | Nút máy chủ, không phải đường dẫn tệp |
| P03 | `…\This PC\E:\RM#1\Secret Project Data` | `E:\RM#1\Secret Project Data` | verified (path) | Thiết bị RM#1 chỉ là **inferred** (tra volume map theo thời gian) |
| P04 | `…\E:\Secret Project Data\design\winter_whether_advisory.zip` | `E:\…\winter_whether_advisory.zip` | verified (path) | Thiết bị RM#2 = inferred |
| P05 | `…\winter_whether_advisory.zip\ppt` | `E:\…\winter_whether_advisory.zip\ppt` | verified | `ppt` nằm **bên trong file zip** (`archive_path`) |
| P06 | `…\This PC\D:\de` (CDBurn) | `D:\de` | **unresolved** | Khu chờ ghi đĩa; chưa chứng minh đã nằm trên đĩa; mốc sớm hơn NIST |
| P07 | `…\This PC\V:\Secret Project Data\final` | `V:\…\final` | **inferred** | Alias tới UNC chỉ trong `20:26:04Z–20:29:00Z` |
| P08 | `Desktop\S data\Secret Project Data` | `C:\Users\informant\Desktop\S data\…` | inferred | Namespace Desktop → profile user (suy luận) |
| P09 | `Desktop\Shared Documents Folder (Users Files)\Google Drive` | `C:\Users\informant\Google Drive` | inferred | – |
| P10 | `Desktop\ControlPanelHome` | *(rỗng)* | verified | Mục ảo |

**So với helper `extract_drive_path_from_bagmru` của schema v2 (nhánh Nam):** khớp ở 212 event có ổ đĩa/UNC. Khác ở 98 event Desktop (helper trả root rỗng, Phúc suy ra `C:\Users\informant\Desktop`) và 73 event ảo (helper trả chuỗi ảo như `ControlPanelHome` làm "relative path"). Khuyến nghị R02 dùng `extra_attributes.fs_path`, và bỏ qua `fs_path_basis = virtual`.

**Alias theo thời gian:** `scripts/volume_map.py` (`VolumeMap.resolve / canonical_path`). Ngoài khoảng đã chứng minh thì trả `None` (unresolved), **không đoán**. Đã test: `V:` ngoài khoảng → None; `E:` lúc 18:37Z ngày 23/03 và 13:38Z ngày 24/03 → RM#1; lúc 14:01Z ngày 24/03 → RM#2.

**UNC:** bản sửa của Nam (nhánh `nam-week2-v2`) giữ đúng `\\10.11.11.128\…`. Test `test_team_normalizer_keeps_unc_prefix` pass trên code tích hợp, và tự bỏ qua trên `dev` hiện tại (chưa có schema v2).

---

## 2. Ba tình huống điều tra với chuỗi bằng chứng (ngày 18)

Mỗi mắt xích: **dòng nguồn (tool output) → event (ID trong timeline) → vai trò trong candidate**. Mọi event đều truy ngược được bằng `scripts/trace_evidence.py` (692/692 khớp).

### Case A – Network share: duyệt thư mục và mở file Excel (tương ứng C1/C2 của Thi)

| Dòng nguồn | Event | UTC 23/03 | Vai trò |
|---|---|---|---|
| `Deduplicated.csv:L106` (UsrClass) | `CASE01-SB0133` First Interacted `…\pricing decision` | 20:24:15 | **Observed**: thư mục được mở lần đầu (`verified`, 3 công cụ) |
| `Deduplicated.csv:L13` (NTUSER) | `CASE01-SB0141` (twin của SB0133) | 20:24:33 | **Cùng một lần duyệt**, không tính là bằng chứng thứ hai |
| `registry_usb_network.csv:L26` | `CASE01-REG0018` Map Network Drive MRU `a=\\10.11.11.128\secured_drive` | 20:26:04 | Observed: ổ mạng được ánh xạ (key LastWrite) |
| `AutomaticDestinations_fromF.csv:L23` | `CASE01-JL0022` Excel 12 → `…\(secret_project)_pricing_decision.xlsx` | 20:26:53 | **Observed**: Excel mở file trên share |
| `LECmd_Output_fromF.csv:L2` | `CASE01-LNK0001` LNK Created | 20:26:53 | Observed: Shell tạo shortcut cho cùng file (cùng một lần mở) |
| `Deduplicated.csv:L106` | `CASE01-SB0158` Last Interacted (MRU 0) | 20:28:17 | Inferred (`mru0_inference`): lần cuối thư mục được tương tác |

- **Inferred:** user rà soát thư mục dự án mật trên share rồi mở file định giá bằng Excel.
- **Unsupported:** file bị sao chép hoặc exfiltrate; Excel thực thi (không có `EXCEL.EXE.pf`); SB0158 xảy ra trước khi mở file.
- **NIST-confirmed:** 16:23 EDT kết nối share, 16:26 EDT map V:, 16:28 EDT copy 2 file.
- **Counterexample (cùng thời điểm nhưng không phải hành động):**
  - `CASE01-SB0157` (UsrClass) và `SB0150` (NTUSER): KeyLastWrite **20:28:17** của thư mục `design`, đúng cùng giây với SB0158 nhưng MRU 5 (`parent_key_write`). Key cha được ghi vì `pricing decision`, **không phải** vì `design`.
  - `CASE01-SB0031`–`SB0033`: Created/Modified/Accessed của `design` = 2015-03-22 14:52:22 (`shell_item_metadata`), là trạng thái thư mục trên share, không phải lần truy cập.
  - `CASE01-LNK0004`: TargetModified 2015-01-29 của file Excel (metadata đích).

### Case B – Thiết bị lưu trữ ngoài: file zip trên USB RM#2

| Dòng nguồn | Event | UTC 24/03 | Vai trò |
|---|---|---|---|
| `registry_usb_network.csv:L7` | `CASE01-REG0005` USBSTOR serial `4C530012550531106501` first install | 13:58:33 | Observed: thiết bị lần đầu kết nối |
| `registry_usb_network.csv:L18` | `CASE01-REG0010` EMDMgmt "IAMAN $" VSN `9E6A5B82` | 13:58:34 | Observed: volume được gắn |
| `Deduplicated.csv:L59` | `CASE01-SB0254` Target Created của zip | 13:59:38 | Metadata: file có Created mới hơn Modified → **inferred** vừa được copy vào E: |
| `AutomaticDestinations_fromF.csv:L9` | `CASE01-JL0008` Explorer → `E:\…\winter_whether_advisory.zip`, VSN `9E6A5B82` | 14:01:23 | **Observed**: mở file zip trên volume `9E6A5B82` |
| `LECmd_Output_fromF.csv:L13` | `CASE01-LNK0050` LNK Created | 14:01:23 | Observed: lần mở đầu (nhưng **path hiện tại của LNK là `D:\de\…`**) |
| `Deduplicated.csv:L59` | `CASE01-SB0266` Last Interacted zip (MRU 0) | 14:01:29 | Observed (`verified`): duyệt bên trong zip |

- **Inferred:** volume `9E6A5B82` thuộc USB serial `…106501` (RM#2). Liên kết USBSTOR ↔ EMDMgmt dựa trên **trùng thời điểm 1 giây**, không phải ID tường minh.
- **Unsupported:** ai cắm USB (USBSTOR là cấp máy); nội dung zip là dữ liệu mật; file được sao chép **từ** máy này.
- **NIST-confirmed:** 09:58 EDT cắm RM#2, 09:59 EDT copy, 10:01:23/10:01:29 EDT Jump List/ShellBag (khớp đến giây).
- **Counterexample:**
  - `CASE01-SB0172` `E:\RM#1\Secret Project Data` lúc 13:38:31: **cùng ký tự E:**, khác thiết bị (RM#1).
  - `CASE01-LNK0050` có `target_path = D:\de\…` nhưng `LNK_FileCreated` (14:01:23) thuộc lần mở trên **E:**: không được ghép mốc này với `D:\de`.
  - `CASE01-SB0171` Accessed 04:00:00 = nửa đêm EDT, FAT chỉ lưu ngày (`fat_date_only`).

### Case C – Truy cập thư mục khu chờ ghi CD `D:\de`

| Dòng nguồn | Event | UTC 24/03 | Vai trò |
|---|---|---|---|
| `Deduplicated.csv:L63` | `CASE01-SB0282` Target Created `D:\de` | 19:47:48 | Metadata (thư mục được tạo trong khu chờ) |
| `Deduplicated.csv:L63` | `CASE01-SB0309` First Interacted `D:\de` (CDBurn) | 19:54:35 | **Observed** (`verified`) |
| `Deduplicated.csv:L69` | `CASE01-SB0312` Last Interacted `D:\de\winter_whether_advisory.zip` | 19:54:43 | Observed: mở zip từ `D:\de` |
| `Deduplicated.csv:L63` | `CASE01-SB0330` Last Interacted `D:\de` (MRU 0) | 20:44:13 | Inferred (`mru0_inference`) |
| `AutomaticDestinations_fromF.csv:L7` | `CASE01-JL0006` `D:\de\winter_whether_advisory.zip`, VSN `E297F1A5` | 20:44:13 | Observed: zip trên volume quang |
| `LECmd_Output_fromF.csv:L13` | `CASE01-LNK0051` LNK Modified → `D:\de\…`, ổ quang | 20:44:18 | Observed: lần mở cuối |

- **Inferred:** `de/pd/prog/prop/tr` là tên viết tắt của 5 thư mục dữ liệu mật.
- **Unresolved:** `D:\de` và file zip trong đó đã có lúc **19:54Z**, trong khi NIST ghi việc đổi tên lúc **20:40Z**. Có 3 volume quang khác VSN (`E297F1A5`, `A58AD72A`, `AE88F176`), nhưng không biết đĩa nào chứa gì lúc 19:54Z.
- **Unsupported:** thư mục đã được **ghi** lên đĩa (CDBurn chỉ là khu chờ); dữ liệu đã rời khỏi tổ chức.
- **Counterexample:** `SB0331` KeyLastWrite 20:44:13 trùng giây với `SB0330` (cùng dòng L63): một lần ghi registry, không phải 2 sự kiện.

---

## 3. Kiểm chứng chéo công cụ (ngày 19)

File: **`week3_validation_matrix.csv`** (631 phép so). Script: `scripts/independent_parsers.py` – parser tự viết theo đặc tả định dạng (struct + olefile), **không dùng EZ Tools**.

| Artifact | Trường so | Công cụ 1 | Đường đọc độc lập | Phép so | Agreement | Disagreement | Unresolved |
|---|---|---|---|---|---|---|---|
| ShellBags | LastWrite key BagMRU (First/Last/KeyLastWrite) | SBECmd 2026.10.2 | python-registry 1.3.1 | 220 | 220 | 0 | 0 |
| ShellBags (6 key của F001/F004/F005) | như trên, tới mili-giây | SBECmd | ShellBags Explorer 2026.10.1 (GUI, tuần 1) + python-registry | 6 | 6 | 0 | 0 |
| LNK | TargetCreated/Modified/Accessed, VolumeSerialNumber | LECmd 2026.10.3 | `[MS-SHLLINK]` header + LinkInfo | 60 | 60 | 0 | 0 |
| Prefetch | LastRun, RunCount, số FilesLoaded, có/không file thư xin nghỉ | PECmd 2026.10.3 | SCCA v23 (0x80, 0x98, Filename Strings) | 289 | 289 | 0 | 0 |
| Jump List | DestList LastModified, Path | JLECmd 2026.10.5 | OLE `DestList` v1 | 62 | 62 | 0 | 0 |

- 12 trường Path của Jump List: JLECmd in `chuỗi gốc ==> tên đã giải CLSID`, phần gốc khớp nguyên văn với parser độc lập → agreement (có ghi chú).
- 7 trường không tồn tại trong file (LNK `.xps` và thư mục `secret.lnk` không có target time; LNK mạng không có VolumeID): cả hai công cụ cùng rỗng → agreement (có ghi chú).
- **R04 kiểm chứng độc lập:** Prefetch `WINWORD.EXE` nạp `RESIGNATION_LETTER_(IAMAN_INFORMANT).DOCX` **và** file khóa `~$SIGNATION_…DOCX` (Word chỉ tạo file này khi mở tài liệu để chỉnh sửa); `XPSRCHVW.EXE` nạp `.XPS`; `IEXPLORE.EXE` cũng nạp `.DOCX` (negative control).

**Độ lệch thực tế giữa 2 hive** (`week3_cross_hive_deltas.csv`, không dùng con số cố định): 14 cặp, |Δ| 0–33 s, trung vị 4 s; NTUSER muộn hơn UsrClass ở 12/14 cặp. Riêng `design`: 2 s; `pricing decision`: 18 s; nút share: 33 s.

**Độ chính xác và timezone**

| Nguồn | Độ phân giải | Timezone lưu trữ | Ghi chú |
|---|---|---|---|
| Registry LastWrite (BagMRU, USBSTOR…) | 100 ns (SBECmd làm tròn xuống giây) | UTC | – |
| Shell item MAC | FAT 2 s; Accessed trên FAT chỉ có ngày | UTC (Windows quy đổi khi ghi) | 0/168 event có giây lẻ |
| LNK header target MAC | 100 ns | UTC | – |
| Prefetch LastRun | 100 ns | UTC | Win7: chỉ 1 mốc |
| DestList LastModified | 100 ns | UTC | – |
| Timestamp file system của .lnk/.pf | 100 ns (NTFS) | UTC | **Chỉ hợp lệ khi đọc trên ổ mount** |

**Tái lập:**
```
pip install olefile python-registry
python analysis/phuc-artifacts/scripts/independent_parsers.py <evidence_work> \
    --hives <evidence_work>/hives -o analysis/phuc-artifacts/week3_validation_matrix.csv
python analysis/phuc-artifacts/scripts/cross_hive_deltas.py -o analysis/phuc-artifacts/week3_cross_hive_deltas.csv
```
`<evidence_work>` = thư mục chứa `Recent/`, `Prefetch/`, `JumpLists/`, `hives/` (bản copy, hash trong `case01_source_inventory.csv`).
