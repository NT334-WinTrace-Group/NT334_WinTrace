"""
Tra cứu volume_map_case01.csv theo thời gian: ký tự ổ / alias -> volume/thiết bị tại một mốc UTC.

Dùng cho R02 (Object Association): chỉ coi `V:\\x` và `\\\\10.11.11.128\\secured_drive\\x` là cùng đối tượng
khi mốc thời gian nằm trong khoảng alias hợp lệ; chỉ coi hai sự kiện trên `E:` là cùng thiết bị khi
cùng một dòng volume map.

    from volume_map import VolumeMap
    vm = VolumeMap.load("analysis/phuc-artifacts/volume_map_case01.csv")
    vm.resolve("V:", "2015-03-23T20:27:33Z")      # -> dòng V: (\\\\10.11.11.128\\secured_drive)
    vm.canonical_path(r"V:\\Secret Project Data\\final", "2015-03-23T20:27:33Z")

Không có khoảng thời gian khớp -> trả None ("unresolved"), KHÔNG đoán.
"""
import csv
from datetime import datetime, timezone
from pathlib import Path

DEFAULT = Path(__file__).resolve().parents[1] / "volume_map_case01.csv"


def _ts(s):
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


class VolumeMap:
    def __init__(self, rows):
        self.rows = rows

    @classmethod
    def load(cls, path=DEFAULT):
        with open(path, newline="", encoding="utf-8-sig") as f:
            return cls(list(csv.DictReader(f)))

    def resolve(self, alias, when):
        """Trả danh sách dòng khớp alias tại thời điểm `when` (UTC). Rỗng nếu không xác định được."""
        t = _ts(when) if isinstance(when, str) else when
        alias = alias.rstrip("\\").upper()
        out = []
        for r in self.rows:
            if r["volume_alias"].rstrip("\\").upper() != alias:
                continue
            start, end = _ts(r["valid_from_utc"]), _ts(r["valid_to_utc"])
            if start is None and end is None:
                out.append(r)  # không giới hạn thời gian (ví dụ C:)
            elif t is not None and (start is None or start <= t) and (end is None or t <= end):
                out.append(r)
        return out

    def canonical_path(self, path, when):
        """`V:\\a\\b` -> `\\\\10.11.11.128\\secured_drive\\a\\b` nếu alias hợp lệ tại `when`; ngược lại None.
        Đường dẫn không phải alias mạng được trả nguyên trạng."""
        if len(path) >= 2 and path[1] == ":":
            matches = self.resolve(path[:2], when)
            net = [m for m in matches if m["canonical_volume"].startswith("\\\\")]
            if len(net) == 1:
                return net[0]["canonical_volume"] + path[2:]
            if path[:2].upper() == "V:":
                return None  # alias mạng ngoài khoảng đã chứng minh -> unresolved
        return path
