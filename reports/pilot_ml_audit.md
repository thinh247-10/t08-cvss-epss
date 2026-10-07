# N3 — Audit ML mẫu pilot cũ (Phase 1, bước 2)

Ngày thực hiện: **07/10/2026 (Asia/Saigon)**.
Nhánh thực tế: `test/p1-data-audit`.
Hướng dẫn: [Phase 1 N3, mục 2](../docs/phase-1-nguoi-3.md)
và [pilot-handoff, mục 4](../docs/pilot-handoff.md).

**Kết quả:** hoàn tất kiểm mẫu cũ. Đọc thành công **35 dòng × 33 cột**,
gồm **30 ứng viên có nhãn và 5 Rejected**. Checksum, schema/dtype, ID, version
và nhãn/vector đều khớp. Mẫu thiếu `AV:A`, `AV:P`, `A:L` so với 451 ứng viên pilot.
Đây là kiểm dữ liệu trước train; chưa có kết quả mô hình.

## 1. Version, nguồn và checksum

- Version mẫu: `pilot-v0.1-20260930T165232_235700Z-handoff-5139baa04b95`.
- Version pilot nguồn: `pilot-v0.1-20260930T165232_235700Z`.
- Schema version: `0.1`.
- Khoảng công bố nguồn: 01–07/01/2023, theo `published` UTC.
- NVD nguồn được tải: `2026-09-30T16:52:32.235700+00:00`
  (`source_retrieved_at` trong metadata).
- Mẫu được build: `2026-09-30T17:01:09.152920+00:00`;
  `retrieved_at` trong CSV là thời điểm build này.
- Cách chọn: seed 42; lấy các SHA-256 nhỏ nhất của `seed:CVE ID`
  riêng trong nhóm ứng viên và nhóm Rejected.

| File đã đọc | SHA-256 thực tế |
|---|---|
| `data/sample/cves_sample.csv` | `a5c3e501fe1e339feee5f820454ec918e456df5b34f0ea3e9d6e0dac45b5600d` |
| `data/sample/metadata.json` | `28ef5c99f40db0e56c798e4eb1c3af616467203209d58fc86a3416ee716dd530` |
| `reports/pilot_label_distribution.json` | `415988c2be87992b9066d60fec767b4ce0d9cf8a428464e15b1744d1af77ac3a` |
| `config/project.yaml` | `dc8ba19b3de6b7b7cad5bd4a04dee7377f8b879a59735507db8d566080d4e3d4` |

Checksum CSV và JSON thống kê khớp lần lượt `sample_sha256` và
`label_report_sha256` trong metadata. Hash metadata/config được ghi để truy vết
lần kiểm này; không có checksum độc lập cho hai file đó.
Cả 35 version trong CSV khớp metadata và JSON thống kê; danh sách ID và thứ tự
khớp `sample_ids`. Hash bốn file trước/sau lần audit giống nhau.

Số liệu **451** lấy từ [JSON thống kê đã kiểm checksum](pilot_label_distribution.json):
pilot nguồn có 543 dòng = 451 ứng viên + 92 Rejected.
Raw/Parquet và metadata nguồn tại
`data/processed/pilot_20260930T165232_235700Z/` không có trên máy nhận;
chưa đọc lại 451 dòng hoặc xác minh hash raw/Parquet nguồn.
Mẫu cố ý lấy 30/5 nên không dùng tỷ lệ này để ước lượng tỷ lệ quần thể.

Báo cáo này chỉ dùng mẫu cũ và thống kê pilot cũ. Bảng ghép 71.653 dòng
có version riêng, được nhận ở [biên bản bàn giao](n3_handoff_check.md);
không dùng số liệu bảng ghép để suy ra kết quả ở đây.

## 2. Môi trường và cách đọc

| Thành phần | Phiên bản thực tế |
|---|---|
| Hệ điều hành | Windows 11, build 26200, 64 bit |
| Python | 3.13.16 |
| pandas | 3.0.6 |
| pyarrow | 25.0.1 |
| PyYAML | 6.0.3 |

Đọc CSV bằng `SAMPLE_DTYPES`, `keep_default_na=False`, `na_values=[""]`,
`true_values=["True"]`, `false_values=["False"]` theo hướng dẫn.
Giá trị `False` được đọc thành boolean false; ô rỗng là missing.

- `cvss_base_score`, `epss`, `epss_percentile`: nullable `Float64`.
- `has_cvss31_label`, `in_scope`, `is_kev`: nullable `boolean`.
- Các cột còn lại ban đầu là `string`, đúng `SAMPLE_DTYPES`.
- `published`, `last_modified`, `retrieved_at` chuyển thành
  `datetime64[us, UTC]`, không có lỗi parse hoặc missing.
- `domain_tags`, `scope_evidence` chuyển từ JSON thành Python list;
  cả 35 dòng của mỗi cột đều là `[]`, không có JSON lỗi.

## 3. Kết quả kiểm thực tế

| Kiểm tra | Kết quả |
|---|---:|
| Dòng / cột | 35 / 33 |
| CVE ID duy nhất, đúng định dạng | 35 |
| ID thiếu / trùng | 0 / 0 |
| Description missing hoặc chỉ khoảng trắng | 0 |
| `vuln_status=Modified` / `Rejected` | 30 / 5 |
| `has_cvss31_label=True` / `False` / missing | 30 / 5 / 0 |
| Ứng viên không Rejected, description có nội dung, đủ nhãn/vector | 30 |
| Vector hiện có parse hợp lệ Base CVSS 3.1 | 30/30 |
| Nhãn lệch vector / sai version ở ứng viên | 0 / 0 |
| Base Score thiếu hoặc ngoài [0,10] ở ứng viên | 0 |
| Nguồn nhãn `nvd@nist.gov`, type `Primary` | 30 |
| KEV true / false / chưa biết | 0 / 0 / 35 |
| Scope `needs_review`, `in_scope=false` | 35 |
| `split` đã gán | 0 |

Ứng viên được xác định từ description, trạng thái và tám nhãn khớp vector,
rồi mới đối chiếu `has_cvss31_label`; không chỉ tin cờ có sẵn.
`parse_base_vector` kiểm đúng prefix `CVSS:3.1`, đủ tám Base metric duy nhất,
giá trị nằm trong tập lớp hợp lệ và từng nhãn CSV khớp vector.
Đếm lại từng lớp của 30 ứng viên khớp hoàn toàn JSON thống kê.
Không phát hiện lỗi đọc, dtype, ID hoặc nhãn cụ thể cần sửa ở mẫu này.

### Missing và các dòng bị loại

| Cột / nhóm cột | Missing trên 35 dòng | Giải thích |
|---|---:|---|
| `cvss_version`, `cvss_vector`, `cvss_base_score`, `cvss_source`, `cvss_type` | 5 ở mỗi cột | Cùng 5 Rejected |
| `AV/AC/PR/UI/S/C/I/A` | 5 ở mỗi cột | Cùng 5 Rejected |
| `epss`, `epss_percentile`, `epss_date` | 35 ở mỗi cột | Chưa ghép EPSS |
| `is_kev`, `kev_date_added`, `kev_known_ransomware` | 35 ở mỗi cột | Chưa ghép KEV |
| `split` | 35 | Chưa gán split |
| Các cột khác sau đọc/parse | 0 | List rỗng vẫn là giá trị có mặt |

Năm CVE dưới đây có `vuln_status=Rejected`, `has_cvss31_label=False`,
thiếu toàn bộ trường CVSS và tám metric nêu trên; giữ trong mẫu để kiểm missing,
loại khỏi ứng viên ML:

| CVE ID | Lý do loại |
|---|---|
| CVE-2022-0259 | Rejected, không có nhãn/vector |
| CVE-2022-43804 | Rejected, không có nhãn/vector |
| CVE-2022-43811 | Rejected, không có nhãn/vector |
| CVE-2022-43819 | Rejected, không có nhãn/vector |
| CVE-2022-43820 | Rejected, không có nhãn/vector |

Missing này đúng thiết kế bàn giao; không điền nhãn, EPSS=0 hoặc KEV=false.
Thiếu EPSS/KEV không tự loại 30 ứng viên khỏi kiểm nhãn NLP.
`in_scope=false` kèm `needs_review` là chưa nhận vào cohort, chưa chứng minh ngoài
Web/mobile; coverage Web/mobile hiện **pending/N/A**.

Kiểm thêm mô tả trùng bằng Unicode NFKC → gom khoảng trắng → strip → casefold:
có một nhóm gồm CVE-2022-43804, CVE-2022-43811, CVE-2022-43819, CVE-2022-43820
cùng mô tả Rejected. Trong 30 ứng viên có nhãn, không có nhóm trùng theo quy tắc này.
Kết quả này chỉ kiểm trùng chính xác sau chuẩn hóa trong mẫu;
chưa kiểm gần trùng, nhóm sản phẩm hoặc leakage xuyên split ở dữ liệu toàn khoảng.

## 4. Hỗ trợ từng lớp: 451 ứng viên nguồn và 30 ứng viên mẫu

Cột pilot lấy từ JSON; cột mẫu tính lại từ CSV rồi đối chiếu JSON.
Năm Rejected không nằm trong mẫu số nhãn. Mỗi metric cộng đúng 451 ở pilot
và 30 ở mẫu. Thứ tự lớp theo thiết kế Phase 0/data contract.

| Metric | Lớp | Pilot: 451 ứng viên | Mẫu: 30 ứng viên |
|---|---|---:|---:|
| AV | N | 324 | 21 |
| AV | A | 6 | 0 |
| AV | L | 120 | 9 |
| AV | P | 1 | 0 |
| AC | L | 441 | 29 |
| AC | H | 10 | 1 |
| PR | N | 277 | 16 |
| PR | L | 107 | 8 |
| PR | H | 67 | 6 |
| UI | N | 303 | 18 |
| UI | R | 148 | 12 |
| S | U | 360 | 21 |
| S | C | 91 | 9 |
| C | N | 71 | 8 |
| C | L | 111 | 8 |
| C | H | 269 | 14 |
| I | N | 121 | 9 |
| I | L | 94 | 8 |
| I | H | 236 | 13 |
| A | N | 162 | 10 |
| A | L | 6 | 0 |
| A | H | 283 | 20 |

Pilot có đủ mọi lớp hợp lệ của tám metric; không có lớp support bằng 0.
Các lớp ít mẫu cần chú ý: **AV:P=1 (0,22%)**, **AV:A=6 (1,33%)**,
**A:L=6 (1,33%)**, **AC:H=10 (2,22%)**.
Đây là số support quan sát được, chưa phải ngưỡng lớp hiếm đã chốt.

Mẫu thiếu **AV:A, AV:P và A:L** dù pilot có các lớp đó; AC:H chỉ có một mẫu.
Không target nào chỉ có một lớp trong 30 dòng, nhưng mẫu nhỏ chưa đủ để đánh giá
khả năng học lớp hiếm. Mẫu dùng kiểm giao diện, không đại diện coverage Web/mobile
hoặc phân phối của dataset toàn khoảng.

## 5. Vì sao chưa chia train/validation/test từ tuần này

`published` của mẫu nằm từ `2023-01-01T01:15:11.287Z` đến
`2023-01-07T19:15:09.260Z`, đúng cửa sổ nguồn.
Theo ranh giới tạm thời trong `config/project.yaml`:

| Split dự kiến | Khoảng UTC: start tính, end không tính | Ứng viên mẫu |
|---|---|---:|
| train | [2023-01-01, 2024-01-01) | 30 |
| validation | [2024-01-01, 2024-07-01) | 0 |
| test | [2024-07-01, 2025-01-01) | 0 |

Đây chỉ là đối chiếu trong bộ nhớ; `split` nguồn vẫn null.
Tuần pilot không có dữ liệu năm 2024 nên chưa đủ validation/test theo thiết kế.
Không chia ngẫu nhiên 35 dòng để công bố accuracy/F1 hoặc so mô hình.

Có **33/35 ID** mang năm khác năm `published`, ví dụ
`CVE-2010-10002` được công bố ngày 01/01/2023; phải dùng `published` để chia thời gian.
Cả 35 dòng có `last_modified > published`; khoảng last_modified là
`2023-11-07T03:41:10.547Z` đến `2026-06-17T05:35:46.040Z`.
Snapshot chứa chỉnh sửa sau công bố, nên chia thời gian không phục hồi dữ liệu
lịch sử đúng thời điểm công bố.

Khi kiểm bảng toàn khoảng, đếm số ứng viên và support mọi lớp theo split dự kiến;
kiểm ID/mô tả trùng, gần trùng/nhóm sản phẩm, missing và nguồn nhãn.
Nếu cần thay khoảng năm, đề xuất N1 ghi quyết định/version trước khi đánh giá test.
Chưa khóa split trong bước kiểm mẫu này.

## 6. Góp ý và phần chưa xác minh gửi N1

1. Giữ nullable boolean, timestamp UTC, list JSON và provenance như mẫu hiện tại.
   Giữ Rejected/missing trong master và có lý do loại khỏi ML; không sửa nhãn nguồn.
2. Giữ đầy đủ mapping lớp, kể cả support bằng 0. Với dữ liệu train sau này:
   lớp vắng phải báo không có dữ liệu học; target chỉ một lớp dùng fallback
   constant/Dummy theo thiết kế. Không gộp/xóa lớp khó hoặc dời mẫu test để làm đẹp coverage.
3. Audit support theo thời gian trên bảng toàn khoảng trước khi khóa split.
   Mẫu bổ sung để kiểm các lớp còn thiếu nên có version/đường dẫn riêng và giữ gói cũ;
   không ghi đè mẫu hoặc annotation N2.
4. Base Score ở mẫu mới được kiểm có mặt và trong [0,10];
   **chưa tính lại/đối chiếu scorer**. Module scorer dùng chung hiện vẫn là TODO;
   cần N2/N1 hoàn thiện trước khi khóa dataset. Không viết công thức điểm riêng cho audit.
5. `config/model.yaml` và `docs/model-plan.md` chưa có trong working tree.
   Theo Phase 1 N3 mục 1, đề nghị N1 tích hợp PR thiết kế Phase 0.
   Việc này không chặn kiểm mẫu; không tự tạo lại thiết kế ở bước 2.
6. Thống kê 451 đã kiểm checksum và tổng số, nhưng raw/Parquet cũ chưa được đọc lại.
   Scope, gần trùng/nhóm sản phẩm và audit toàn khoảng còn ở bước tiếp theo.

Các góp ý trên là nội dung bàn giao trong báo cáo; chưa có xác nhận N1 đã nhận/xử lý.

## 7. Lệnh thực sự chạy và kiểm chứng

Chạy tại gốc repo bằng môi trường `.venv`, offline. Khối dưới đã chạy thành công
(exit code 0); xuất JSON kết quả, tất cả **19 kiểm tra** trong `checks` đều true,
`label_issues=[]`. Script chỉ đọc file và biến đổi DataFrame trong bộ nhớ;
hash trước/sau xác nhận bốn file đầu vào giữ nguyên.

```powershell
@'
import hashlib, json, platform, sys
from pathlib import Path
import pandas as pd
import pyarrow, yaml
from src.collect.prepare_handoff import SAMPLE_COLUMNS, SAMPLE_DTYPES
from src.collect.nvd_collector import ALLOWED_LABELS, parse_base_vector

paths = [Path(p) for p in ("data/sample/cves_sample.csv",
    "data/sample/metadata.json", "reports/pilot_label_distribution.json",
    "config/project.yaml")]
before = {p.as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
meta = json.loads(paths[1].read_text(encoding="utf-8"))
labels = json.loads(paths[2].read_text(encoding="utf-8"))
config = yaml.safe_load(paths[3].read_text(encoding="utf-8"))
df = pd.read_csv(paths[0], dtype=SAMPLE_DTYPES, keep_default_na=False,
    na_values=[""], true_values=["True"], false_values=["False"])
csv_dtypes = {name: str(dtype) for name, dtype in df.dtypes.items()}
for name in ("domain_tags", "scope_evidence"):
    df[name] = df[name].map(json.loads)
for name in ("published", "last_modified", "retrieved_at"):
    df[name] = pd.to_datetime(df[name], utc=True, errors="raise")
issues, valid = [], []
for _, row in df.iterrows():
    parsed = parse_base_vector(row["cvss_vector"])
    valid.append(parsed is not None)
    if pd.notna(row["cvss_vector"]) and parsed is None:
        issues.append({"cve_id": row.cve_id, "column": "cvss_vector",
                       "error": "invalid Base CVSS 3.1 vector"})
    if parsed is not None:
        for name, value in parsed.items():
            if pd.isna(row[name]) or row[name] != value:
                issues.append({"cve_id": row.cve_id, "column": name,
                               "error": "label does not match vector"})
        if pd.isna(row.cvss_version) or row.cvss_version != "3.1":
            issues.append({"cve_id": row.cve_id, "column": "cvss_version",
                           "error": "wrong version"})
        if pd.isna(row.cvss_base_score) or not 0 <= row.cvss_base_score <= 10:
            issues.append({"cve_id": row.cve_id, "column": "cvss_base_score",
                           "error": "missing or out of range"})
valid = pd.Series(valid, index=df.index, dtype="boolean")
blank = df.description.str.strip().fillna("").eq("")
rejected = df.vuln_status.eq("Rejected").fillna(False)
candidate = ~rejected & ~blank & valid & df[list(ALLOWED_LABELS)].notna().all(axis=1)
counts = {m: {v: int(df.loc[candidate, m].eq(v).sum())
          for v in sorted(values)} for m, values in ALLOWED_LABELS.items()}
normal = df.description.str.normalize("NFKC").str.replace(
    r"\s+", " ", regex=True).str.strip().str.casefold()
start = pd.Timestamp(meta["source_params"]["pubStartDate"], tz="UTC")
end = pd.Timestamp(meta["source_params"]["pubEndDate"], tz="UTC")
checks = {
    "sample_checksum": before[paths[0].as_posix()] == meta["sample_sha256"],
    "distribution_checksum": before[paths[2].as_posix()] == meta["label_report_sha256"],
    "schema_columns_order": list(df.columns) == SAMPLE_COLUMNS,
    "csv_dtypes": all(csv_dtypes[n] == d for n, d in SAMPLE_DTYPES.items()),
    "sample_version": df.dataset_version.notna().all() and
        set(df.dataset_version) == {meta["dataset_version"]} ==
        {labels["sample_dataset_version"]},
    "source_version": meta["source_dataset_version"] == labels["source_dataset_version"],
    "sample_ids_order": df.cve_id.tolist() == meta["sample_ids"],
    "ids_present_unique_valid": df.cve_id.notna().all() and df.cve_id.is_unique and
        df.cve_id.str.fullmatch(r"CVE-\d{4}-\d{4,}").all(),
    "sample_size": len(df) == meta["sample_size"] == 35,
    "candidate_size": int(candidate.sum()) == meta["labelled_candidates"] ==
        labels["sample_candidate_size"] == 30,
    "rejected_size": int(rejected.sum()) == meta["rejected_examples"] ==
        labels["sample_rejected_size"] == 5,
    "label_flag": df.has_cvss31_label.notna().all() and
        df.has_cvss31_label.equals(valid),
    "sample_distribution": counts == labels["sample_candidate_label_counts"],
    "pool_distribution_totals": labels["candidate_pool_size"] == 451 and
        all(set(values) == ALLOWED_LABELS[m] and sum(values.values()) == 451
            for m, values in labels["candidate_label_counts"].items()),
    "published_within_source_window": df.published.between(start, end).all(),
    "timestamps_present_ordered": df[["published", "last_modified", "retrieved_at"]].
        notna().all().all() and df.last_modified.ge(df.published).all(),
    "json_lists": all(isinstance(v, list) and v == [] for name in
        ("domain_tags", "scope_evidence") for v in df[name]),
    "scope_pending": df.scope_status.eq("needs_review").all() and
        df.in_scope.notna().all() and df.in_scope.eq(False).all(),
    "source_files_unchanged": all(hashlib.sha256(p.read_bytes()).hexdigest() ==
        before[p.as_posix()] for p in paths),
}
split_counts = {name: int((candidate &
    df.published.ge(pd.Timestamp(bounds["start"], tz="UTC")) &
    df.published.lt(pd.Timestamp(bounds["end_exclusive"], tz="UTC"))).sum())
    for name, bounds in config["split"].items() if isinstance(bounds, dict)}
result = {
    "versions": {"python": sys.version.split()[0], "pandas": pd.__version__,
        "pyarrow": pyarrow.__version__, "PyYAML": yaml.__version__,
        "platform": platform.platform()},
    "dataset_version": meta["dataset_version"], "sha256": before,
    "checks": {name: bool(value) for name, value in checks.items()},
    "rows_columns": list(df.shape), "csv_dtypes": csv_dtypes,
    "timestamp_dtypes": {n: str(df[n].dtype) for n in
        ("published", "last_modified", "retrieved_at")},
    "status_counts": df.vuln_status.value_counts(dropna=False).to_dict(),
    "label_flag_counts": {str(k): int(v) for k, v in
        df.has_cvss31_label.value_counts(dropna=False).items()},
    "missing_counts": {n: int(df[n].isna().sum()) for n in df.columns},
    "blank_descriptions": int(blank.sum()), "candidate_count": int(candidate.sum()),
    "excluded": [{"cve_id": r.cve_id, "vuln_status": r.vuln_status,
        "missing_fields": [n for n in ("cvss_version", "cvss_vector",
        "cvss_base_score", "cvss_source", "cvss_type", *ALLOWED_LABELS)
        if pd.isna(r[n])]} for _, r in df.loc[~candidate].iterrows()],
    "label_counts": counts, "label_issues": issues,
    "source_type_counts": df.loc[candidate, ["cvss_source", "cvss_type"]].
        value_counts().reset_index(name="count").to_dict("records"),
    "published_range": [str(df.published.min()), str(df.published.max())],
    "last_modified_range": [str(df.last_modified.min()), str(df.last_modified.max())],
    "modified_after_published": int(df.last_modified.gt(df.published).sum()),
    "cve_year_differs_published": df.loc[df.cve_id.str.slice(4, 8).astype(int).
        ne(df.published.dt.year), "cve_id"].tolist(),
    "duplicate_description_groups": [group.cve_id.tolist() for _, group in
        df.assign(normalized=normal).groupby("normalized") if len(group) > 1],
    "provisional_candidates_by_published": split_counts,
    "phase0_files_present": {p: Path(p).is_file() for p in
        ("config/model.yaml", "docs/model-plan.md")},
    "source_snapshot_present": Path(meta["source_metadata"]).is_file(),
}
print(json.dumps(result, indent=2, ensure_ascii=True))
'@ | .\.venv\Scripts\python.exe -
```

Kiểm các test hiện có liên quan đến pilot/CSV bàn giao:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_collect_pilot tests.test_prepare_handoff -v
```

Kết quả thực tế: **8 tests, OK**, exit code 0. Các test kiểm missing/boolean/text
qua CSV, nhãn lệch vector, mẫu ổn định, lớp support 0 và scope chưa được tự xác nhận.
Không tạo trainer hoặc kết quả F1/accuracy trong bước này.

