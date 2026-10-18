# Phase 3 N2 — Bước B: thống kê ranking quan sát

Ngày chạy: 2026-10-18. Branch `feat/p3-ranking-context`.
Contract: `docs/phase-3-artifact-contract.md`, schema `p3-ranking-metrics-v1`.
Config chốt trước khi chạy: `config/phase3.yaml`, K=10/20/50,
ngưỡng minh họa CVSS>=7.0 và EPSS>=0.10, không lọc cohort theo ngưỡng.

## Lệnh đã chạy

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt -r requirements-model.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m src.analysis.ranking_metrics --help
.\.venv\Scripts\python.exe -m unittest tests.test_ranking_metrics tests.test_rankings tests.test_cvss tests.test_phase1_release -q
.\.venv\Scripts\python.exe -m src.analysis.ranking_metrics --rankings data/processed/p3_n2/rankings.csv --config config/phase3.yaml --output-dir data/processed/p3_n2
```

Môi trường: Python 3.13.12, pandas 3.0.6, pyarrow 25.0.1, SciPy 1.18.1,
NumPy 2.5.3, PyYAML 6.0.3. Ban đầu thiếu SciPy, sau đó test hồi quy Phase 1
phát hiện thiếu joblib của module model mới; đã cài dependency pin của dự án.
Lỗi logging pip do encoding đường dẫn Unicode được xử lý bằng `PYTHONUTF8=1`.
`pip check` cuối: không có dependency bị hỏng. Không train model hoặc gọi API dữ liệu.

## Kiểm thử và provenance

- 36 test đạt: 13 test metric (bao gồm CLI roundtrip/tamper), 8 ranking,
  6 CVSS và 9 Phase 1 release.
- Fixture tính tay: Jaccard {A,B}/{B,C}=1/3; recall 0 và 1; tau=-1/3
  không hòa, tau=1/2 có hai loại hòa; kiểm ID khác cohort, missing, version,
  rank sai, K invalid, N=1, score hằng, KEV=0 và K>=N.
- CLI kiểm hash/bytes của parquet với release metadata, rồi đối chiếu toàn bộ
  396 ID/tín hiệu/rank với `build_rankings` từ release; không chỉ đối chiếu N.
- Provenance dùng Git for Windows giống terminal repo; MSYS2 Git trong PATH dùng
  autocrlf khác và từng báo dirty do newline. Không sửa cấu hình Git toàn máy.
- Kiểm chéo CSV thật độc lập: đếm concordant/discordant/ties từng cặp cho tau-b,
  đếm lại top-K/overlap/cutoff, kiểm toàn bộ hash/bytes output trong metadata.
- Output CSV UTF-8/LF; JSON strict (không NaN/Infinity). Metadata ghi hashes/bytes
  của config/input/code/output, commit chạy và package versions, số dòng CSV.
- `rankings.csv` giữ nguyên 48.438 byte, SHA-256
  `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.

## Kết quả thật trên snapshot v1

Dataset `t08-v1.0-20261010`, cohort `t08-v1.0-20261010:ranking`, N=396,
388 Web + 8 mobile, tổng KEV=3. Policy `cvss-epss-kev-first-v1`.
EPSS 2026-09-29; KEV phát hành 2026-09-30T16:59:23.0688Z,
tải 2026-10-01T11:29:35.854976+00:00.

Kendall tau-b CVSS Base–EPSS từ điểm gốc: **0.30569771817081276**.
Tính bằng SciPy `variant=b`, có xử lý ties, không dùng rank đã phá hòa theo ID.
Tham chiếu: https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.kendalltau.html.

| Policy | K | KEV hits/3 | Recall | Nhóm hòa tại cutoff | Được lấy từ nhóm hòa |
|---|---:|---:|---:|---:|---:|
| CVSS | 10 | 0/3 | 0 | 28 | 10 |
| CVSS | 20 | 0/3 | 0 | 28 | 20 |
| CVSS | 50 | 1/3 | 0.3333333333 | 1 | 1 |
| EPSS | 10 | 3/3 | 1 | 1 | 1 |
| EPSS | 20 | 3/3 | 1 | 1 | 1 |
| EPSS | 50 | 3/3 | 1 | 1 | 1 |
| KEV-first | 10 | 3/3 | null | 1 | 1 |
| KEV-first | 20 | 3/3 | null | 1 | 1 |
| KEV-first | 50 | 3/3 | null | 1 | 1 |

KEV-first Recall luôn null với reason `policy_uses_kev_directly`; hits chỉ mô tả.
Nhóm cutoff một phần tử không phải bất đồng phá hòa; vẫn ghi count=1.

| Cặp policy | K | Giao | Hợp | Jaccard |
|---|---:|---:|---:|---:|
| CVSS / EPSS | 10 | 1 | 19 | 0.0526315789 |
| CVSS / EPSS | 20 | 2 | 38 | 0.0526315789 |
| CVSS / EPSS | 50 | 10 | 90 | 0.1111111111 |
| CVSS / KEV-first | 10 | 1 | 19 | 0.0526315789 |
| CVSS / KEV-first | 20 | 2 | 38 | 0.0526315789 |
| CVSS / KEV-first | 50 | 10 | 90 | 0.1111111111 |
| EPSS / KEV-first | 10 | 10 | 10 | 1 |
| EPSS / KEV-first | 20 | 20 | 20 | 1 |
| EPSS / KEV-first | 50 | 50 | 50 | 1 |

Ngưỡng minh họa 2x2 (không phải nhãn khai thác): high/high=20,
CVSS cao–EPSS thấp=139, CVSS thấp–EPSS cao=8, low/low=229; tổng 396.
`rank_deltas.csv` có 396 dòng, delta=CVSS rank − EPSS rank; dương là EPSS xếp sớm hơn.

## Output và bàn giao N3

`data/processed/p3_n2/`: rankings.csv (396 dòng), ranking_metrics.json,
topk_metrics.csv (9 dòng), overlap.csv (9 dòng), rank_deltas.csv (396 dòng), metadata.json.
Hash từng output/config/input nằm trong metadata; metadata không tự hash.
ZIP đợt B kèm contract, config và báo cáo để N3 đọc schema trước khi vẽ metric.
Chi tiết gói/checksum ở `docs/handoffs/p3-n2-ranking.md` sau khi đóng gói.
Chuẩn bị file không đồng nghĩa đã gửi/được N3 xác nhận.

## Giới hạn và trạng thái

- KEV chỉ 3, catalog không đầy đủ; không-KEV không phải false positive hoặc an toàn.
- Ba nguồn có mốc ngày khác nhau. Không phải kiểm định dự báo 30 ngày, không suy nhân quả.
- EPSS và KEV không độc lập. KEV-first dùng KEV để sort, không tự kiểm định bằng KEV.
- Jaccard=1 cho top-K EPSS/KEV-first chỉ nói cùng tập top-K, không khẳng định thứ tự giống nhau.
- Hòa CVSS ở top-10/20 lớn, ID tie-break ảnh hưởng thành phần top-K.
- CVSS cao/EPSS thấp không chứng minh vá lãng phí; context/affected chưa được tính ở B.
- [x] A: CSV ranking đã tái tạo, hash khớp.
- [x] B: config/contract, metrics, tests và output thật.
- [ ] Người dùng gửi gói/schema cho N3; chưa có xác nhận tiếp nhận.
- [ ] C/D/E: Environmental/mapping/queue/case/playbook chưa thực hiện.
