# Bàn giao N2 → N3, Phase 3 đợt A+B

Ngày chuẩn bị: 2026-10-18. Người thực hiện: CanhLai (N2).
Branch `feat/p3-ranking-context`; commit tái tạo output
`591358d` (full SHA trong metadata). Đây chưa phải bàn giao toàn bộ Phase 3.

## Gói gửi riêng

- File: `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/3/n2_p3_step_b_20261018.zip`.
- Kích thước: **19.198 byte**.
- SHA-256: `c3aacd4e7b8afddc5950365c929c71358a56e2d794a3d37626feb714d7508945`.
- Đã kiểm CRC, đủ 9 file, hash từng output/ranking/config khớp metadata.
- Không chứa model, `.env`, `.venv`, key hay toàn bộ dataset release.
- Gói chứa lại CSV của A nên N3 chỉ cần gói này để có đầy đủ A+B.

Giải nén vào thư mục tạm mới để tránh ghi đè artifact đang dùng. Trong ZIP:

```text
p3_n2/
  rankings.csv
  ranking_metrics.json
  topk_metrics.csv
  overlap.csv
  rank_deltas.csv
  metadata.json
phase-3-artifact-contract.md
phase3.yaml
p3_ranking_results.md
```

N3 đọc contract trước khi vẽ metric, kiểm hashes rồi đặt `p3_n2/` dưới
`data/processed/`. Nếu đã có thư mục từ đợt A, đối chiếu/reconcile trước khi chép,
không xóa dữ liệu riêng. Config/code chuẩn nằm trên branch; copy config trong ZIP
chỉ để đối chiếu checksum, không tự chép vào root repo.

## Version và coverage

Dataset `t08-v1.0-20261010`; cohort `t08-v1.0-20261010:ranking`.
Policy `cvss-epss-kev-first-v1`; schema `p3-ranking-metrics-v1`.
Context `phase3-context-v1` mới là version dự kiến, chưa có Environmental/queue.
EPSS 2026-09-29; KEV phát hành 2026-09-30, tải 2026-10-01 UTC.

- Rankings: 396 ID, 388 Web + 8 mobile, 3 KEV, không loại thêm hàng.
- Top-K: 9 dòng; overlap: 9 dòng; delta: 396 dòng.
- 36 test đạt (13 metric + 8 ranking + 6 CVSS + 9 release).
- Tau-b=0.30569771817081276, điểm gốc có ties.
- KEV-first recall=null có reason; không đổi ô rỗng CSV thành 0.
- Hash ranking A không đổi: `4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.

## Tái chạy

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_ranking_metrics tests.test_rankings tests.test_cvss tests.test_phase1_release -q
.\.venv\Scripts\python.exe -m src.analysis.ranking_metrics --rankings data/processed/p3_n2/rankings.csv --config config/phase3.yaml --output-dir data/processed/p3_n2
```

CLI tái tạo output trong repo, không sửa ZIP đã gửi. Lần chạy mới metadata đổi
timestamp/commit; nếu gửi lại phải dùng tên revision mới, không ghi đè gói này.

## Trạng thái và giới hạn

- [x] A+B hoàn tất, dữ liệu và contract sẵn sàng cho N3 vẽ song song.
- [ ] Người dùng gửi ZIP này cho N3; chưa có bằng chứng đã truyền file/tiếp nhận.
- [ ] C/D/E chưa làm: Environmental/mapping/queue/sensitivity/case/playbook.

Chỉ 3 KEV; không gọi non-KEV là false positive, không kiểm định dự báo 30 ngày,
không coi KEV-first recall là kiểm định độc lập. Hòa CVSS tại cutoff top-10/20
có 28 CVE, ID tie-break ảnh hưởng top-K. EPSS/KEV-first cùng tập top-K không
có nghĩa cùng thứ tự. Chi tiết hạn chế và bảng số thật ở báo cáo trong ZIP.
