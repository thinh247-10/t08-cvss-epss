# Bàn giao Phase 2 — N2

Ngày: 2026-10-15. Người thực hiện: CanhLai.
Branch: `feat/p2-cvss-scorer`. Dataset: `t08-v1.0-20261010`.
PR: https://github.com/thinh247-10/t08-cvss-epss/pull/6.

## Kết quả sẵn sàng tiếp nhận

- Nhận gói v1: `PHASE1 RELEASE OK`; Python 3.13.12.
- Base scorer dùng chung đã kiểm chứng theo FIRST; `tests/test_cvss.py`.
- Ranking: 396 CVE, 3 KEV, cùng tập ID cho ba policy, đủ rank 1–396.
- Case: 5 cặp từ mapping v1, gồm 3 Web/2 mobile; client `review_required`.
- Review validation: 13 CVE từ N3 commit `a5c0c16`, phủ cả tám metric,
  có hai case scoped Web; validation không có mobile.
- 23 test đạt: `tests.test_phase1_release`, `tests.test_cvss`, `tests.test_rankings`.

## Artifact gửi riêng N1

File nguồn: `data/processed/rankings.csv` (Git ignore).
Policy: `cvss-epss-kev-first-v1`; cohort `t08-v1.0-20261010:ranking`.
EPSS: 2026-09-29. SHA-256:
`4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.

Bản tiện gửi đặt tại
`D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/2/n2_phase2_handoff_20261015/`:
`rankings.csv` và `p2_n2_handoff.md` này. Gửi hai file cho N1 qua kênh chia sẻ
nhóm. Chưa có bằng chứng N1 đã nhận; không đánh dấu thay người nhận.

## Tích hợp còn lại

- PR #6 đã đổi base từ `main` sang `develop` ngày 2026-10-15;
  đã kiểm tra GitHub: open, không phải draft, mergeable, 8 file thay đổi.
  N1 kiểm tích hợp và merge khi sẵn sàng; N2 không tự merge thay N1.
- N1 tiếp nhận ranking và bảo trì module ranking ở Phase 3.
- N3 lấy `reports/p2_validation_security_review.md` để tổng hợp model card.
- Xác nhận tiếp nhận của N1/N3, reproduction model trên máy khác và quyết định
  DistilBERT thuộc phối hợp nhóm; không phải kết quả đã thực hiện trong báo cáo N2.

## Tự kiểm tra

Tại repo root:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_phase1_release tests.test_cvss tests.test_rankings -v
Get-FileHash -LiteralPath data/processed/rankings.csv -Algorithm SHA256
```

Kỳ vọng 23 test OK và checksum như trên. Các báo cáo chi tiết:
`p2_scorer_check.md`, `p2_ranking_smoke.md`, `p2_validation_security_review.md`
và `docs/analysis-results.md`.
