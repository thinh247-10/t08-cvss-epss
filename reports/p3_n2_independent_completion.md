# Phase 3 N2 — hoàn thành phần độc lập, context revision v2

Hoàn thiện 2026-10-20; advisory mở rộng đọc 2026-10-19. Branch feat/p3-ranking-context.
Không đánh dấu xác nhận, tác giả case hoặc hình ảnh thay N1/N3.

## Công việc đã bổ sung

- Hoàn thiện docs/analysis-results.md: 5 case N2 (3 Web/2 mobile) có vector nguồn,
  version/range/URL/ngày, điều kiện affected, tác động nghiệp vụ, EPSS/KEV/rank,
  Environmental và quyết định patch/review, staging/rollback và giới hạn.
- Cập nhật docs/03-environmental-context.md theo kết quả thật; bỏ khung lựa chọn
  ngành và pilot cũ, phân biệt population RQ2 với context, Scope-C all-X exception.
- Hoàn thiện docs/04-patch-playbook.md: trigger/owner, version/applicability,
  backup/restore, compatibility, approval, rollout/rollback và post-patch checks.
  Mốc thời hạn ghi rõ là giả định vận hành, không suy ra từ 3 KEV hoặc báo đã đo.
- Mở mapping từ 6 lên 15 cặp có nguồn vendor, không đợi N1 để nghiên cứu thêm.
  context_version tăng phase3-context-v2; snapshot/inventory/policy không đổi.

## Mapping mở rộng và quyết định thận trọng

Chín cặp thêm cùng asset Discourse 2.8.13/API-01; tất cả CVE có trong cohort v1.
Các URL đầy đủ/ngày/range/conditions/reviewer lưu trong extension YAML/output CSV.

| CVE | Vendor GHSA | Quyết định | Lý do chính |
|---|---|---|---|
| 2022-23548 | 7rw2-f4x7-7pxf | affected có điều kiện | stable <=2.8.13; post-parser ReDoS |
| 2022-23549 | p47g-v5wr-p4xp | affected có điều kiện | stable <=2.8.13; post length validation |
| 2022-46168 | 8p7g-3wm6-p3rm | needs_review | chưa rõ group SMTP được bật |
| 2023-22453 | xx97-6494-p2rv | affected có điều kiện | stable <=2.8.13; user JSON endpoint |
| 2023-22454 | ggq4-4qxc-c462 | needs_review | pending approval/CSP chưa rõ |
| 2023-22455 | 5rq6-466r-6mr9 | needs_review | tag editing/CSP chưa rõ |
| 2023-22468 | 8mr2-xf8r-wr8m | needs_review | vendor range lệch mô tả v1 + CSP chưa rõ |
| 2023-23620 | hvj9-g84x-5prx | affected có điều kiện | stable <=3.0.0; restricted-tag route |
| 2023-23621 | mrfp-54hf-jrcv | affected có điều kiện | stable <=3.0; user-agent parser ReDoS |

Không giả định CSP tắt hoặc SMTP bật, không gọi 15 cặp là 15 affected/15 hệ thống
độc lập/15 lần patch. Vendor hiện tại cho 22468 fixed >=3.0.1 còn v1 nói 2.8.13:
giữ source conflict và review, không tự nói 2.8.13 unaffected hoặc sửa nhãn ranking.

## Kết quả chạy v2

- 15 mapping rows = 10 affected có điều kiện + 5 needs_review; target 15 đạt.
- 10 Environmental rows, source observed; 5 exclusions có reason.
- Queue 15 dòng = 8 patch + 7 review (5 applicability unknown + 2 client); không mất cặp.
- Context comparison chỉ 8 patch pairs; hai policy cùng tập, rank 1–8.
- Context vs env-first Jaccard@1=1, @2=1/3; Base vs Env @1=0, @2=1/3.
- RQ2 giữ nguyên 396 ID/3 KEV; ranking SHA
  4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67.
- Dataset t08-v1.0-20261010; inventory phase1-v1; snapshot EPSS 2026-09-29,
  KEV phát hành 2026-09-30/tải 2026-10-01 UTC. Không train hoặc tải lại tín hiệu.
- 67 regression/report tests đạt; verifier v1 14 file OK; 280 fixture FIRST đã khớp ở r1,
  scorer không đổi khi mở mapping. Oracle không thay kiểm độc lập của N3.

## Lệnh thực hiện và kiểm tra

```powershell
.\.venv\Scripts\python.exe -m src.analysis.ranking_metrics --rankings data/processed/p3_n2/rankings.csv --config config/phase3.yaml --output-dir data/processed/p3_n2
.\.venv\Scripts\python.exe -m src.analysis.context_priority --master data/processed/phase1_v1_20261010/cves.parquet --mapping config/phase3_mapping.yaml --inventory config/assets.yaml --config config/phase3.yaml --output-dir data/processed/p3_n2
.\.venv\Scripts\python.exe -m unittest tests.test_cvss_environmental tests.test_context_priority tests.test_ranking_metrics tests.test_rankings tests.test_cvss tests.test_phase1_release tests.test_asset_inventory tests.test_phase3_reports -q
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
```

Đối chiếu tự động số liệu 5 case/coverage/policy với CSV trước khi đóng gói;
package có schema/metadata/hash và tài liệu N2, không có file plot giả của N3.
ZIP r1 không bị ghi đè. Chi tiết ZIP v2 và SHA ở docs/handoffs/p3-n2.md.

## Checklist đóng phần độc lập

- [x] A/B ranking/metrics/config/contract/test.
- [x] C scorer và expected độc lập; mapping đạt 15 có căn cứ/review rõ.
- [x] D queue/sensitivity cùng tập, giữ unknown/client/missing.
- [x] E phần N2: 5 case đã điền, context doc và playbook hoàn thiện.
- [x] Tài liệu/CSV đối chiếu, code/test có thể tái chạy; gói mới giữ provenance.
- [ ] N1 gửi case Web riêng và kiểm tích hợp/version/range conflict; chưa có khi fetch.
- [ ] N3 gửi case mobile riêng và một kiểm Environmental độc lập; chưa có khi fetch.
- [ ] N3 bàn giao plots/captions để N2 đối chiếu; không tự viết thay hoặc giả xác nhận.
- [ ] Nhóm nhận gói/review/merge PR; chưa tự đánh dấu tiếp nhận hay merge.

Không còn bỏ trống case/playbook vì chờ nhóm: bản N2 đã có. Các checkbox còn mở
là bằng chứng/đầu vào và quyền quyết định của nhóm, không phải số nghiên cứu giả.
