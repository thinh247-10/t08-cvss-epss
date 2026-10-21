# Nghiệm thu Phase 3 — tích hợp N1 ngày 21/10/2026

**Hoàn tất phần nghiên cứu/triển khai Phase 3; có thể bắt đầu Phase 4.**
Đây là kiểm kỹ thuật của N1 chạy bằng công cụ hỗ trợ, không phải xác nhận hai đồng đội
đã nhận gói mới hoặc đã diễn tập demo. Kiểm trên máy khác và demo thuộc Phase 4.

## Kết quả kiểm hai thành viên

| Phần | Đánh giá |
|---|---|
| N2 `59c86b5` | Ranking/metric đúng cohort; Environmental/queue có kiểm nguồn và tests; context-v2 đủ15 mapping |
| N3 `ade5a28` | Plots, case mobile, Decimal crosscheck, analysis AI phụ và UI contract đúng hướng; đầu vào còn r1 |
| N1 hoàn thiện | Merge hai branch; tái tạo context-v2, cập nhật hình/notebook/UI contract; kiểm độc lập, thêm case Web, đóng gói |

Lỗi/thiếu đã xử lý: r1 có6 cặp còn r2 có15; notebook và UI contract chưa đồng bộ;
crosscheck đóng cứng version r1; provenance gọi Git trong PATH khác Git for Windows;
oracle ghi cứng ngày đọc; receipt N3 được liên kết nhưng không có trong commit.
Gói mới dùng receipt chung, không giả lập receipt N3 gốc.

Đính chính yêu cầu N1 trước đó: Environmental all-X không luôn bằng Base với Scope=C
vì công thức Modified Impact v3.1. Kiểm 280 vector độc lập FIRST khớp toàn bộ.

## Bằng chứng và số liệu đã kiểm

- Dataset `t08-v1.0-20261010`; 396 CVE ranking (388Web/8mobile), 3 KEV.
- Tau-b trên score gốc **0,30569771817081276**; N1 đếm lại từng cặp độc lập với SciPy.
- CVSS top50 chứa1/3 KEV; EPSS top50 chứa3/3. Đây là đối chiếu snapshot, không forecast.
- Context `phase3-context-v2`:15 mapping,10 scored,8 patch,7 review;2 client vẫn review.
- Top50 đủ150 dòng (3 policy×50); 7PNG+7SVG. N1 đã mở xem cả7PNG, nhãn/legend đọc được;
  kiểm toàn bộ ID top50 và số liệu nguồn. SVG do cùng hàm render, N3 đã xem bản r1.
- AI phụ:69validation/108test scoped,354 dòng, không thiếu; không train/inference lại.
- Full suite **253 test, OK, skipped4**; sau sửa nhỏ tiếp **29 test, OK, skipped3**.
  Skip do fixture r1/đường dẫn received trên máy N3 không hiện hữu; production v2 đã chạy trực tiếp.
- Notebook6 code cells đã chạy lại,7 hình thật embedded; `pip check` đạt.
- [Kiểm artifact độc lập](../reports/p3_integration_verification.json),
  [log tái chạy](../reports/p3_review_n1.md), [hình/caption](../reports/p3_figures.md).

## Phạm vi xác minh

Chỉ nhận ZIP bước B trong Downloads; không nhận ZIP N2 r2 và N3 cuối.
N1 tái tạo từ code đã push và release v1 trên máy N1. Vì vậy gói N1 là revision mới,
không tuyên bố byte-identical với ZIP máy N2/N3. Metadata ghi nguồn/commit/hash từng file.
Không đổi nhãn CVSS, EPSS, KEV, split hoặc model Phase 2. Một số metadata lịch sử trong
gói tái tạo giữ trạng thái peer review pending tại lúc sinh; biên bản này ghi kết quả tích hợp sau đó.

Nguồn giới hạn: context là tổ chức giả định;9 cặp thêm cùng một Discourse asset,
không phải9 deployment độc lập hoặc9 lần vá. EPSS29/09, KEV phát hành30/09 và tải01/10UTC,
không cùng ngày. Không-KEV không chứng minh không khai thác; KEV-first không kiểm định
độc lập bằng KEV recall. Mobile held-out AI không có; không khái quát chất lượng model sang mobile.

## Gói gửi cả hai bạn

`data/processed/phase3_handoff_20261021.zip`, receipt hash/bytes tại
`docs/handoffs/phase-3-complete-20261021.json`. Gói giữ đường dẫn tương đối repo:
`data/processed/p3_n2`, `p3_n3`, staging context đã kiểm, `reports/`, notebook và config.
Không có `.env`, API key, `.venv`, model hoặc dữ liệu Phase1/2 lớn.
Giải nén vào thư mục mới để kiểm manifest trước, không ghi đè sản phẩm cũ.
N1 giữ các gói cũ để truy nguyên; gửi **gói Phase3 mới** cho cả hai người.
Không phải gửi lại Phase1/2 nếu họ đã có bản đúng.

## Việc tiếp theo

- [N1 — môi trường/runbook/kiểm release](phase-4-nguoi-1.md).
- [N2 — kịch bản bảo mật và nghiệm thu nội dung](phase-4-nguoi-2.md).
- [N3 — demo offline và hiển thị AI](phase-4-nguoi-3.md).

Không mở Phase5 như thể đã diễn tập xong. Gate Phase4 phải có demo chạy thật và log máy nhận.
