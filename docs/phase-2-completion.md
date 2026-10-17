# Nghiệm thu và bàn giao Phase 2 — 17/10/2026

Trạng thái: **hoàn tất Phase 2 về triển khai, thí nghiệm và kiểm gói bàn giao**. Việc nhận gói và chạy trên máy đồng đội chưa được xác nhận.

Gói ZIP có 253.203.876 byte, SHA-256 `902f97cc84727a98cd36b9f3c17797927979e85f87466972d3f4ab5add1171ce`.
Đã giải nén mới, kiểm đủ 61 file theo manifest, đối chiếu notebook 13 cell và nạp model
trong tiến trình mới bằng CPU: 5 CVE validation khớp 8 nhãn và Base score. Không đánh giá
lại test. Xem [biên bản kiểm gói](../reports/p2_final_handoff_verification.json).

Yêu cầu chạy trên máy khác trong kế hoạch chưa được chứng minh: lần tái lập và kiểm gói
do N1 thực hiện trên máy N1. Đây là giới hạn bàn giao, không được ghi thành xác nhận của N3.

## Sản phẩm đã có

| Người / phần việc | Bằng chứng |
|---|---|
| N1 — dữ liệu/split đóng băng, tích hợp và tái lập | Release `t08-v1.0-20261010`, `reports/p2_reproduction_n1.md` |
| N2 — scorer, ranking, phân tích bảo mật | `reports/p2_scorer_check.md`, `reports/p2_ranking_smoke.md`, `reports/p2_validation_security_review.md` |
| N3 — Dummy/TF-IDF, đánh giá và model card | `src/model/`, `docs/model-card.md`, báo cáo gốc N3; baseline N1 tái lập khớp metric |
| N1 chạy thay N3 — DistilBERT một encoder/tám head | `reports/p2_distilbert_run.md`, config, model thật, prediction và checksum |
| Notebook trên model thật | `notebooks/02_model_eval_n1.ipynb`, 13 code cell đã thực thi |
| Kiểm tra tích hợp | 178/178 test đạt; checksum/inference/save-load đã kiểm |

N1 đã thực hiện phần chạy thay N3 theo yêu cầu; không ghi thay đóng góp hoặc lời
xác nhận của N2/N3. Joblib gốc N3 chưa được nhận; thay bằng bản retraining N1
có version riêng, metric khớp và gói đã được kiểm tra. Nhận xét nguồn này cần giữ
trong báo cáo, không gọi hai file model là giống byte.

## Kết luận RQ1

Mô tả CVE có thể dùng để dự đoán từng metric CVSS, nhưng sai số toàn vector còn
đáng kể. Trên test toàn ML, TF-IDF có mean macro-F1 0,7521 và exact vector 38,65%;
DistilBERT một epoch đạt 0,7317 và 33,05%. Kết quả không đủ để tự động thay thế
chuyên viên hay quyết định vá. Mẫu đã xác nhận scope Web có kết quả khác và
nhỏ hơn nhiều; mobile chưa có mẫu validation/test.

Không có ngưỡng điểm đặt trước để “đạt đồ án”. Phase này đạt về quy trình,
sản phẩm và phân tích giới hạn. Không chọn lại cấu hình hoặc sửa test để tăng điểm.

## Nhận gói và bước tiếp theo của nhóm

1. Cập nhật code `develop` bằng `git pull --ff-only origin develop` khi working
   tree sạch; nếu có sửa riêng, lưu công việc trước, không reset để lấy code.
2. Nhận ZIP `phase2_handoff_20261017.zip` qua kênh chia sẻ file. Đối chiếu SHA-256
   và byte count trong `docs/handoffs/phase-2-complete-20261017.json`.
3. Gói chứa `baseline.zip`, thư mục `distilbert`, `rankings.csv`, mã nguồn,
   requirements, notebook và báo cáo. Không chứa `.env` hay API key. Release
   Phase 1 được chuyển riêng như trước; không cần tải lại NVD/EPSS/KEV.
4. Mỗi người giữ môi trường Python riêng. Baseline dùng requirements-model/data;
   nhánh DistilBERT dùng requirements-distilbert. Không gửi `.venv`.
5. N2 dùng **CVSS quan sát + EPSS + KEV** trên cùng 396 CVE để làm Phase 3;
   tiếp tục Environmental, bối cảnh tài sản và case study. Không thay CVSS bằng
   prediction model trong thí nghiệm chính.
6. N3 dùng ranking đã kiểm để làm biểu đồ/so sánh top-50 theo Phase 3. Không train
   lại model hoặc sửa split; metric/prediction đã đủ để viết phần AI.
7. N1 kiểm tích hợp, version/hash và khả năng tái chạy. Người nhận tự ghi kết quả
   tải/verify; biên bản này chưa xác nhận hai bạn đã tải gói cuối.

Manifest đường dẫn làm việc: `config/phase2_release.yaml`.
Kế hoạch tiếp theo: [Phase 3 — xếp hạng và bối cảnh](phases/phase-3-xep-hang-va-boi-canh.md).
