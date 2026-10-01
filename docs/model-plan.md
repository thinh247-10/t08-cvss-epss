# Kế hoạch mô hình — Phase 0, Người 3

Căn cứ: [config/model.yaml](../config/model.yaml) và [data contract](data_contract.md).
Đây là thiết kế ban đầu; chưa train, tải checkpoint hoặc có số đo chất lượng mô hình.

## 1. Input, output và nhãn

- **Input:** chỉ `description` tiếng Anh có nội dung. CVE ID, ngày và version là metadata;
  CVSS nguồn, EPSS và KEV không làm feature.
- **Output:** tám nhãn Base theo thứ tự AV/AC/PR/UI/S/C/I/A, vector CVSS 3.1 và Base Score
  tính từ vector bằng scorer chung của N2. Input rỗng trả lỗi; score không tính được giữ null.

| Metric | Label order, ID bắt đầu từ 0 |
|---|---|
| AV | N, A, L, P |
| AC | L, H |
| PR | N, L, H |
| UI | N, R |
| S | U, C |
| C | N, L, H |
| I | N, L, H |
| A | N, L, H |

Giữ mapping này trong train, inference và artifact; không nhận `X` hoặc trộn phiên bản CVSS.
Nhãn nguồn được chọn theo contract: vector 3.1 hợp lệ từ `nvd@nist.gov` trước, rồi Primary,
rồi thứ tự nguồn/vector cố định. Không tự sửa nhãn; nhãn nguồn là mốc đánh giá của dataset.

## 2. Ba mức model và tham số ban đầu

| Model | Thiết kế và vai trò |
|---|---|
| Dummy | Một `DummyClassifier(strategy=most_frequent)` mỗi metric, fit trên train; mốc so sánh lớp phổ biến |
| TF-IDF + Logistic Regression | Một vectorizer dùng chung, tám classifier độc lập; baseline thực hiện trước DistilBERT |
| DistilBERT | `distilbert/distilbert-base-uncased`, một encoder chung và tám head kích thước 4/2/3/2/2/3/3/3 |

Baseline dùng `ngram_range=[1,2]`, `min_df=2`, `max_features=50000`,
`class_weight=balanced`, `max_iter=1000`. DistilBERT dùng tokenizer tương ứng,
`max_length=256`, `lemmatize=false`; learning rate và batch size chưa xác nhận.
Seed 42 khớp `project.seed` trong `config/project.yaml`.

Theo YAML, `configured_values=initial_design`, `status=not_run`,
`selection_split=validation`, `empirically_selected_parameters=null`.
Các giá trị trên chưa được thực nghiệm lựa chọn. Chỉ ghi tham số đã chọn khi có bằng chứng
validation và lưu config/version tương ứng. Chưa kết luận DistilBERT tốt hơn baseline trước khi đo.

## 3. Dữ liệu và chống leakage

Split lấy từ trường `split` của [config/project.yaml](../config/project.yaml), qua
`data.split_source` và `data.split_key`; chia theo `published`, hiện còn `provisional`.
Không đổi ngày split trong thiết kế model. Các model dùng cùng ID và dataset/split version.

- Fit TF-IDF, class weights và preprocessing có học tham số **chỉ trên train**.
  Nếu dùng class weights cho DistilBERT, tính riêng từng metric từ train.
- Validation chọn cấu hình/checkpoint; test chỉ đánh giá cuối.
- Kiểm ID không chồng, mô tả trùng/gần trùng và nhóm sản phẩm giữa split trước khi khóa dữ liệu.
  Thay dữ liệu/nhãn/split phải lưu quyết định và tăng `dataset_version`.
- NVD snapshot có thể chứa mô tả/nhãn sửa sau ngày công bố; split thời gian không tự khôi phục
  dữ liệu lịch sử. Báo đây là đánh giá trên snapshot hiện có.

**Missing/Rejected:** chỉ đưa vào ML các CVE không Rejected, có mô tả không rỗng và đủ tám
nhãn CVSS 3.1 hợp lệ. Giữ dữ liệu thiếu/Rejected trong master/raw, báo lý do và số mẫu loại;
không tự điền target. Thiếu EPSS/KEV không tự loại mẫu ML; giữ null/unknown.

**Lớp hiếm:** thống kê mọi lớp theo metric/split, kể cả lớp có số mẫu 0. Giữ nguyên mapping,
không gộp lớp hoặc xóa mẫu validation/test khó. `balanced` tính từ train, chưa bảo đảm cải thiện.
Lớp vắng train phải được báo là không có dữ liệu học; nếu mở miền train, cần N1 tổng hợp quyết định
và vẫn báo kết quả Web/mobile riêng.

**Fallback:** target train chỉ có một lớp dùng Dummy thay Logistic Regression cho riêng target đó;
các target khác tiếp tục dùng Logistic Regression. Lưu `classes_` và ánh xạ về label order chung.
Train rỗng hoặc TF-IDF không có từ vựng là lỗi cần ghi nhận, không coi là fallback một lớp.
DistilBERT giữ đủ tám head và báo giới hạn khi train thiếu lớp.

## 4. Phần cứng

Dùng số liệu bản nháp đã được chủ máy xác nhận.

| Hạng mục | Kết quả |
|---|---|
| CPU | AMD Ryzen 7 7730U with Radeon Graphics; 8 nhân, 16 bộ xử lý logic |
| RAM vật lý | 15,4 GiB; không phải RAM còn trống |
| GPU hệ điều hành liệt kê | AMD Radeon (TM) Graphics |
| VRAM | Chưa xác nhận |
| Torch/backend GPU | Chưa xác nhận |
| Thời gian máy khả dụng | Chưa xác nhận |

Dummy và baseline dự kiến chạy CPU. Tên GPU chưa chứng minh khả năng tăng tốc Torch;
thiết bị chạy DistilBERT cần kiểm trước Phase 2.

## 5. Phạm vi và ngân sách DistilBERT

Theo YAML, N3 đề xuất `timeboxed_extension`: **tổng tối đa 6 giờ fine-tune**, tối đa **2 lượt**,
**3 epoch mỗi lượt**. Ngân sách không tính chuẩn bị môi trường/tải checkpoint và không phải
thời gian hoàn thành đã đo. Baseline được ưu tiên; hết ngân sách hoặc thiếu tài nguyên thì dừng,
ghi `not_run`, `partial` hoặc `failed` cùng lý do.

Phạm vi bắt buộc hay mở rộng, máy chạy và ngân sách **chưa được nhóm chốt**;
N1 tổng hợp D05 trước Phase 2. Chỉ chạy khi dataset/split/nhãn, evaluator/scorer và thiết bị đã sẵn sàng.

## 6. Đánh giá

| Kết quả | Chính sách |
|---|---|
| Từng metric | Accuracy, macro-F1, F1 từng lớp, support và số mẫu |
| Macro-F1 | Dùng toàn bộ `label_order`, `average=macro`, `zero_division=0`; lớp vắng vẫn báo support 0 |
| Exact-vector accuracy | Số CVE đúng cả tám metric / toàn bộ CVE đủ nhãn trong split đánh giá |
| Base MAE/RMSE | Chỉ tính trên các cặp target/prediction có vector hợp lệ và tính được bằng scorer chung |
| `score_coverage` | Số cặp tính được score / toàn bộ CVE đủ nhãn; báo tử số và mẫu số |
| `invalid_prediction_count` | Đếm hàng có lỗi inference/vector/scorer, mỗi hàng tối đa một lần; lỗi target báo riêng |

Giữ hàng prediction lỗi và lý do; không âm thầm loại khỏi báo cáo. Prediction lỗi tính là sai
trong exact-vector; metric từng thành phần không tính đủ phải báo coverage và trạng thái chưa hoàn chỉnh.
Split rỗng hoặc không có cặp score hợp lệ báo null/N/A. Model chưa chạy không có số đo.
So sánh các model trên cùng tập đánh giá và version; Base Score dùng scorer chung của N2.

## 7. Artifact dự kiến

| Đường dẫn | Nội dung |
|---|---|
| `models/baseline.joblib` | Dummy, vectorizer, tám estimator/fallback, mapping và config/version |
| `models/distilbert/` | Encoder/heads, tokenizer, mapping và config/version nếu chạy |
| Mapping/config cùng model | Label-to-ID/ID-to-label, bản chụp config, seed và manifest/checksum |
| `data/processed/predictions.csv` | Prediction theo schema contract |
| `reports/model_metrics.json` | Metrics, số mẫu, coverage/lỗi, config và model/dataset/split version |
| `docs/model-card.md` | Intended use, dữ liệu, thiết bị và giới hạn |
| `notebooks/02_model_eval.ipynb` | Phân tích kết quả từ artifact |

Prediction một dòng/CVE/model, khóa `(cve_id, model_version)`, gồm:

- `cve_id`, `split`, `dataset_version`, `model_version`, `prediction_usage` (`evaluation`/`demo`).
- `pred_AV`, `pred_AC`, `pred_PR`, `pred_UI`, `pred_S`, `pred_C`, `pred_I`, `pred_A`.
- `predicted_vector`, `predicted_base_score`, `vector_valid`, `prediction_error`.

## 8. Demo phác thảo

1. **Dataset/ranking:** đọc artifact đã tính, hiển thị snapshot và nguồn điểm.
2. **Case theo tài sản:** xem applicability, Base/Environmental và lý do ưu tiên.
3. **Nhập mô tả:** dùng model đã lưu, hiển thị tám metric/vector/score hoặc lỗi, `model_version`
   và nhãn “ước lượng từ mô tả”; chưa có ground truth thì không hiển thị accuracy cho trường hợp đó.

Demo không train hoặc tải dữ liệu/checkpoint khi mở app. Phase 0 chỉ phác thảo bằng chữ.

## 9. Thông báo bàn giao nhóm

```text
N3 đã soạn xong hai đầu ra thiết kế Phase 0: config/model.yaml và docs/model-plan.md.
Branch: chore/p0-model-config. 
Môi trường: Python 3.13.16; pandas 3.0.6, pyarrow 25.0.1, PyYAML 6.0.3, scikit-learn 1.9.1; import dữ liệu/scikit-learn OK.
Phần cứng: Ryzen 7 7730U (8 nhân/16 luồng), RAM 15,4 GiB, AMD Radeon (TM) Graphics.
Chưa xác nhận: VRAM, Torch/backend GPU và thời gian máy khả dụng.
Đề xuất DistilBERT: phần mở rộng có giới hạn, tổng 6 giờ fine-tune, tối đa 2 lượt, 3 epoch/lượt; chưa train hoặc tải checkpoint.
Cần N1 tổng hợp/chốt: nhãn nguồn, dataset/split và phạm vi/ngân sách DistilBERT; N2 chốt scorer chung.
Dữ liệu cần từ N1: description tiếng Anh, đủ 8 nhãn CVSS 3.1, vector/nguồn, published/split, metadata/version/checksum và thống kê lớp/missing/Rejected.
Phase 1 tiếp theo: đọc mẫu, kiểm dtype/nhãn và audit dữ liệu trước khi train.
```
