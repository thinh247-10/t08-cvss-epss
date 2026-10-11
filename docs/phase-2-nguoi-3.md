# Người 3 — Nhận gói v1 và huấn luyện mô hình Phase 2

Ngày giao: 2026-10-11. Code Phase 1: `e0b948b` trên `develop`.
Dataset: **`t08-v1.0-20261010`**. Mục tiêu: mô tả CVE → tám metric → vector CVSS 3.1
→ Base Score. EPSS/KEV không phải feature hoặc target của mô hình này.

## 1. Nhận code, môi trường và ZIP

N1 gửi riêng `phase1_v1_20261010.zip` (38.599.819 byte). Không nhận `.venv` hoặc
API key của N1; train trên gói offline không cần NVD key. Không tải lại dataset.

Tại thư mục repo có `src`:

```powershell
Get-Location
git status --short
```

Lưu/commit thay đổi của mình trước khi chuyển branch nếu có. Sau đó:

```powershell
git switch develop
git pull --ff-only origin develop
git switch -c feat/p2-nlp-baseline
```

Nếu branch đã tồn tại, switch sang nó và kiểm đã có code `develop` mới;
không xóa branch, reset hoặc force để né lỗi.

Giữ `.venv` riêng nếu đã dùng được. Nếu chưa có:

```powershell
py -0p
python -m venv .venv
```

Dùng interpreter đã cài trên máy; ghi lại version thực tế. Nếu `python` không tồn tại,
chọn interpreter từ `py -0p` thay vì sao chép `.venv` từ máy khác.

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
.\.venv\Scripts\python.exe -m pip install scikit-learn joblib matplotlib seaborn jupyter
.\.venv\Scripts\python.exe -c "import sklearn, joblib, pandas, pyarrow; print('BASELINE ENV OK', sklearn.__version__)"
```

Chưa cần cài Torch/Transformers cho Dummy và TF-IDF. Khi code baseline hoàn chỉnh,
tạo `requirements-model.txt` ghi phiên bản baseline đã chạy được để N1 tái chạy;
không dùng toàn bộ `pip freeze` chứa các thư viện không liên quan làm dependency chung.

```powershell
Get-FileHash -LiteralPath "$env:USERPROFILE\Downloads\phase1_v1_20261010.zip" -Algorithm SHA256
```

Thay đường dẫn nếu bạn lưu nơi khác. Hash phải là
`215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.
Giải nén vào `data/processed/` để có thư mục `phase1_v1_20261010`.
Không ghi đè bản khác đã có; kiểm version/hash trước.

```powershell
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
```

Gửi N1 `PHASE1 RELEASE OK`, dataset version và Python version thực tế.

## 2. Dữ liệu và giao thức đã khóa

| Nội dung | Giá trị/cách dùng |
|---|---|
| Input chính | `data/processed/phase1_v1_20261010/ml_cohort.parquet` |
| Config model | `config/model.yaml` đã tồn tại, chứa thiết kế chưa train |
| Split đã gán | Train 28.815; validation 19.606; test 18.821 |
| Feature | Chỉ `description` |
| Target | AV, AC, PR, UI, S, C, I, A theo `label_order` |
| Scorer | `src.environmental.cvss_base.calculate_base_score(vector)` |
| Validator | `src/model/data_validation.py`, gọi qua `prepare_baseline_inputs` nếu phù hợp |
| Metadata/support | `metadata.json`, `label_support.csv` trong gói |

Không chia lại hoặc khử trùng lại khi train. Không đọc master 71.653 dòng rồi tự
lọc khác; dataset ML 67.242 dòng đã khóa ID. Kiểm cấu trúc test được phép,
nhưng không dùng prediction/lỗi/điểm test để chọn model hoặc preprocessing.

ML toàn miền và Web/mobile phải báo riêng: scoped train/validation/test là
219/69/108. Cả 8 mobile đều trong train; validation/test scoped chỉ có Web.
Không tuyên bố đã đo chất lượng dự đoán riêng trên mobile. Giữ lớp support 0
trong báo cáo; quy ước macro-F1 theo toàn bộ label map, `zero_division=0`.

## 3. Làm lần lượt

### Bước A — Dummy và TF-IDF, khoảng 5 giờ

`src/model/baseline.py` hiện chỉ có hàm chuẩn bị input, chưa train.
Triển khai tại file này:

1. Đọc config và đúng dataset/version; dùng cột split có sẵn.
2. Một Dummy most-frequent cho mỗi metric, fit trên train.
3. Một TF-IDF chung fit chỉ train, tám Logistic Regression riêng; cấu hình khởi đầu
   đã có trong YAML. Head một lớp dùng constant/Dummy và ghi log; train rỗng báo lỗi.
4. Tối đa hai cấu hình baseline, chọn trên validation theo macro-F1 trung bình tám
   metric và chi phí. Ghi trước tiêu chí; không thử test trong vòng lựa chọn.
5. Lưu/nạp `models/baseline.joblib` chứa Dummy, vectorizer, classifier, labels,
   config, model_version, dataset_version, seed và phiên bản thư viện.
6. Rà chuỗi điểm/vector CVSS có sẵn trong description; nếu xử lý, dùng cùng quy tắc
   cố định trong train/inference, ghi số dòng và không xóa từ nghiệp vụ như remote/authenticated.

Tạo `tests/test_baseline.py`: feature chỉ mô tả, vocabulary fit train, fallback
một lớp, save/load cho prediction giống nhau, input rỗng/version sai báo lỗi.
Không cần train full dataset trong unit test.

### Bước B — Suy luận và đánh giá, khoảng 3 giờ

| File tạo/sửa | Trách nhiệm |
|---|---|
| `src/model/predict.py` | Nạp artifact, nhận mô tả, xuất tám nhãn/vector/score bằng scorer chung |
| `src/model/evaluate.py` | Join theo ID/model version; tính accuracy/F1/support, exact vector, MAE/RMSE và coverage |
| `tests/test_model_evaluation.py` | Prediction đảo dòng, thiếu/trùng ID, vector invalid, split rỗng, lớp support 0 |
| `notebooks/02_model_eval.ipynb` | Gọi module, hiển thị kết quả thật, không chứa bản sao thuật toán |

Xuất `data/processed/predictions.csv` đúng mục prediction trong data contract.
Khóa `(cve_id, model_version)`, có `prediction_usage`, split/dataset/model version,
8 cột `pred_*`, vector, score, validity và lỗi. Mỗi mô hình cần model_version riêng.
Prediction lỗi phải được đếm, không âm thầm bỏ để làm đẹp metric.

Lưu `reports/model_metrics.json` có số mẫu/mẫu số, kết quả toàn miền và scoped,
validation tách test. Giao lỗi validation cho N2; tránh đưa lỗi test vào vòng sửa model.

### Bước C — Khóa lựa chọn, test và model card, khoảng 2 giờ

Tạo `docs/model-card.md`: mục đích/giới hạn, version, split, config đã chọn,
thiết bị/thời gian, validation và test tách riêng, lỗi N2 phân tích.
Thêm bảng đối chiếu Costa et al. (2022), DOI `10.1109/ACCESS.2022.3179692`:
dữ liệu, input, nhãn/CVSS version, model, split, metric; chỉ ghi chi tiết bài gốc
khi đã đọc nguồn, chưa xác minh thì nêu rõ. Không gọi đây là tái lập DeepCVA commit-level.

Khóa config và artifact trước khi chạy test cuối. Không đổi model từ điểm test rồi
báo lại như test chưa từng được xem. Ghi NVD là snapshot hiện tại, có nhãn/mô tả
cập nhật sau published; MinHash có thể bỏ sót và sản phẩm vẫn giao nhau giữa split.

### Bước D — DistilBERT có giới hạn, sau baseline

Chưa bắt đầu bằng việc cài Torch/fine-tune ngay. Hoàn thiện A/B và kiểm thiết bị trước.
Phần cứng N3 được ghi là Radeon; tên GPU chưa xác nhận backend tăng tốc chạy được.
Gửi N1 kết quả kiểm thiết bị và ước tính thời gian để chốt D05.

Sau khi quyết định chạy: branch `feat/p2-distilbert` từ `develop` đã tích hợp baseline;
làm `src/model/distilbert_multihead.py`, encoder chung + 8 head, tokenizer checkpoint
tương ứng, không lemmatize. Dùng cùng ID/labels/evaluator như baseline, lưu checkpoint revision.
Kế hoạch tổng dành tối đa 4 giờ thao tác kỹ thuật; YAML đề xuất tối đa 6 giờ máy train
tổng, 2 lượt (smoke + lượt giới hạn), tối đa 3 epoch/lượt. Đây là giới hạn khác loại,
không phải cam kết sẽ hoàn thành. Chưa có thiết bị/ngân sách xác nhận thì ghi chờ D05.
Nếu không chạy được trong giới hạn, ghi `not_run`/`partial`/`failed` đúng thực tế.

## 4. Prompt đầu tiên

```text
Đọc docs/phase-2-nguoi-3.md, docs/data_contract.md, config/model.yaml và validator.
Chỉ triển khai Bước A: Dummy và TF-IDF + tám Logistic Regression, description-only,
dùng split v1 có sẵn, fit train, save/load, fallback một lớp và tests/test_baseline.py.
Không tải NVD/EPSS, không sửa dataset/split, không chạy test cuối hay DistilBERT.
Ghi CLI thực sự đã triển khai và kết quả smoke test; không bịa metric full run.
```

CLI train/evaluate/predict của kế hoạch cũ là mục tiêu triển khai, chưa phải lệnh
chạy được hiện tại. Sau khi code xong, ghi chính xác lệnh đã chạy trong model card.

## 5. Commit, push và giao artifact

Stage từng file đã tạo, có thể commit riêng từng bước. Ví dụ phần A:

```powershell
git status --short
git add src/model/baseline.py tests/test_baseline.py config/model.yaml requirements-model.txt
git diff --cached --check
git diff --cached --stat
git commit -m "feat(model): add dummy and TF-IDF CVSS baselines"
git push -u origin feat/p2-nlp-baseline
```

Bỏ tên file chưa tạo khỏi lệnh add. PR **base `develop`, compare `feat/p2-nlp-baseline`**.
N2 sở hữu scorer/ranking; N3 sở hữu config/model.yaml, model modules, model card và
notebook đánh giá. Muốn đổi scorer thì báo N2, không tạo bản riêng.

Model trong `models/` và prediction trong `data/processed/` được gửi riêng, kèm
SHA-256, model/dataset version và dependencies. Không force-add model lớn lên Git.
Chỉ nạp joblib từ artifact tin cậy do nhóm tạo. Ghi manifest nhỏ trong
`docs/handoffs/phase-2-model.json` sau khi có artifact thật; không điền hash giả.

N1 tái chạy trên máy thứ hai bằng lệnh bạn ghi: import, nạp model, dự đoán mẫu validation,
đối chiếu hash/version và prediction. Chỉ đánh dấu tái chạy thành công khi có kết quả.

Hoàn thành phần N3 khi Dummy/TF-IDF có metric thật, save/load được, prediction đúng schema,
model card/EDA có output, N2 nhận được lỗi validation và DistilBERT có trạng thái rõ.
