# Phase 0 — Hướng dẫn riêng cho Người 3: môi trường và thiết kế mô hình AI

**Người nhận:** Người 3 — ML/NLP và demo.  
**Branch làm việc:** `chore/p0-model-config`. **Branch tích hợp:** `develop`.  
**Mục tiêu thời gian:** khoảng 4 giờ làm việc, bố trí trong 1–2 ngày; ghi thời hạn thực tế với nhóm.  
**Môi trường hướng dẫn:** Windows, VS Code, PowerShell. Cập nhật hướng dẫn: 01/10/2026.

File này đủ để bắt đầu từ máy riêng. Mỗi người tự tạo `.venv`; API key NVD chỉ phục vụ lấy dữ liệu,
không phải key để train mô hình. Nhóm không yêu cầu review độc lập trước merge: tự kiểm tra,
ghi kết quả trong PR và tích hợp khi có quyền. N1 tổng hợp các quyết định thiết kế dùng chung.

## 1. Đầu ra cần có để kết thúc Phase 0

Nhiệm vụ của bạn là thiết kế và chuẩn bị thực nghiệm dự đoán **tám thành phần CVSS 3.1 từ mô tả CVE**.
Mục tiêu bảo mật của đồ án vẫn là giải thích CVSS cao không tự quyết định thứ tự vá.

| Việc bắt buộc | Đầu ra |
|---|---|
| Lấy repo, tạo branch, môi trường riêng chạy được | `.venv` trên máy; import được thư viện dữ liệu và scikit-learn |
| Kiểm kê CPU/RAM/GPU thực tế | Ghi trong `docs/model-plan.md`, phần môi trường |
| Chốt giao diện mô hình, nhãn và cấu hình ban đầu | Tạo `config/model.yaml` |
| Thiết kế baseline, DistilBERT, split, đánh giá và xử lý dữ liệu khó | Tạo `docs/model-plan.md` |
| Đề xuất phạm vi DistilBERT và ngân sách chạy | Ghi rõ phương án, căn cứ phần cứng và điểm cần N1 chốt |
| Phác thảo demo bằng chữ | Một mục trong `docs/model-plan.md`; chưa viết giao diện |
| Bàn giao qua Git | Commit/push, PR vào `develop` |

**Chưa cần train, tải checkpoint lớn hoặc công bố F1 trong Phase 0.** Huấn luyện thuộc Phase 2;
kiểm tra đầy đủ mẫu và phân bố dữ liệu thuộc Phase 1. Đọc thử mẫu có thể làm ngay để kiểm môi trường.

N1 đã chuẩn bị pilot 543 CVE công bố trong 01–07/01/2023: 451 ứng viên có mô tả/vector,
92 Rejected. Mẫu bàn giao nhỏ gồm 30 ứng viên và 5 Rejected. Đây là snapshot thử, chưa xác nhận
phạm vi Web/mobile, chưa ghép EPSS/KEV và chưa có split chính thức.
Xem [metadata mẫu](../data/sample/metadata.json) và [bàn giao pilot](pilot-handoff.md).

## 2. Lấy repo và tạo branch — khoảng 15 phút

### 2.1. Chuẩn bị

- Dùng tài khoản GitHub riêng có quyền vào repo `thinh247-10/t08-cvss-epss` do N1 cấp.
- Mở VS Code → Terminal → New Terminal, chọn PowerShell.
- Nếu chưa có Git, cài từ [Git for Windows](https://git-scm.com/download/win), mở lại terminal.
- Nếu chưa có Python, cài từ [Python cho Windows](https://www.python.org/downloads/windows/), kiểm tra lại sau khi mở terminal mới.

```powershell
git --version
python --version
```

N1 đã chạy phần dữ liệu với Python 3.14.3. Nếu dùng bản khác, ghi phiên bản và kết quả cài thư viện
trong model plan; không mặc định Python mới hơn là không dùng được hoặc CPU là không làm được đồ án.
Khả năng chạy GPU phải kiểm riêng khi cài PyTorch ở bước triển khai model.

### 2.2. Nếu CHƯA clone repo

Đứng ở thư mục cha muốn đặt dự án:

```powershell
git clone --branch develop https://github.com/thinh247-10/t08-cvss-epss.git
cd t08-cvss-epss
```

Đăng nhập tài khoản của bạn nếu Git yêu cầu. Nếu báo không có quyền, gửi N1 tên tài khoản và lỗi;
không dùng chung mật khẩu hay tạo một repo khác thay repo nhóm.

### 2.3. Nếu ĐÃ clone repo

Tại thư mục có `README.md`, `src`, `config`:

```powershell
Get-Location
git status --short
git remote -v
```

Nếu có thay đổi cá nhân chưa lưu, xử lý trên branch hiện tại trước khi chuyển; không xóa/reset
chỉ để làm sạch. Khi sẵn sàng:

```powershell
git fetch origin
git switch develop
git pull --ff-only origin develop
```

Nếu máy chưa có branch `develop` và Git không tự tạo tracking branch:

```powershell
git switch --track origin/develop
```

### 2.4. Tạo branch N3

Chạy một lần từ `develop`:

```powershell
git switch -c chore/p0-model-config
git branch --show-current
```

Kết quả cuối phải là `chore/p0-model-config`. Nếu branch đã tồn tại từ buổi trước,
dùng `git switch chore/p0-model-config` thay vì `-c`.

## 3. Tạo `.venv` riêng và cài thư viện — khoảng 20–30 phút

Mỗi người tạo môi trường trên máy mình từ requirements. Hướng dẫn dùng trực tiếp interpreter
trong `.venv`, nên không cần kích hoạt `Activate.ps1` hoặc đổi PowerShell execution policy.
[Python venv](https://docs.python.org/3/library/venv.html) giải thích cách tạo và dùng môi trường.

```powershell
if (-not (Test-Path -LiteralPath ".venv")) {
    python -m venv .venv
}
```

Nếu máy có launcher `py` nhưng `python` chưa chạy được, kiểm tra `py --version` và dùng
`py -m venv .venv` cho bước tạo. Các lệnh tiếp theo luôn gọi Python trong repo:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
.\.venv\Scripts\python.exe -m pip install "scikit-learn>=1.3.0"
.\.venv\Scripts\python.exe -c "import requests, dotenv, pandas, pyarrow, yaml, sklearn; print('ML PHASE 0 ENV OK')"
```

Ghi phiên bản đã chạy vào model plan:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -c "import sys; print(sys.executable)"
.\.venv\Scripts\python.exe -m pip show pandas pyarrow PyYAML scikit-learn
```

Interpreter phải nằm trong `.venv` của repo. Đây là môi trường chuẩn bị dữ liệu/baseline.
Torch/Transformers và checkpoint được chuẩn bị ở bước triển khai sau khi kiểm phần cứng;
không cần cài toàn bộ `requirements.txt` để kết thúc Phase 0.
N1 quản lý requirements chung; nếu bạn cần thay đổi dependency, ghi đề xuất và phiên bản đã thử.

## 4. API key và `.env` — hướng dẫn đầy đủ, bước tùy chọn

### 4.1. Phân biệt đúng mục đích

| Việc | Vai trò của API key |
|---|---|
| Đọc CSV/JSON mẫu trong repo | Không cần key |
| TF-IDF và Logistic Regression chạy trên dữ liệu đã có | Không cần NVD key |
| Fine-tune DistilBERT trên máy hoặc môi trường tính toán đã chọn | NVD key không tham gia huấn luyện |
| Tự gọi NVD để lấy CVE mới | Có thể cấu hình NVD key riêng |

Checkpoint dự kiến là [distilbert/distilbert-base-uncased](https://huggingface.co/distilbert/distilbert-base-uncased).
Đó là mô hình nền để fine-tune; việc lấy dữ liệu NVD và tải mô hình là hai công việc riêng.
Không yêu cầu mua một API sinh văn bản để thực hiện thiết kế này.

### 4.2. Đăng ký NVD key nếu muốn tự thử collector

1. Mở [NVD — Request an API Key](https://nvd.nist.gov/developers/request-an-api-key).
2. Nhập email của bạn và các thông tin form yêu cầu, thực hiện xác thực trên trang.
3. Kiểm tra email và thư rác; làm theo hướng dẫn NVD để nhận/kích hoạt key.
4. Lưu key trên máy riêng. Không xin key của N1 và không đưa key vào model config.

Thực hiện theo biểu mẫu/email hiện tại của NVD; không giả định thời hạn cấp hoặc kích hoạt.
Nếu chưa nhận key, tiếp tục công việc offline: đây không phải điều kiện chặn Phase 0.

### 4.3. Tạo cấu hình local

```powershell
if (-not (Test-Path -LiteralPath ".env")) {
    Copy-Item -LiteralPath ".env.example" -Destination ".env"
} else {
    Write-Output ".env da ton tai; mo file de kiem tra tren may cua ban."
}
```

Mở `.env` trong VS Code, điền key thật thay chỗ giữ chỗ:

```dotenv
NVD_API_KEY=KEY_RIENG_CUA_BAN
```

Nếu chưa có key, để `NVD_API_KEY=` trống. Đừng chạy API với `your-key-here` hay
`KEY_RIENG_CUA_BAN`, vì đây chỉ là giá trị mẫu.

```powershell
.\.venv\Scripts\python.exe -c "from dotenv import load_dotenv; import os; load_dotenv('.env'); k=(os.getenv('NVD_API_KEY') or '').strip(); print('KEY CONFIGURED' if k and k not in ('your-key-here','KEY_RIENG_CUA_BAN') else 'KEY NOT CONFIGURED')"
git check-ignore -v .env .venv/
git ls-files -- .env ".venv/*"
```

Lệnh đầu chỉ báo có cấu hình, không xác nhận key hợp lệ trên server. `check-ignore` cần chỉ ra
quy tắc bỏ qua, còn `git ls-files` cần không liệt kê `.env`/môi trường. Nếu đang được Git theo dõi,
báo N1 xử lý trước khi push. Chia sẻ kết quả trạng thái, không gửi key, ảnh chứa key hoặc header.

### 4.4. Kiểm tra API một CVE nếu cần

```powershell
.\.venv\Scripts\python.exe -m src.collect.explore_apis CVE-2021-44228
```

Script hiện tại gửi NVD key tới NVD; phần EPSS/KEV không dùng key đó.
Đây là thử kết nối và schema, không phải bước train. CVE mẫu này ngoài khoảng 2023–2024 dự kiến.
Nếu gặp HTTP lỗi, ghi mã lỗi/endpoint để gửi N1; không cần tải lại dataset lớn cho Phase 0.

## 5. Kiểm kê phần cứng thực tế — khoảng 15 phút

Chạy trên máy của bạn và ghi kết quả vào mục môi trường trong `docs/model-plan.md`:

```powershell
Get-CimInstance Win32_Processor | Select-Object Name,NumberOfCores,NumberOfLogicalProcessors
Get-CimInstance Win32_ComputerSystem | Select-Object @{Name="RAM_GB";Expression={[math]::Round($_.TotalPhysicalMemory/1GB,1)}}
Get-CimInstance Win32_VideoController | Select-Object Name
```

Nếu có NVIDIA và `nvidia-smi`:

```powershell
if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
    nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
} else {
    Write-Output "Chua co nvidia-smi; ghi GPU/VRAM chua xac nhan neu can."
}
```

Lệnh này đọc tên GPU/VRAM/driver, không chứng minh PyTorch đã dùng được CUDA.
Nguồn tra lệnh: [NVIDIA SMI](https://docs.nvidia.com/deploy/nvidia-smi/index.html).
Không có NVIDIA hoặc chưa biết CUDA thì ghi đúng thực trạng và lập phương án CPU cho baseline;
không dành cả Phase 0 sửa GPU. Việc cài và thử torch thuộc bước chuẩn bị chạy DistilBERT.

Mục môi trường cần ghi: hệ điều hành, Python, phiên bản thư viện, CPU, RAM, GPU/VRAM nếu xác nhận,
khả năng dành thời gian/máy để train, hạn chế hiện có. Không ghi “GPU OK” khi chỉ mới thấy tên card.

## 6. Đọc tài liệu và chốt bài toán — khoảng 30 phút

Đọc [Phase 0 chung](phases/phase-0-pham-vi-va-thiet-ke.md), [data contract](data_contract.md),
`config/project.yaml`, `src/model/baseline.py` và `src/model/distilbert_multihead.py`.
Hai file model hiện mới có TODO: chưa có trainer hoạt động.

Luồng cần thiết kế:

```text
Mô tả CVE tiếng Anh
    -> mô hình dự đoán AV / AC / PR / UI / S / C / I / A
    -> ghép vector CVSS 3.1 hợp lệ
    -> tính Base Score bằng scorer chuẩn dùng chung
```

| Thành phần | Quy ước của nhóm |
|---|---|
| Input của model | Chỉ `description`; CVE ID/ngày dùng quản lý và split, không làm feature |
| Nhãn | Tám thành phần lấy từ vector CVSS 3.1 của nguồn đã chọn |
| Không làm feature | Điểm/vector nguồn, EPSS, KEV, nhãn do nhóm gán hoặc kết quả cần dự đoán |
| Nguồn nhãn | Giữ `cvss_source`, `cvss_type`, raw để truy vết; N1 lo chọn nguồn theo contract |
| Kết quả AI | Vector/điểm ước lượng; không âm thầm thay CVSS nguồn trong ranking chính |

Thứ tự lớp phải cố định và lưu cùng model artifact:

| Metric | Lớp theo thứ tự đề xuất | Số lớp |
|---|---|---:|
| AV | N, A, L, P | 4 |
| AC | L, H | 2 |
| PR | N, L, H | 3 |
| UI | N, R | 2 |
| S | U, C | 2 |
| C | N, L, H | 3 |
| I | N, L, H | 3 |
| A | N, L, H | 3 |

Đối chiếu nhãn và cách tính điểm với [FIRST CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document).
Không trộn vector 2.0/3.0/4.0 vào cùng bộ nhãn này. Điểm dự đoán được tính từ vector;
chưa cần thiết kế một mô hình hồi quy điểm riêng.

## 7. Tạo `config/model.yaml` — khoảng 30 phút

**Chức năng file:** giữ cấu hình thí nghiệm để người khác biết đầu vào/đầu ra, nhãn, seed và
các giới hạn đã chọn. N3 sở hữu file này; N1 giữ cấu hình dữ liệu chung trong `config/project.yaml`.

Mẫu dưới đây là **thiết kế ban đầu**, các tham số chưa được chọn bằng thực nghiệm.
Trainer hiện chưa có code đọc YAML này; phải triển khai và kiểm tra ở Phase 2.

```yaml
schema_version: "0.1"
status: "phase0_design"
seed: 42

data:
  project_config: "config/project.yaml"
  sample: "data/sample/cves_sample.csv"
  input_column: "description"
  cvss_version: "3.1"
  target_metrics: ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
  split_source: "config/project.yaml"
  rejected_policy: "exclude_from_ml_keep_in_master"
  missing_label_policy: "exclude_from_ml_keep_in_master"

label_order:
  AV: ["N", "A", "L", "P"]
  AC: ["L", "H"]
  PR: ["N", "L", "H"]
  UI: ["N", "R"]
  S: ["U", "C"]
  C: ["N", "L", "H"]
  I: ["N", "L", "H"]
  A: ["N", "L", "H"]

dummy:
  strategy: "most_frequent"

baseline:
  vectorizer: "tfidf"
  ngram_range: [1, 2]
  min_df: 2
  max_features: 50000
  classifier: "logistic_regression"
  class_weight: "balanced"
  max_iter: 1000
  single_class_fallback: "dummy"

distilbert:
  checkpoint: "distilbert/distilbert-base-uncased"
  architecture: "shared_encoder_eight_heads"
  lemmatize: false
  max_length: 256
  epochs_cap: 3
  max_runs: 2
  scope_decision: "pending"
  training_time_budget_hours: null

evaluation:
  per_metric: ["accuracy", "macro_f1", "per_class_f1", "support"]
  vector: ["exact_vector_accuracy"]
  score: ["mae", "rmse", "score_coverage", "invalid_prediction_count"]
  macro_f1_labels: "all_declared_labels"
  zero_division: 0
  test_usage: "final_evaluation_only"

artifacts:
  baseline: "models/baseline.joblib"
  distilbert_dir: "models/distilbert"
  predictions: "data/processed/predictions.csv"
  metrics: "reports/model_metrics.json"
```

Việc bạn phải hoàn thiện thêm:

1. Giải thích các cấu hình trong `docs/model-plan.md`; không sao chép rồi coi đã chốt.
2. Đề xuất `scope_decision` là `required` hoặc `timeboxed_extension`, kèm căn cứ máy/thời gian.
   Thiết kế hiện tại yêu cầu baseline, còn vai trò bắt buộc của DistilBERT đang chờ chốt ở D05.
3. Điền ngân sách giờ thực tế bạn đề xuất cho DistilBERT. Phân biệt rõ đề xuất của N3 với quyết định
   toàn nhóm; gửi N1 để tổng hợp. Nếu chưa thống nhất, ghi câu hỏi và mốc chốt, không tự ghi đã thống nhất.
4. Giữ tham chiếu split về `config/project.yaml`; không tạo một bộ ngày chia khác ở file riêng.

## 8. Tạo `docs/model-plan.md` — khoảng 60 phút

**Chức năng file:** giải thích vì sao chọn thiết kế, ai nhận artifact nào và cách kiểm chứng kết quả.
Nội dung đủ để N1 chuẩn bị dữ liệu đúng và N2 hiểu AI đang đo severity.

### 8.1. Môi trường và giới hạn tài nguyên

Ghi các kết quả mục 3/5, thời gian có thể chạy máy, điểm chưa xác nhận và phương án khi không có GPU.
Các thông số chưa đo để “chưa xác nhận”; không điền số RAM/VRAM hoặc thời gian train dự đoán như số đã đo.

### 8.2. Ba mức mô hình

| Mức | Thiết kế cần mô tả | Vai trò |
|---|---|---|
| Dummy | Dự đoán lớp phổ biến nhất của từng metric, fit trên train | Mốc tối thiểu để biết mô hình có vượt đoán lớp thường gặp hay không |
| TF-IDF + Logistic Regression | Vectorizer fit trên train, tám bộ phân loại đầu ra; xử lý target chỉ có một lớp | Baseline bắt buộc trước mô hình sâu |
| DistilBERT | Một encoder dùng chung, tám head phân loại; mỗi head một số lớp theo bảng nhãn | Fine-tune theo ngân sách đã chốt, so cùng split với baseline |

[DummyClassifier](https://scikit-learn.org/stable/modules/generated/sklearn.dummy.DummyClassifier.html)
là mốc so sánh không khai thác nội dung đầu vào. Với DistilBERT, tham khảo
[tài liệu mô hình](https://huggingface.co/docs/transformers/model_doc/distilbert) và checkpoint đã chọn.
Không dùng nguyên head sentiment hai lớp có sẵn để thay cho tám head CVSS.

Đối với DistilBERT, dùng tokenizer tương ứng checkpoint. Thiết kế mặc định không lemmatize;
việc biến đổi mạnh câu đầu vào phải là thí nghiệm có lý do. Nếu dùng class weights cho loss,
tính từ train riêng cho mỗi metric. Không khẳng định multi-task tốt hơn baseline trước khi đo.

### 8.3. Split, dữ liệu thiếu và leakage

Ghi kế hoạch tạm thời từ `config/project.yaml`: train 2023, validation nửa đầu 2024,
test nửa cuối 2024. Khóa ranh giới sau audit dữ liệu và trước khi đánh giá test.

- Fit TF-IDF, class weights và mọi bước học tham số chỉ trên train.
- Validation dùng chọn cấu hình; không dùng test để chọn tham số, số epoch hoặc đổi split.
- Rejected hoặc thiếu mô tả/nhãn không vào ML; N1 vẫn giữ trong master để phân tích missing.
- Một target chỉ có một lớp trong train: ghi fallback Dummy; không gọi Logistic Regression trên target đó.
- Lớp không xuất hiện trong train: báo rõ không có dữ liệu học lớp đó; không xóa mẫu test khó để đẹp điểm.
- Kiểm tra mô tả trùng/nhóm sản phẩm giữa các split trước khi khóa dataset.
- NVD tải hiện tại có thể đã sửa mô tả sau ngày công bố. Chia theo `published` không tự phục hồi
  dữ liệu lịch sử; báo giới hạn này, không gọi kết quả là dự báo hồi cứu không nhìn trước.

### 8.4. Đánh giá cần báo những gì?

| Kết quả | Cách trình bày |
|---|---|
| Từng metric | Accuracy, macro-F1, F1 từng lớp và số mẫu hỗ trợ |
| Toàn vector | Tỷ lệ dự đoán đúng đồng thời cả tám thành phần |
| Điểm Base | MAE/RMSE sau khi tính từ vector hợp lệ, cùng số mẫu tính được và số lỗi |
| So sánh | Dummy, TF-IDF và DistilBERT trên cùng split/version; nếu không chạy model nào thì ghi chưa chạy |

Thiết kế YAML dùng toàn bộ danh sách lớp đã khai báo khi tính macro-F1, `zero_division=0`.
Lớp thiếu mẫu vẫn phải ghi support bằng 0; cần giải thích quy ước này trong báo cáo.
Tham khảo cách chọn `labels`/`average`/`zero_division` ở
[scikit-learn f1_score](https://scikit-learn.org/stable/modules/generated/sklearn.metrics.f1_score.html).

N2 và N1 thống nhất scorer CVSS dùng chung trước khi đánh giá điểm. N3 không viết một công thức
tính điểm khác trong notebook. Đánh giá theo nhãn nguồn được chọn, không ngụ ý nhãn nguồn luôn đúng tuyệt đối.

### 8.5. Artifact dự kiến và phác thảo demo

Liệt kê đường dẫn trong data contract: model, label mapping/config, `predictions.csv`,
`model_metrics.json`, model card. Nêu khóa CVE/model/version và các cột `pred_AV`…`pred_A`,
`predicted_vector`, `predicted_base_score`, trạng thái lỗi. Chưa cần tạo file kết quả giả.

Phác thảo bằng chữ ba màn hình demo Phase 4:

1. Dataset/ranking: đọc artifact đã tính, hiện ngày snapshot và nguồn điểm.
2. Case theo tài sản: trình bày applicability và lý do ưu tiên.
3. Nhập mô tả → ước lượng vector/điểm, ghi rõ là kết quả mô hình; chưa có nhãn thật thì không hiển thị accuracy cho CVE đó.

### 8.6. Những quyết định gửi N1

Ghi kết luận về môi trường, input/nhãn, split tạm thời, chính sách lớp hiếm, metric và phạm vi DistilBERT.
Đánh dấu nội dung đã thống nhất, nội dung mới là đề xuất và câu hỏi còn mở. N1 cập nhật
`docs/decisions.md`, `docs/data_contract.md` và cấu hình chung; N3 không sửa cùng lúc các file N1 đang tổng hợp.

## 9. Đọc thử gói mẫu — nên làm, chưa cần audit đầy đủ ở Phase 0

Chạy tại gốc repo để kiểm tra loader:

```powershell
.\.venv\Scripts\python.exe -c "import pandas as pd; from src.collect.prepare_handoff import SAMPLE_DTYPES; df=pd.read_csv('data/sample/cves_sample.csv', dtype=SAMPLE_DTYPES, keep_default_na=False, na_values=[''], true_values=['True'], false_values=['False']); print('rows:',len(df)); print(df['has_cvss31_label'].value_counts(dropna=False)); print('KEV unknown:',df['is_kev'].isna().sum())"
```

Với gói mẫu hiện tại: 35 dòng, 30 nhãn True, 5 False và 35 giá trị KEV chưa biết.
Mẫu đã có trong Git nên không cần raw/Parquet lớn từ máy N1 để chạy lệnh này.
Chưa cần chạy `prepare_handoff.py` trên máy bạn vì script tạo mẫu cần snapshot raw của N1.

Trong [thống kê pilot](../reports/pilot_label_distribution.json), 451 ứng viên hiện có chỉ một mẫu
AV:P, sáu mẫu A:L và mười mẫu AC:H. Đây là lý do cần audit lớp hiếm, không phải kết quả chất lượng AI.
Mẫu 30 dòng có thể thiếu lớp; không train/test ngẫu nhiên trên 35 dòng bàn giao để công bố F1.

Sang Phase 1, mới làm đầy đủ `reports/pilot_ml_audit.md` theo [hướng dẫn bàn giao](pilot-handoff.md).

## 10. Prompt hỗ trợ thiết kế — mỗi lần một việc

### Prompt A — config mô hình

```text
Tôi là Người 3 của T08, Phase 0, branch chore/p0-model-config.
Đọc docs/data_contract.md, config/project.yaml và hai file src/model hiện có.
Chỉ tạo config/model.yaml cho input description, tám metric CVSS 3.1,
Dummy + TF-IDF/Logistic Regression và DistilBERT shared encoder/eight heads.
Giữ label order cố định, tham chiếu split từ project.yaml. Không train, tải checkpoint,
đổi ngày split, dùng EPSS/KEV làm feature hay tạo số đo kết quả.
Phân biệt tham số thiết kế ban đầu với tham số đã được thực nghiệm lựa chọn.
```

### Prompt B — kế hoạch thực nghiệm

```text
Tạo docs/model-plan.md dựa trên config/model.yaml và data contract.
Bao gồm input/output, ba mức model, chống leakage, missing/Rejected, lớp hiếm,
fallback nếu train chỉ một lớp, metric/label policy, artifact và demo phác thảo.
Phần phần cứng dùng đúng kết quả tôi cung cấp, mục chưa có ghi chưa xác nhận.
Không khẳng định DistilBERT tốt hơn baseline trước khi đo. Ghi phạm vi/ngân sách
DistilBERT là đề xuất cần N1 tổng hợp nếu nhóm chưa chốt.
Chỉ viết tài liệu; chưa sửa code model hoặc các file chung của N1.
```

Sau khi dùng AI, bạn phải tự giải thích được vì sao không dùng EPSS/KEV làm feature,
vì sao cần Dummy và vì sao không dùng test để chỉnh model.

## 11. Tự kiểm tra rồi commit/push

Sau khi đã tạo `config/model.yaml`, kiểm cú pháp và đủ target:

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; import yaml; c=yaml.safe_load(Path('config/model.yaml').read_text(encoding='utf-8')); expected={'AV','AC','PR','UI','S','C','I','A'}; assert set(c['data']['target_metrics'])==expected; assert set(c['label_order'])==expected; assert c['data']['input_column']=='description'; assert c['data']['cvss_version']=='3.1'; print('MODEL CONFIG OK')"
git diff --check
git diff --stat
git status --short
```

Lệnh kiểm không chứng minh trainer đã có hoặc thiết kế đã đúng toàn bộ; đọc lại từng lớp và policy.
Mở Markdown Preview của `docs/model-plan.md` để kiểm bảng/link, rà thông số còn để trống.

Stage hai đầu ra N3:

```powershell
git add config/model.yaml docs/model-plan.md
git diff --cached --stat
git diff --cached --name-only
git commit -m "chore(p0): define model configuration and experiment plan"
git push -u origin chore/p0-model-config
```

Nếu Git yêu cầu danh tính, cấu hình trong repo bằng tên/email thật rồi chạy lại commit:

```powershell
git config user.name "TEN_CUA_BAN"
git config user.email "EMAIL_CUA_BAN"
```

Tạo PR trên GitHub:

- **Base:** `develop`.
- **Compare:** `chore/p0-model-config`.
- **Tiêu đề:** `[Phase 0][N3] Cấu hình mô hình và thiết kế thực nghiệm`.
- **Mô tả:** input/nhãn, baseline/DistilBERT, split/evaluation, môi trường đã kiểm, quyết định còn mở;
  ghi rõ chưa huấn luyện và chưa có số đo chất lượng.

Tự kiểm Files changed. Nhóm không bắt buộc một lượt review độc lập trước merge.
Nếu có quyền, Squash and merge → Confirm; nếu thiếu quyền, gửi link PR cho N1 tích hợp.
Sau khi PR hiển thị Merged:

```powershell
git switch develop
git pull --ff-only origin develop
```

Sang Phase 1 dùng branch `test/p1-data-audit` từ `develop` mới để audit mẫu/dữ liệu.
Huấn luyện và demo thực hiện theo các phase sau, không cần tạo các branch đó ngay bây giờ.

## 12. Checklist kết thúc Phase 0 của N3

- [ ] Có `.venv` riêng, import được dữ liệu + scikit-learn, ghi phiên bản thật.
- [ ] Đã ghi CPU/RAM/GPU thực tế và các giới hạn; không nhầm có GPU với CUDA đã hoạt động.
- [ ] API key: biết cách cấu hình riêng khi cần; thiếu key không chặn công việc offline.
- [ ] `config/model.yaml` có input, CVSS 3.1, tám label mapping, seed và tham chiếu split.
- [ ] Có thiết kế Dummy, TF-IDF và DistilBERT; phân biệt baseline nhiều bộ phân loại với encoder chung/tám head.
- [ ] `docs/model-plan.md` giải thích leakage, missing/Rejected, lớp hiếm và fallback.
- [ ] Đã nêu quy ước macro-F1, support, exact-vector, MAE/RMSE và cách báo lỗi prediction.
- [ ] Có đề xuất rõ về phạm vi/ngân sách DistilBERT; đánh dấu đúng phần chưa được nhóm chốt.
- [ ] Đã phác thảo artifact/demo và liệt kê yêu cầu dữ liệu gửi N1.
- [ ] Hai file đầu ra đã commit/push; PR đã tích hợp hoặc gửi N1 nếu thiếu quyền merge.

Khi đạt các mục này, phần thiết kế Phase 0 của bạn hoàn tất; N1 tổng hợp quyết định chung.
Không cần đợi model train xong, có GPU hoạt động hoặc audit đủ mọi CVE mới báo xong Phase 0.

Mẫu thông báo bàn giao để tự gửi cho nhóm:

```text
N3 đã hoàn thành thiết kế Phase 0.
Branch/PR: <link>
Đầu ra: config/model.yaml, docs/model-plan.md.
Môi trường: <Python/thư viện/CPU/RAM/GPU và phần chưa xác nhận>.
Đề xuất phạm vi DistilBERT và ngân sách: <nội dung cụ thể>.
Điểm cần N1 tổng hợp/chốt: <nội dung cụ thể>.
Phase 1 tiếp theo: đọc mẫu, kiểm dtype/nhãn và audit dữ liệu trước khi train.
```
