# Người 1 — Điều phối dữ liệu và tích hợp Phase 2

Bạn là N1. Dataset `t08-v1.0-20261010` đã khóa; model chưa được huấn luyện.
Phần kiểm dữ liệu, split, duplicate và đóng gói trong kế hoạch N1 đã làm ở cuối
Phase 1. Phần còn lại là giúp N2/N3 bắt đầu, giữ đầu vào nhất quán và kiểm model
chạy lại được trên máy bạn. Không cần train một baseline riêng cạnh tranh với N3.

## 1. Việc làm ngay: gửi đúng gói

N1 tiếp tục trên `develop` cho tài liệu/tích hợp nhỏ như đã thống nhất.
N2 dùng `feat/p2-cvss-scorer`; N3 dùng `feat/p2-nlp-baseline`.

Mở terminal tại đúng repo, không phải thư mục cha:

```powershell
Set-Location -LiteralPath 'C:\Users\LOQ\Desktop\t08-cvss-epss\t08-cvss-epss'
git branch --show-current
git status --short
```

Branch cần là `develop`. File `a` chưa được theo dõi có thể vẫn còn; chỉ stage
file cụ thể liên quan. Nếu có thay đổi khác, xem nội dung trước khi pull/chuyển branch.

Gửi hai bạn **cùng một ZIP**:

`data/processed/phase1_v1_20261010.zip`

Kèm hướng dẫn tương ứng:

- N2: [phase-2-nguoi-2.md](phase-2-nguoi-2.md).
- N3: [phase-2-nguoi-3.md](phase-2-nguoi-3.md).
- Cả hai đọc thêm [kế hoạch chung](phases/phase-2-mo-hinh-nlp.md).

ZIP là 38.599.819 byte. SHA-256:
`215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`.
Không gửi `.env`, API key hoặc `.venv`; mỗi người đã có hướng dẫn môi trường riêng.
ZIP được gửi qua kênh chia sẻ của nhóm; push Git không tự gửi dữ liệu này.

Tin nhắn bạn có thể sao chép để gửi:

```text
Nhóm bắt đầu Phase 2 với dataset t08-v1.0-20261010.
Pull develop, nhận ZIP phase1_v1_20261010.zip và làm theo file phase-2-nguoi-2.md
hoặc phase-2-nguoi-3.md tương ứng. Không cần tải lại NVD/EPSS hay xin API key.
Sau khi giải nén, chạy python trong .venv của mình với -m src.collect.verify_phase1.
Gửi lại dòng PHASE1 RELEASE OK, dataset version và Python version.
N2 bắt đầu kiểm scorer/ranking; N3 bắt đầu Dummy/TF-IDF sau khi đọc gói thành công.
```

## 2. Ghi nhận tiến độ, không cần chờ cả hai cùng xong

Mở [reports/p2_integration_status.md](../reports/p2_integration_status.md).
Chỉ thay trạng thái bằng bằng chứng thật: ngày nhận, commit, log hoặc checksum.
N2 đọc được gói thì N2 bắt đầu ngay; N3 đọc được thì N3 bắt đầu ngay.
Việc N2 chưa phân tích lỗi không chặn N3 train vì chưa có prediction để đọc lỗi.

| Người | Đầu ra đầu tiên cần giao cho bạn | Khi nào |
|---|---|---|
| N2 | Kết quả verifier; test scorer + báo cáo | Sau khi nhận gói, trước phần phân tích lỗi |
| N3 | Kết quả verifier; smoke test Dummy/TF-IDF và save/load | Sau khi nhận gói, trước train/đánh giá đầy đủ |
| N2 | Ranking sơ bộ 396 ID và case study | Làm song song với N3 |
| N3 | Model, dependencies, manifest, validation predictions/metrics | Khi baseline đã chạy |
| N2 | Phân tích ít nhất 10 lỗi validation nếu có đủ | Sau khi N3 giao prediction |

## 3. Trong lúc chờ: chuẩn bị máy tái chạy và chốt tài nguyên

Bạn đã có `.venv`, không tạo lại. Ghi interpreter hiện tại:

```powershell
.\.venv\Scripts\python.exe --version
```

Chưa cần cài toàn bộ `requirements.txt` vì nó gồm cả Torch/Transformers.
Chờ N3 giao `requirements-model.txt` có phiên bản thực chạy được để đồng bộ môi trường.
Đừng tự chọn phiên bản khác rồi coi chênh lệch prediction là lỗi model.

Nếu muốn dùng máy bạn cho DistilBERT, thu thông tin máy trước:

```powershell
Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors
Get-CimInstance Win32_ComputerSystem | Select-Object TotalPhysicalMemory
Get-CimInstance Win32_VideoController | Select-Object Name
```

RAM ở lệnh trên là byte, không phải RAM trống; tên GPU không chứng minh Torch dùng được.
Ghi thêm thời gian máy bạn có thể chạy. Không cần cài Torch chỉ để đọc ba thông tin này.
Sau baseline và khi có thông tin thiết bị, cập nhật D05 trong `docs/decisions.md`:
máy chạy, backend thực kiểm, phạm vi và ngân sách DistilBERT. N3 thực hiện model.
Nếu không đủ tài nguyên, ghi trạng thái mở rộng chưa chạy; Dummy/TF-IDF vẫn là bắt buộc.

Bạn cũng có thể đọc `reports/data_quality.md` và `docs/data_contract.md` để chuẩn bị
giải thích dataset cho báo cáo: 396 ranking; 67.242 ML; 8 mobile đều ở train;
EPSS/KEV khác ngày; không lấy điểm dự đoán thay điểm nguồn trong ranking chính.

## 4. Khi N2 giao code: kiểm tích hợp

Nhận link PR/commit của `feat/p2-cvss-scorer` và báo cáo test. Kiểm phần thay đổi
đúng scorer/test/ranking/case, không đổi split hay gói v1. Không yêu cầu review độc lập.

- Scorer dùng `src.environmental.cvss_base.calculate_base_score`, không có hai bản tính Base.
- Ranking có đúng 396 ID duy nhất từ cohort v1, 3 KEV, đủ version/snapshot/policy.
- Sort CVSS/EPSS có tie-break theo CVE ID; KEV-first theo contract.
- Case mobile giữ điều kiện affected và exposure client; không tự biến thành internet.

Sau khi kiểm và merge PR vào `develop`, cập nhật máy:

```powershell
git switch develop
git pull --ff-only origin develop
```

Chỉ chạy test mới khi file tương ứng đã được N2 tạo và merge:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_cvss tests.test_rankings -v
```

Ghi log/kết quả thực vào bảng tiến độ. Nếu lỗi, xử lý lỗi trước khi đánh dấu đạt.

## 5. Khi N3 giao model: đây là phần kỹ thuật chính còn lại của bạn

Nhận đủ bộ sau, không chỉ một file `.joblib`:

1. Code/commit trên branch N3 và PR về `develop`.
2. `requirements-model.txt`, Python/sklearn/joblib versions thực chạy.
3. Model `baseline.joblib`, model_version và dataset_version.
4. Manifest `docs/handoffs/phase-2-model.json` ghi đường dẫn/kích thước/SHA-256 thực.
5. Validation predictions, metrics và lệnh inference đã chạy, trong model card.

Chỉ nạp model từ artifact tin cậy của nhóm. Kiểm hash **trước** khi load:

```powershell
Get-FileHash -LiteralPath 'models/baseline.joblib' -Algorithm SHA256
```

Lệnh trên dùng sau khi đã đặt file N3 gửi đúng đường dẫn và đối chiếu manifest.
Nếu file đã tồn tại khác hash, giữ riêng hai bản và hỏi rõ version, không chép đè vô thức.

Sau khi tích hợp code N3, cài dependencies đã bàn giao:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-model.txt
```

Tái chạy inference trên **một tập ID validation cố định** có prediction tham chiếu
của N3. Dùng đúng CLI trong model card; CLI `predict` hiện chưa triển khai nên tài liệu
này không giả định tham số chạy. Không cần train lại toàn bộ model để kiểm portability.

Tạo `reports/p2_reproduction_n1.md` sau khi chạy, ghi:

- Ngày, code commit, máy/Python/dependencies, dataset/model version và hash.
- Lệnh thực chạy, danh sách ID validation hoặc đường dẫn + hash của danh sách.
- So tám nhãn, vector và Base Score với N3 sau khi join đúng ID/model_version.
- Số khớp/tổng số; nếu sai, lưu ID và lỗi. Không chỉnh prediction bằng tay.
- Có cần Internet/API/GPU lúc inference không; phải khớp thiết kế artifact.

Không chạy test để giúp N3 chọn cấu hình. Test chỉ đánh giá sau khi N3 đã khóa lựa
chọn; việc bạn xác minh validation/inference không làm phát sinh vòng tuning test.

## 6. File bạn sở hữu và prompt sử dụng

| File | Bạn làm gì |
|---|---|
| `reports/p2_integration_status.md` | Ghi bằng chứng bàn giao và trạng thái thật |
| `reports/p2_reproduction_n1.md` | Tạo khi tái chạy model; không điền trước kết quả |
| `docs/decisions.md` | Ghi quyết định tài nguyên/phạm vi DistilBERT khi có thông tin |
| `docs/phases/phase-2-mo-hinh-nlp.md` | Đánh dấu gate khi thực sự đạt |

N3 sở hữu baseline/evaluator/config model; N2 sở hữu scorer/ranking sơ bộ.
Không đồng thời sửa file của họ khi chưa thống nhất để tránh xung đột.

Prompt khi đã nhận artifact N3:

```text
Đọc docs/phase-2-nguoi-1.md, model card và manifest N3 đã giao.
Kiểm checksum/version trước khi load. Tái chạy inference bằng CLI thật trên
cùng ID validation có kết quả tham chiếu của N3; so theo ID, không theo thứ tự dòng.
Ghi kết quả thật vào reports/p2_reproduction_n1.md. Không retrain, tune bằng test,
sửa nhãn, thay dataset v1 hoặc tự tạo hash/kết quả còn thiếu.
```

## 7. Git và tiêu chí xong phần N1

Lưu riêng từng tài liệu đã hoàn thành; không `git add .`. Ví dụ sau khi ghi tiến độ:

```powershell
git add reports/p2_integration_status.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(phase2): record integration progress"
git push origin develop
```

Thêm `reports/p2_reproduction_n1.md` vào commit khi file đã có bằng chứng thật.
Nếu remote thay đổi, kiểm/tích hợp trước, không force push.

Phần N1 hoàn thành khi: N2/N3 đọc được gói đúng version; code họ tích hợp được;
model chạy lại trên máy N1; artifact/prediction/metrics đúng contract; quyết định
DistilBERT có trạng thái rõ; đầu vào Phase 3 sẵn sàng. Hiện chưa có model nên chưa
thể đánh dấu hoàn tất Phase 2, nhưng bạn có thể làm ngay bước 1–3.
