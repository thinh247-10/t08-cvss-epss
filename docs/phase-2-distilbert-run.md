# Thử nghiệm DistilBERT có giới hạn — N1 chạy thay N3

**Đã chạy xong ngày 17/10/2026.** Xem [kết quả thật](../reports/p2_distilbert_run.md)
và [gói bàn giao](phase-2-completion.md). Các lệnh train bên dưới là hồ sơ tái lập;
không chạy lại vào thư mục đã khóa để thay kết quả test.

Demo offline với model đã có (từ thư mục gốc repo):

```powershell
.\.venv\Scripts\python.exe -m src.model.predict_distilbert --bundle data/processed/p2_distilbert_20261017 --description "A remote attacker can execute arbitrary code."
```

Mặc định inference dùng CPU, kiểm checksum trước khi nạp model, không cần API key.

Phần mở rộng dùng cùng 67.242 CVE, split và label map của release v1. Đây là
thử nghiệm bổ sung sau baseline; không sửa baseline, không chọn theo điểm test.

## Cấu hình đã khai báo

`config/distilbert.yaml`: một encoder DistilBERT pretrained dùng chung, tám head
linear từ token đầu tiên, dropout 0,2, mean của tám weighted cross entropy.
Trọng số balanced tính riêng từ train; lớp vắng train có trọng số 0 và vẫn được
báo khi đánh giá. Max length 256; không lemmatize; dùng cùng quy tắc che CVSS
rõ ràng trong mô tả như baseline. Chỉ mô tả là feature.

Một epoch cố định, learning rate 2e-5, AdamW, weight decay 0,01, warmup 10%,
batch 8, tích lũy gradient 4, clip gradient 1, FP16, seed 42. Đây là cấu hình
định trước cho thử nghiệm giới hạn, không phải kết quả tối ưu. Không thử nhiều
epoch rồi lựa theo test. Validation báo riêng; chỉ mở test sau khi khóa model.

Một smoke run 20 batch train kiểm tra CUDA, loss hữu hạn, bộ nhớ và save/load.
Ước tính chi phí toàn bộ bằng thời gian smoke mỗi batch × số batch train × 2,5
để dự phòng inference, ghi file và máy chậm do nhiệt. Full run chỉ được phép nếu
ước tính cùng smoke dưới 6 giờ máy. Thời gian thật có thể khác ước tính.

## File và lệnh

- `src/model/distilbert_multihead.py`: kiến trúc, tokenization, trọng số/loss,
  save/load safetensors, prediction theo schema CVSS chung.
- `src/model/run_distilbert.py`: tải checkpoint một lần, khóa revision và hash;
  smoke/train, log, validation, khóa trước test, xuất metric và manifest.
- `tests/test_distilbert.py`: tiny encoder offline, không tải model hay train v1.

Chạy từ thư mục repo với môi trường đã cài `requirements-distilbert.txt`:

```powershell
.\.venv\Scripts\python.exe -m src.model.run_distilbert prepare
.\.venv\Scripts\python.exe -m src.model.run_distilbert smoke --output data/processed/p2_distilbert_smoke_20261017
.\.venv\Scripts\python.exe -m src.model.run_distilbert train --output data/processed/p2_distilbert_20261017 --smoke-report data/processed/p2_distilbert_smoke_20261017/smoke.json
```

Các output từ chối ghi đè. Không xóa lock để chạy lại test. `prepare` cần mạng;
smoke và train dùng model/tokenizer đã tải, không gọi NVD/EPSS/KEV hay đọc API key.
Gói pretrained dùng revision SHA cụ thể từ Hugging Face, không dùng mã remote.

Kết quả thật và quyết định gate sẽ ghi tại `reports/p2_distilbert_run.md` khi
thử nghiệm kết thúc. Có code hoặc cài thư viện không đồng nghĩa đã train thành công.

Tài liệu kỹ thuật đã đối chiếu:
[PyTorch Windows/CUDA](https://pytorch.org/get-started/locally/),
[DistilBERT hidden states](https://huggingface.co/docs/transformers/v4.46.0/model_doc/distilbert).
