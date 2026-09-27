# T08 — Dự đoán mức độ nghiêm trọng và ưu tiên vá lỗ hổng: CVSS vs EPSS

> Đồ án môn học — Chương C3 (Đánh giá tác động, thang đo rủi ro)

Kế hoạch nhóm: [Lộ trình 30 ngày, 6 phase và phân công chi tiết cho 3 người](docs/05-ke-hoach-phan-cong.md).

> Bắt đầu từ [Phase 0 — Phạm vi Web/mobile và thiết kế](docs/phases/phase-0-pham-vi-va-thiet-ke.md).
> Các module nghiệp vụ hiện chủ yếu là TODO; lệnh chạy bên dưới cần được hoàn thiện/đối chiếu theo kế hoạch trước khi sử dụng. Schema bàn giao: [data contract](docs/data_contract.md).

Quy trình làm nhóm: [chia branch, commit, push và Pull Request](docs/06-git-workflow.md).

## Câu hỏi nghiên cứu

Đồ án này **không** nhằm xây dựng một mô hình học máy tốt nhất. Mô hình NLP ở đây là
một công cụ phục vụ câu hỏi bảo mật cốt lõi:

> **Tại sao "CVSS cao" không đồng nghĩa với "cần vá trước"?
> Và một tổ chức nên ưu tiên vá lỗ hổng như thế nào?**

Bốn câu hỏi con:

| # | Câu hỏi | Phương pháp |
|---|---------|-------------|
| RQ1 | Có thể ước lượng tám thành phần CVSS v3.1 từ mô tả CVE chính xác đến đâu? | Baseline NLP, mô hình đa nhiệm nếu đủ thời gian và phân tích lỗi |
| RQ2 | Các thang đo ưu tiên (CVSS / EPSS / KEV) bất đồng với nhau ở đâu trong thực tiễn? | Phân tích xếp hạng, vẽ biểu đồ tương quan và đánh giá sự sai lệch |
| RQ3 | Bối cảnh hệ thống (White/Gray-box) làm thay đổi mức rủi ro như thế nào so với CVSS tĩnh? | Áp dụng CVSS Environmental Metrics trên mô hình kiến trúc giả định |
| RQ4 | Quy trình ưu tiên vá nào phù hợp với hệ thống Web/mobile giả định? | Xây dựng báo cáo phân tích bảo mật và Patch Prioritization Playbook |

**Sản phẩm trọng tâm là RQ2–RQ4 ở góc độ bảo mật.** Mô hình AI trong RQ1 là phương pháp hỗ trợ ước lượng severity; kết quả dự đoán không tự quyết định CVE nào phải vá trước.

## Bối cảnh: tại sao đề tài này có ý nghĩa thực tế

- CVSS đo **mức nghiêm trọng nếu bị khai thác**, không đo **khả năng bị khai thác**.
- EPSS đo xác suất bị khai thác trong 30 ngày tới, nhưng không biết gì về hệ thống của bạn.
- KEV ghi nhận lỗ hổng đã bị khai thác theo tiêu chí của catalog; CVE không có trong KEV không phải nhãn âm chắc chắn.
- Không thang nào trong ba thang trên biết tài sản nào quan trọng với tổ chức của bạn.

Một tổ chức chỉ sắp thứ tự theo CVSS có thể ưu tiên một lỗ hổng rất nghiêm trọng nhưng
không áp dụng cho tài sản đang vận hành, đồng thời xếp thấp hơn một lỗ hổng điểm vừa phải
đang có tín hiệu khai thác và ảnh hưởng tới tài sản trọng yếu. Đồ án sẽ đo mức bất đồng
trên dataset thực tế thay vì giả định trước CVSS hoặc EPSS luôn tốt hơn.

## Ngoài phạm vi

- **Không** khai thác CVE, không viết/chạy exploit, không PoC.
- **Không** tái tạo mô hình EPSS (dữ liệu telemetry khai thác không công khai).
- Không đánh giá hệ thống thật của bất kỳ tổ chức nào; tổ chức trong RQ3 là giả định.

## Cấu trúc thư mục

```
src/collect/        Thu thập dữ liệu: NVD, EPSS, CISA KEV
src/model/          Baseline TF-IDF + DistilBERT multi-head
src/environmental/  CVSS Environmental Metrics — RQ3
src/analysis/       So sánh xếp hạng, biểu đồ bất đồng — RQ2
docs/               Tài liệu phân tích — sản phẩm chính của đồ án
data/raw/           Dữ liệu thô (không commit)
data/processed/     Dataset đã làm sạch (không commit)
notebooks/          EDA
```

## Cài đặt

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # rồi điền NVD_API_KEY
```

Đăng ký NVD API key miễn phí tại https://nvd.nist.gov/developers/request-an-api-key
(không có key thì giới hạn còn 5 request/30 giây).

## Quy trình dự kiến sau khi triển khai

Các module dưới đây đang được xây theo [kế hoạch phase](docs/05-ke-hoach-phan-cong.md).
Chỉ đưa lệnh đã chạy được vào [runbook](docs/phases/phase-4-tich-hop-va-demo.md) ở Phase 4;
không dùng khối này như bằng chứng repo hiện đã hoàn thiện pipeline.

```bash
# 1. Khám phá schema API (chạy 1 lần để hiểu dữ liệu)
python src/collect/explore_apis.py CVE-2021-44228

# 2. Thu thập và chuẩn hóa dữ liệu công khai
python src/collect/nvd_collector.py --start 2023-01-01 --end 2024-12-31
python src/collect/epss_client.py
python src/collect/kev_client.py

# 3. Huấn luyện mô hình dự đoán vector CVSS
python src/model/baseline.py
python src/model/distilbert_multihead.py

# 4. Tính CVSS theo bối cảnh tài sản giả định
python -m src.environmental.cvss_environmental

# 5. Phân tích và xuất hình báo cáo
python -m src.analysis.compare_rankings
python -m src.analysis.plots
```

## Lưu ý về dữ liệu (quan trọng)

Từ tháng 4/2026, NIST thay đổi cách vận hành NVD: các CVE đã có điểm CVSS do CNA
cung cấp sẽ không được NVD chấm lại, và phần lớn CVE tồn đọng chuyển sang trạng thái
`Not Scheduled`. Hệ quả cho đồ án:

- Nhãn CVSS trong dataset đến từ **nhiều nguồn khác nhau** (NVD vs CNA).
- Phải lưu trường `source` của từng metric và thống kê riêng.
- Sự không nhất quán giữa các nguồn chấm điểm chính là một phát hiện đáng bàn (xem Wunder et al. 2024).

## Nhóm thực hiện

| Vai trò | Phụ trách |
|---------|-----------|
| **Người 1 — Data/Integration, nhóm trưởng** | Thu thập NVD/EPSS/KEV, quản lý snapshot và provenance, làm sạch/ghép dữ liệu, EDA, runbook và bản tích hợp. |
| **Người 2 — Security Analysis** | Xác định phạm vi Web/mobile, kiểm tra applicability, tính CVSS Environmental, so sánh ranking, viết case study và playbook ưu tiên vá. |
| **Người 3 — NLP/Demo** | Xây baseline, thử DistilBERT trong giới hạn thời gian, đánh giá tám metric và tích hợp artifact vào demo local. |

## Tài liệu tham khảo

Xem [docs/references.md](docs/references.md)

## Giấy phép

MIT — xem [LICENSE](LICENSE)
