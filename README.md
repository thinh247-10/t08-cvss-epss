# T08 — Dự đoán mức độ nghiêm trọng và ưu tiên vá lỗ hổng: CVSS vs EPSS

> Đồ án môn học — Chương C3 (Đánh giá tác động, thang đo rủi ro)

## Câu hỏi nghiên cứu

Đồ án này **không** nhằm xây dựng một mô hình học máy tốt nhất. Mô hình NLP ở đây là
một công cụ phục vụ câu hỏi bảo mật cốt lõi:

> **Tại sao "CVSS cao" không đồng nghĩa với "cần vá trước"?
> Và một tổ chức nên ưu tiên vá lỗ hổng như thế nào?**

Bốn câu hỏi con:

| # | Câu hỏi | Phương pháp |
|---|---------|-------------|
| RQ1 | Có thể ước lượng mức nghiêm trọng của một CVE chỉ từ mô tả văn bản không? | Mô hình NLP dự đoán vector CVSS |
| RQ2 | Các thang đo ưu tiên (CVSS / EPSS / KEV / SSVC) bất đồng với nhau ở đâu? | Phân tích xếp hạng và tương quan |
| RQ3 | Bối cảnh hệ thống làm thay đổi mức rủi ro như thế nào? | CVSS Environmental Metrics trên tổ chức giả định |
| RQ4 | Quy trình ưu tiên vá nào là hợp lý trong thực tế? | Patch Prioritization Playbook |

**Sản phẩm trọng tâm là RQ2–RQ4.** RQ1 chỉ là bước đệm.

## Bối cảnh: tại sao đề tài này có ý nghĩa thực tế

- CVSS đo **mức nghiêm trọng nếu bị khai thác**, không đo **khả năng bị khai thác**.
- EPSS đo xác suất bị khai thác trong 30 ngày tới, nhưng không biết gì về hệ thống của bạn.
- KEV cho biết lỗ hổng **đã** bị khai thác, nhưng chắc chắn bỏ sót (chỉ gồm những gì CISA xác nhận được).
- Không thang nào trong ba thang trên biết tài sản nào quan trọng với tổ chức của bạn.

Một tổ chức chỉ vá theo CVSS sẽ tiêu tốn nguồn lực vào hàng nghìn lỗ hổng gần như
không ai khai thác, đồng thời bỏ sót những lỗ hổng điểm trung bình nhưng đang bị
khai thác thực tế trên hệ thống trọng yếu.

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

## Quy trình chạy

```bash
# 1. Khám phá schema API (chạy 1 lần để hiểu dữ liệu)
python src/collect/explore_apis.py CVE-2021-44228

# 2. Thu thập dữ liệu
python src/collect/nvd_collector.py --start 2020-01-01 --end 2025-12-31
python src/collect/epss_client.py
python src/collect/kev_client.py

# 3. Huấn luyện
python src/model/baseline.py
python src/model/distilbert_multihead.py

# 4. Phân tích (phần trọng tâm)
python src/environmental/apply_environmental.py
python src/analysis/compare_rankings.py
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
| Data / Infra | Pipeline thu thập, deploy AWS |
| ML / NLP | Baseline, DistilBERT multi-head, explainability |
| Security Analysis | Environmental metrics, so sánh thang đo, playbook |

## Tài liệu tham khảo

Xem [docs/references.md](docs/references.md)

## Giấy phép

MIT — xem [LICENSE](LICENSE)
