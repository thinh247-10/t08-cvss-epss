# Phase 1 — Xây dataset có căn cứ cho Web và ứng dụng di động

**Thời gian:** ngày 3–7. **Ngân sách:** khoảng 12 giờ/người, ưu tiên dữ liệu dùng được trước.

**Trước:** [Phase 0](phase-0-pham-vi-va-thiet-ke.md) · **Sau:** [Phase 2 — NLP](phase-2-mo-hinh-nlp.md).

**Quy định chung:** [Kế hoạch tổng thể](../05-ke-hoach-phan-cong.md) · [Data contract](../data_contract.md).

**Bàn giao pilot NVD-only đang triển khai:** [File mẫu, cách đọc và việc N2/N3 làm ngay](../pilot-handoff.md).
Mẫu này chưa ghép EPSS/KEV, chưa xác nhận scope và chưa khóa split.

**Git:** [Quy trình branch/PR](../06-git-workflow.md). Kế hoạch ban đầu: N1 dùng `feat/p1-data-pipeline` hoặc `feat/data-pipeline`; N2 `feat/p1-scope-assets`; N3 `test/p1-data-audit`.
**Điều chỉnh theo lựa chọn của N1:** các bước nhỏ đang làm trực tiếp trên `develop`, không bắt buộc tạo branch hay review độc lập cho mỗi bước. Việc này không thay thế xác nhận scope/nhãn của N2/N3.

> Đây là kế hoạch và tiêu chí đích; không phải mọi chức năng bên dưới đã hoàn thành.
> Cập nhật 01/10/2026: parser và NVD pilot đã có; EPSS/KEV đã tải thật thành công;
> `build_dataset.py --pilot` đã chạy và xuất bảng ghép; Parquet/CSV và checksum đã được kiểm tra.
> Thu thập NVD toàn khoảng, scope, audit/split và khóa dataset v1 vẫn chưa hoàn tất.

**Cập nhật kiểm tra 03/10/2026:** `collect_nvd.py` đã tải thật tháng 01/2023:
2.565 CVE qua 6 trang, 228 Rejected/thiếu vector, 2.337 ứng viên mô tả + vector.
Raw, bảng, giá trị parser và checkpoint hoàn tất đã được đối chiếu. Output:
`data/processed/nvd_20261002T170958_423579Z/metadata.json`.
Tiếp theo mở rộng sang 2023–2024 theo config; chưa đánh dấu lượt toàn khoảng đã chạy.
[Hướng dẫn Người 1 — NVD nhiều trang](../phase-1-nguoi-1-nvd-phan-trang.md).

### Tiến độ pilot và hướng dẫn đang dùng

| Phần | Trạng thái đã xác minh | Hướng dẫn thao tác |
|---|---|---|
| NVD | 543 CVE trong cửa sổ 01–07/01/2023; 451 ứng viên có mô tả/vector, 92 Rejected | [Gói bàn giao NVD](../pilot-handoff.md) |
| EPSS | Snapshot 29/09/2026: 451 có điểm, 92 thiếu; bảng giữ đủ 543 ID | [Người 1 — EPSS](../phase-1-nguoi-1-epss.md) |
| KEV | Catalog 2026.09.30: 1.730 CVE; đã kiểm tra count/ID/checksum | [Người 1 — KEV](../phase-1-nguoi-1-kev.md) |
| Ghép pilot | Đã lưu `joined_pilot_20261001T114053_995549Z`: 543 dòng; 2 ID thuộc KEV; đã kiểm tra Parquet/CSV/checksum; scope/split còn pending | [Người 1 — Ghép pilot và giới hạn chờ nhóm](../phase-1-nguoi-1-ghep-pilot.md) |

Pilot lưu output theo thư mục từng lần chạy để không ghi đè snapshot/gói bàn giao.
Các đường dẫn cố định bên dưới là đích của pipeline đầy đủ; dùng metadata để tìm
đúng artifact pilot. Chỉ dùng dữ liệu có manifest hợp lệ, không chọn thư mục mới nhất theo phỏng đoán.

## 1. Mục tiêu cần đạt

Có một dataset tái tạo được từ NVD + EPSS + CISA KEV, đồng thời giải thích được vì sao mỗi
CVE được tính là Web/mobile. N2 dùng dataset để phân tích bảo mật; N3 dùng các dòng đủ nhãn
để làm thực nghiệm NLP; cả hai đọc cùng tên cột và cùng `dataset_version`.

Hai mốc bàn giao:

- **Cuối ngày 4:** mẫu thật đủ nhỏ để kiểm tra giao tiếp; nên có vài chục dòng thuộc nhiều trường hợp.
- **Cuối ngày 7:** dataset v1, báo cáo chất lượng, danh sách chia dữ liệu và quyết định về phạm vi/split.

Với so sánh top-50, mục tiêu là cohort ranking có **hơn 100 CVE**, ưu tiên **từ 200 CVE trở lên**
nếu nguồn đáp ứng. Đây là mục tiêu kiểm tra tính hữu ích của phân tích, không phải số lượng đã có.
Tổng số CVE tải về không chứng minh số lượng đủ điều kiện: cần đếm sau scope, CVSS 3.1 và EPSS.

## 2. Phân công theo ngày

| Ngày | N1 — Data/Infra | N2 — Security/Context | N3 — ML/Demo |
|---|---|---|---|
| 3 | Khoảng 2,5 giờ: NVD pilot, lưu raw và manifest; hiện thực parser CVSS 3.1 | Khoảng 2 giờ: hoàn thiện scope và bảng sản phẩm có căn cứ; chọn mẫu để kiểm tra | Khoảng 2 giờ: đọc contract; chuẩn bị đọc dataset và kiểm tra tám nhãn |
| 4 | Khoảng 2,5 giờ: EPSS cùng T, tải KEV, ghép mẫu đầu tiên | Khoảng 2,5 giờ: review khoảng 20–30 quyết định scope; kiểm tra cả nhận và loại | Khoảng 2 giờ: đọc mẫu trên máy riêng, báo lỗi kiểu dữ liệu/missing/nhãn |
| 5 | Khoảng 3 giờ: phân trang/retry/cache; chạy phạm vi đã chốt; hoàn thiện join | Khoảng 3 giờ: kiểm tra mobile, advisory và nguồn CVSS; ghi danh sách CVE ứng viên case study | Khoảng 3 giờ: thống kê theo split/lớp; đề xuất điều chỉnh khi lớp hiếm hoặc thiếu mẫu |
| 6 | Khoảng 2 giờ: build dataset và báo cáo chất lượng; sửa lỗi từ reviewer | Khoảng 2,5 giờ: inventory giả định + applicability mẫu; review tập scope chưa chắc chắn | Khoảng 3 giờ: kiểm tra trùng mô tả, khả năng đọc nhãn; chạy thử luồng baseline nhỏ nếu dữ liệu sẵn |
| 7 | Khoảng 2 giờ: khóa dataset v1 và metadata; nghiệm thu pipeline | Khoảng 2 giờ: ký xác nhận cohort Web/mobile, không bịa coverage | Khoảng 2 giờ: xác nhận schema và split cuối cùng trước huấn luyện chính thức |

Các giờ trên gồm review và trao đổi. Không chờ N1 tải xong toàn bộ mới bắt đầu việc N2/N3.

## 3. N1: viết collector và ghép dữ liệu

### 3.1. `src/collect/nvd_collector.py` và `collect_nvd.py` — parser và điều phối tải

Hiện tại `collect_pilot.py` tải một trang trong cửa sổ bảy ngày đầu; `nvd_collector.py`
trích xuất và chọn vector. `collect_nvd.py` bổ sung phân trang, cửa sổ ngày, retry,
cache/checkpoint và output `paged-v1`; tải thật nhiều trang tháng 01/2023 đã được
xác nhận. `build_dataset.py` đọc được cả hai kiểu raw. Danh sách bên dưới
là yêu cầu đích; không đồng nghĩa toàn khoảng 2023–2024 đã được tải hoặc nghiệm thu.

**Chức năng:** lấy các bản ghi CVE trong khoảng công bố, lưu nguồn gốc và xuất dữ liệu trung gian.

Các việc nhỏ nên giao AI theo từng lượt:

1. Đọc `config/project.yaml`; nhận khoảng ngày và thư mục đầu ra qua CLI.
2. Chia khoảng thời gian theo giới hạn API; phân trang theo metadata trả về.
3. Gọi API có timeout; giới hạn tốc độ theo tài liệu hiện hành; retry lỗi tạm thời và rate limit.
4. Lưu checkpoint để tiếp tục sau lỗi; không công bố hoàn tất nếu còn trang tải thất bại.
5. Lưu raw JSON nguyên gốc hoặc dạng nén; lưu URL/tham số đã bỏ key, thời điểm tải và checksum.
6. Chuẩn hóa CVE ID, mô tả tiếng Anh, ngày công bố/cập nhật, trạng thái, CPE/reference cần cho scope.
7. Giữ mọi metric gốc và chọn một CVSS 3.1 theo thứ tự đã chốt trong contract.
8. Xuất `data/raw/nvd_cves.parquet` theo contract; không giả vờ có nhãn nếu thiếu.

**Phải sửa TODO cũ:** không bỏ CVE chỉ vì không có CVSS. Dòng đó vẫn thuộc master;
điều kiện đủ nhãn được xử lý ở các view ML/ranking.

Khi nhiều nguồn bất đồng, lưu nguồn/type của vector được chọn, dấu hiệu bất đồng và vị trí raw
để truy ngược. Không lấy vector có điểm cao nhất vì cách đó làm lệch phân bố mức nghiêm trọng.

### 3.2. `src/collect/epss_client.py` — đã triển khai và chạy cho pilot

**Chức năng:** lấy EPSS cho danh sách CVE tại cùng ngày T, xuất `data/raw/epss.parquet`.

- Nhận CVE ID từ kết quả NVD, loại trùng trước khi gửi request.
- Chia lô theo giới hạn API hiện hành; retry và cache để không tải lại tùy tiện.
- Gửi ngày T đã chốt; kiểm tra ngày thực tế trong response, lưu xác suất và percentile riêng.
- EPSS là số từ 0 đến 1; không nhầm xác suất với percentile hoặc phần trăm đã nhân 100.
- Nếu API không có bản ghi, giữ thiếu và ghi trạng thái; **không thay bằng 0**.
- Nếu một lô thất bại, ghi lỗi tải; không đánh đồng với nguồn đã trả lời “không có dữ liệu”.
- Nếu T chưa có dữ liệu, chọn ngày khả dụng chung và cập nhật metadata cho toàn bộ cohort.

Không dùng EPSS ở “30 ngày sau công bố” khác nhau cho từng CVE trong bảng snapshot chính.
Thiết kế đó là một nghiên cứu khác, cần căn cứ thời gian và dữ liệu lịch sử riêng.

### 3.3. `src/collect/kev_client.py` — đã triển khai và tải catalog thật

**Chức năng:** tải catalog KEV một lần cho snapshot, lưu raw và `data/raw/kev.parquet`.

- Lưu thời điểm tải, `catalogVersion`/`dateReleased` nếu nguồn có, tổng bản ghi, checksum.
- Giữ `cveID`, `dateAdded`, các trường mô tả/vendor/product và thông tin hành động cần thiết.
- Chuẩn hóa khóa thành `cve_id`; kiểm tra trùng trước khi ghép.
- Sau khi tải catalog hoàn chỉnh, CVE không có trong catalog được đánh dấu không nằm trong KEV.
- Nếu tải thất bại hoặc catalog lỗi, dừng build chính thức; không gán toàn bộ membership thành false.
- Không có trong KEV không đồng nghĩa chưa từng bị khai thác; đó là giới hạn phải đi vào báo cáo.

Snapshot T là ngày EPSS; KEV là catalog thực tế tải kèm timestamp. Nếu hai thời điểm lệch nhau,
phải công bố độ lệch. Không tuyên bố đã tái tạo chính xác KEV lịch sử chỉ nhờ lọc `dateAdded`.

### 3.4. `src/collect/filter_scope.py` — file mới, N1 code; N2 chịu trách nhiệm quy tắc

**Chức năng:** gán phạm vi nghiên cứu có thể kiểm tra lại, không dùng để xóa vĩnh viễn dữ liệu master.

Đầu vào là description, CPE/product/reference và bảng quyết định của N2. Đầu ra gồm:

- `domain_tags`: danh sách nhãn `web`/`mobile`, cho phép cả hai đồng thời.
- `in_scope`: có đủ căn cứ đưa vào cohort nghiên cứu chính hay chưa.
- `scope_reason`: lý do ngắn, cụ thể về vai trò sản phẩm.
- `scope_evidence`: danh sách chuỗi URL/advisory/CPE/reference hỗ trợ, truy được về raw.
- `scope_status`: `included`/`excluded`/`needs_review`; chưa rõ thì `in_scope=false` và giữ lý do.
- Phiên bản quy tắc hoặc manifest gắn với lần build để biết dữ liệu được gán nhãn bằng quy tắc nào.

Keyword và CPE chỉ tạo ứng viên. Cho phép quyết định thủ công có căn cứ ghi đè quy tắc tự động;
chưa đủ evidence thì giữ trạng thái cần review theo contract, chưa đưa vào cohort chính.
Không phân loại Web/mobile từ EPSS hoặc KEV: hai trường đó không định nghĩa loại nền tảng.

### 3.5. `src/collect/build_dataset.py` — N1 sở hữu, đã có chế độ pilot

Chế độ hiện có yêu cầu `--pilot` và ba đường dẫn metadata cụ thể; kiểm tra provenance,
left join, giữ scope/split pending và xuất thư mục mới. Chưa áp dụng scope hay khóa v1.
Các bước dưới đây mô tả đích đầy đủ; việc áp dụng quyết định N2 và audit N3 còn chờ.

**Chức năng:** ghép ba nguồn theo `cve_id`, áp dụng scope, kiểm tra contract và xuất artifact chung.

1. Đọc file nguồn đã tải; kiểm tra provenance và hoàn tất phân trang trước khi build.
2. Khử trùng theo quy tắc xác định; left join EPSS/KEV vào tập NVD master.
3. Không để join tăng số dòng do khóa bị trùng; báo lỗi nếu vi phạm.
4. Tạo/chuẩn hóa các cột CVSS 3.1 và tám nhãn hợp lệ; giữ lý do thiếu/không đủ điều kiện.
5. Áp dụng `filter_scope.py`; giữ tập ngoài scope và chưa xác định trong master.
6. Kiểm tra ràng buộc cột, khoảng giá trị, ngày, vector/score và nguồn điểm.
7. Ghi `data/processed/cves.parquet`, mẫu CSV, metadata và báo cáo chất lượng.
8. Nếu kiểm tra quan trọng không đạt, trả exit code lỗi; không ghi đè bản v1 đã khóa bằng dữ liệu lỗi.

**Không viết lại công thức CVSS riêng ở collector.** Chỉ parse/validate; phép tính điểm dùng
module/thư viện CVSS đã thống nhất với N2 và được đối chiếu ở phase sau.

### 3.6. Artifact và chức năng từng file

| Đường dẫn dự kiến | Chức năng | Ai đọc/review |
|---|---|---|
| `data/raw/` | Dữ liệu nguồn, cache/checkpoint và bằng chứng tái dựng | N1 vận hành; N2/N3 kiểm dòng bất thường |
| `data/processed/cves.parquet` | Master chuẩn hóa, một dòng/CVE; không chỉ các dòng đủ nhãn | Cả nhóm |
| `data/sample/cves_sample.csv` | Mẫu thật nhẹ dùng kiểm tra loader/demo; không đại diện hiệu năng ML | N2/N3 |
| `data/sample/metadata.json` | Nguồn/version/snapshot của mẫu, liên hệ với dataset gốc | N2/N3 kiểm khi nhận mẫu |
| `data/metadata.json` | Dataset version, config, seed, nguồn, snapshot, checksum và số lượng | Cả nhóm; người chấm có thể kiểm |
| `reports/data_quality.md` | Coverage, missing, trùng, scope và cảnh báo chất lượng | N2/N3 review trước khi khóa |
| `notebooks/01_eda.ipynb` | Đọc dataset và tái tạo thống kê; không có nguồn dữ liệu bí mật riêng | N1 chủ trì; N3 góp thống kê lớp |
| `tests/test_collect.py` | Kiểm tra parser/join/missing/retry bằng fixture nhỏ, không gọi mạng | N1 viết; N3 review |
| `tests/test_scope.py` | Kiểm tra quy tắc nhận/loại/chưa rõ theo ví dụ N2 đã xác nhận | N1 viết; N2 review |

JSON/list trong CSV mẫu phải theo encoding của contract; không để N3 phải tự đoán cách tách
`domain_tags`. Raw/dataset lớn xử lý theo `.gitignore`; commit mẫu nhỏ và hướng dẫn tái tạo.

## 4. N2: bảo đảm dataset thực sự phục vụ bảo mật Web/mobile

### 4.1. Review phạm vi có ghi lại bằng chứng

Tiếp tục hoàn thiện `docs/scope.md`. Trong ngày 4, chọn khoảng 20–30 dòng có chủ đích:
Web rõ ràng, mobile rõ ràng, thư viện đa dụng, ngoài phạm vi và thiếu mô tả. Review cả dòng
được nhận và bị loại để tìm false positive lẫn false negative; không chỉ nhìn vài ví dụ đẹp.

Tạo **`data/annotations/scope_review.csv` — file mới** theo contract: `cve_id`,
`proposed_domain_tags`, `final_domain_tags`, `scope_status`, `reason`, `evidence_url`,
`reviewer`, `reviewed_at`, `scope_policy_version`.
File này là đầu vào bổ sung cho bộ lọc; không dùng như bộ kết quả định lượng độc lập.

Nếu điều chỉnh quy tắc sau review, ghi version và chạy lại toàn bộ gán scope. Không sửa từng dòng
trong Parquet bằng tay rồi bỏ qua pipeline. Không khẳng định độ chính xác bộ lọc chỉ từ một mẫu nhỏ.

### 4.2. Lập inventory và kiểm tra applicability mẫu

**`config/assets.yaml`**: điền sản phẩm/phiên bản giả định, chức năng và mức quan trọng đã chốt.
**`src/environmental/asset_inventory.py`** hiện là TODO; trong phase này triển khai loader/validator:

- Đọc YAML, kiểm `asset_id` duy nhất và trường bắt buộc.
- Kiểm giá trị CR/IR/AR và yêu cầu lý do, không tự chọn High cho mọi tài sản.
- Kiểm trạng thái phiên bản/chứng cứ; cho phép “chưa xác định” thay vì suy đoán affected.
- Trả cấu trúc thống nhất cho phân tích context ở Phase 3.

Chuẩn bị `data/processed/cve_asset_mapping.csv` theo contract, dùng khoảng 5–10 cặp có bằng chứng:
`applicability` là `affected`/`unaffected`/`needs_review`; phiên bản giả định; nguồn mô tả dải phiên bản ảnh hưởng;
điều kiện khai thác và lý do. Đây là thử giao tiếp dữ liệu; Phase 3 hoàn thiện cohort case study.

Không coi match tên CPE là xác minh đủ: cần đọc dải phiên bản và điều kiện liên quan. Tài sản là
giả định, còn advisory và tình trạng CVE phải truy được nguồn; hai loại thông tin phải tách rõ.

### 4.3. Chuẩn bị danh sách case study, chưa viết kết luận

Trong `docs/03-environmental-context.md`, thêm danh sách ứng viên được đánh dấu **chờ phân tích**.
Ưu tiên vài CVE thật có advisory dễ đọc, liên quan trực tiếp Web/mobile, có khả năng minh họa
bất đồng CVSS–EPSS–KEV hoặc khác biệt applicability/bối cảnh.

Không chỉ chọn các CVE nổi tiếng; không chốt trước rằng “EPSS thấp nên hoãn vá” khi chưa đọc
context. Nếu cohort không có KEV, ghi đúng thực tế và xem phương án mở rộng ở cuối phase.

## 5. N3: kiểm tra dữ liệu cho NLP trước khi huấn luyện chính thức

### 5.1. Việc phải làm với mẫu ngày 4

- Đọc `data/sample/cves_sample.csv` trên máy mình và xác nhận encoding tiếng Anh/Unicode không hỏng.
- Kiểm tra cột mô tả, vector 3.1, tám nhãn, nullable và ngày công bố theo contract.
- Liệt kê lỗi theo CVE ID và tên cột để N1 sửa parser; không chữa riêng trong notebook.
- Thử một lượt đọc → lọc đủ nhãn → chuẩn bị đầu vào; chưa báo F1 như kết quả nghiên cứu.

N3 làm ở `src/model/baseline.py` (file hiện có TODO) phần kiểm tra đầu vào tối thiểu;
thiết kế loader dùng chung và training đầy đủ thuộc Phase 2. Không thêm EPSS/KEV vào feature.

### 5.2. Việc phải làm với dataset ngày 5–6

Đóng góp bảng vào `reports/data_quality.md` và notebook EDA:

| Thống kê | Vì sao cần |
|---|---|
| Số dòng có mô tả và đủ tám nhãn CVSS 3.1 | Biết lượng dữ liệu thật có thể train |
| Số mẫu từng lớp AV/AC/PR/UI/S/C/I/A theo split | Phát hiện thiếu lớp trước khi mô hình lỗi hoặc metric gây hiểu nhầm |
| Số mẫu Web/mobile trong từng split | Biết có thể báo riêng chất lượng trên phạm vi môn học hay không |
| CVE ID và mô tả trùng giữa các split | Phát hiện rò rỉ và mô tả theo khuôn gần giống nhau |
| Nguồn CVSS, trạng thái thiếu nhãn và ngày `last_modified` | Hiểu bias nguồn nhãn và hạn chế hồi cứu |

N3 đề xuất quy tắc loại/nhóm mô tả trùng cho cohort ML trước huấn luyện; N1 ghi trong metadata.
Không xóa các CVE khác nhau khỏi master chỉ vì mô tả giống nhau.

Split dự kiến: train 2023, validation 01–06/2024, test 07–12/2024. Chỉ điều chỉnh theo lượng dữ liệu,
hỗ trợ lớp và phạm vi đã định trước; không đổi sau khi xem điểm test để làm kết quả đẹp hơn.

N3 cập nhật `config/model.yaml` với quyết định cuối và yêu cầu huấn luyện. Nếu thử baseline
nhỏ để kiểm tra luồng, ghi rõ smoke run, không dùng test để chọn tham số.

## 6. Prompt vibe code và kiểm tra thủ công

**N1 — một collector, một lượt:**

```text
Đọc docs/data_contract.md, config/project.yaml và src/collect/nvd_collector.py.
Chỉ hiện thực phân trang NVD + lưu raw/checkpoint và parser CVSS 3.1.
Giữ dòng thiếu vector; lưu source/type và mọi metric raw; không lấy score cao nhất.
Không gọi mạng trong test. Thêm fixture kiểm multi-source, missing và duplicate.
Trước khi sửa, nêu input/output và trường hợp làm script thất bại.
```

N1 đọc raw của vài CVE rồi đối chiếu từng cột; N3 kiểm fixture thiếu nhãn không bị xóa.

**N1 — ghép dữ liệu sau khi từng nguồn đã đúng:**

```text
Chỉ viết src/collect/build_dataset.py theo data contract.
Left join NVD master với EPSS snapshot T và KEV catalog đã tải thành công.
Giữ null EPSS, chặn duplicate key/mismatched date, xuất metadata và quality report.
Không gán KEV false khi catalog tải lỗi. Không tự sửa schema hay thêm điểm tổng hợp.
```

N2 kiểm một CVE KEV, một CVE không KEV và một dòng thiếu EPSS; đối chiếu nguồn thật.

**N2 — scope và tài sản:**

```text
Theo docs/scope.md và mục scope review trong data contract, đề xuất annotation
cho các dòng ứng viên: proposed_domain_tags, final_domain_tags, scope_status,
reason, evidence_url và thông tin review đúng schema scope_review.csv.
Không suy Web từ AV:N, không suy mobile app từ mọi lỗi Android.
Thiếu bằng chứng thì để review. Chỉ trả bảng nháp; không sửa dataset master.
```

N2 mở advisory và kiểm lại trước khi ghi annotation. AI không là nguồn bằng chứng.

**N3 — báo cáo hỗ trợ nhãn:**

```text
Đọc dataset theo docs/data_contract.md. Tạo thống kê số mẫu và lớp theo split,
tách Web/mobile và nguồn CVSS; kiểm CVE ID/mô tả trùng giữa split.
Không fit TF-IDF trên toàn bộ dữ liệu, không huấn luyện/chọn model bằng test.
Chỉ thêm phần thống kê vào notebook EDA đã thống nhất, không tạo schema riêng.
```

N3 tự kiểm bằng cách đếm một metric và một split; không tin bảng thống kê chỉ vì notebook chạy hết.

## 7. Kiểm thử đủ để tin pipeline

Kiểm thử tập trung vào lỗi làm sai kết luận: vector nhiều nguồn, CVSS 4.0/3.0 không lẫn nhãn 3.1,
thiếu CVSS/EPSS, catalog KEV lỗi, join nhân dòng, response sai ngày, phân trang chưa hoàn tất,
scope có nhiều nhãn và quyết định chưa xác định. Dùng fixture nhỏ rõ là giả lập.

Chạy kiểm thử cục bộ trước; sau đó làm một smoke run API với phạm vi nhỏ để xác nhận schema thực.
Fixture giả lập chỉ ở `tests/fixtures/`, không được trộn vào dataset/bảng top-50 để bù dữ liệu thiếu.

Trong metadata, lưu số dòng qua từng bước và số bị loại theo từng nguyên nhân. EDA phải cho thấy
master, cohort Web/mobile, cohort ranking và cohort ML có mẫu số khác nhau.

## 8. Gate cuối ngày 7 và phương án khi thiếu dữ liệu

- [ ] N2 và N3 đọc được artifact v1 trên máy riêng mà không đổi tên cột.
- [ ] Master không trùng CVE ID; không mất dòng chỉ vì thiếu nhãn hoặc ngoài phạm vi.
- [ ] Nguồn CVSS, snapshot EPSS và metadata KEV truy được về raw.
- [ ] Missing EPSS phân biệt với 0; non-KEV phân biệt với lỗi tải catalog.
- [ ] Scope có evidence, có review cả mẫu nhận/loại, có thống kê riêng Web/mobile.
- [ ] Số CVE ranking được báo rõ; nhóm đã quyết định cách xử lý nếu không đủ mục tiêu top-50.
- [ ] Split và chính sách mô tả trùng đã khóa trước training/test; lớp hiếm được liệt kê.
- [ ] Dataset version, config và checksum giúp nhận biết ba người đang dùng cùng dữ liệu.

Nếu cohort ranking chưa đủ hơn 100 dòng, mở rộng khoảng năm hoặc nhóm sản phẩm **trong phạm vi**,
ghi quyết định rồi thu thập lại; ưu tiên việc này hơn trang trí demo. Chỉ mở rộng theo tiêu chí đã
định, không chọn từng CVE để tăng số KEV hoặc làm EPSS có vẻ tốt hơn.

Nếu vẫn có `N <= 50` dòng, chọn `K < N` để so top-K có tính chọn lọc và công bố chưa đạt
top-50 có ý nghĩa; không dùng `K=N` để chứng minh overlap hay ưu tiên tốt. Với `N<2`, chỉ
trình bày dữ liệu/case mô tả và tiếp tục xử lý thiếu mẫu; không nhân bản dòng.
Nếu không có KEV, không tính KEV recall với mẫu số 0; báo không xác định, cân nhắc cohort rộng hơn
hoặc bổ sung ca nghiên cứu ngoài cohort có nhãn rõ và không gộp vào metric chính.

Nếu dữ liệu Web/mobile thiếu cho ML, dùng cohort ML rộng hơn đã thống nhất nhưng giữ đánh giá
Web/mobile riêng. Nếu API chậm, dùng cache/pilot thật để N2/N3 tiếp tục, giảm tính năng phụ;
không bịa điểm và không âm thầm dùng ngày khác nhau.

Cohort mobile nhỏ không bỏ yêu cầu có ít nhất một case mobile client/framework/SDK được xác minh.
Nếu dùng case bổ sung ngoài cohort chính, ghi rõ và không gộp vào top-K hoặc metric ML của cohort.

N1 bàn giao dataset; N2 xác nhận ý nghĩa phạm vi; N3 xác nhận điều kiện nhãn. Ba chữ xác nhận này
là điều kiện bắt đầu thực nghiệm chính thức ở [Phase 2](phase-2-mo-hinh-nlp.md).

## 9. Tài liệu kỹ thuật cần đối chiếu khi viết code

- [NVD Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities): trường dữ liệu và phân trang.
- [NVD Start Here](https://nvd.nist.gov/developers/start-here): giới hạn và thực hành gọi API.
- [FIRST EPSS API](https://api.first.org/epss/): ngày snapshot, xác suất, percentile và truy vấn.
- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): nguồn catalog và ý nghĩa membership.

Ghi ngày truy cập nguồn trong báo cáo; giới hạn API có thể thay đổi, không sao chép số cũ từ TODO.
