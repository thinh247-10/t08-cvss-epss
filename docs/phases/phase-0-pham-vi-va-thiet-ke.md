# Phase 0 — Chốt phạm vi Web/mobile và thiết kế nghiên cứu

**Thời gian:** ngày 1–2 trong kế hoạch 30 ngày. **Ngân sách:** khoảng 4 giờ/người, gồm họp và review.

**Đọc trước:** [Kế hoạch tổng thể](../05-ke-hoach-phan-cong.md) · [Hợp đồng dữ liệu](../data_contract.md).

**Git:** [Branch, commit, push và PR](../06-git-workflow.md). Branch gợi ý: N1 `chore/p0-project-contract`, N2 `docs/p0-security-scope`, N3 `chore/p0-model-config`.

**Tiếp theo:** [Phase 1 — Dữ liệu Web/mobile](phase-1-du-lieu-web-mobile.md).

> Đây là công việc cần thực hiện, chưa phải thông báo rằng repo đã có các tính năng này.
> Các đường dẫn code bên dưới là nơi sẽ triển khai trong tháng tới; file đã tồn tại nhưng chỉ có TODO vẫn phải viết.
> Ngày 1 là ngày nhóm thực sự bắt đầu; nhóm ghi ngày bắt đầu và ngày nộp thật trong kế hoạch tổng thể.

## 1. Mục tiêu và ý nghĩa đối với lời thầy

Kết thúc hai ngày, cả ba người phải giải thích được cùng một câu chuyện:

> Với một tập lỗ hổng của nền tảng Web và ứng dụng di động, CVSS biểu diễn mức nghiêm trọng;
> EPSS bổ sung xác suất khai thác; KEV bổ sung bằng chứng đã được ghi nhận khai thác;
> quyết định vá còn phụ thuộc phần mềm có thực sự hiện diện, phiên bản bị ảnh hưởng và bối cảnh tài sản.

AI là phần thực nghiệm dự đoán tám thành phần CVSS từ mô tả. Nhóm cần làm và đánh giá phần này,
nhưng báo cáo phải dành đủ dung lượng cho phân tích bảo mật, các trường hợp xếp hạng bất đồng
và một quy trình ưu tiên vá có căn cứ. Chưa cần xây dashboard hoặc huấn luyện transformer trong phase này.

Ba sản phẩm phải được chốt ngay:

1. Tập CVE thuộc phạm vi Web/mobile, có lý do và bằng chứng chọn từng dòng.
2. So sánh top-50 theo CVSS, EPSS và **chính sách KEV-first**, cộng phân tích trường hợp bất đồng.
3. Baseline NLP dự đoán AV/AC/PR/UI/S/C/I/A, đánh giá độc lập với bài toán xếp hạng.

KEV là danh mục, không phải thang điểm số thứ ba. “KEV-first” là chính sách nhóm thiết kế để
đưa các CVE có trong KEV lên trước; phải ghi rõ cách phá hòa trong báo cáo.

## 2. Phân công hai ngày

| Người | Ngày 1 — khoảng 2 giờ | Ngày 2 — khoảng 2 giờ | Người review |
|---|---|---|---|
| **N1 — Data/Infra, nhóm trưởng** | Họp 30 phút; kiểm kê code thật/TODO; chốt nơi lưu dữ liệu, bản nháp schema và cấu hình | Hoàn thiện hợp đồng dữ liệu; ghi các quyết định về snapshot, split, chọn nguồn CVSS; lập task và bàn giao | N3 review nhãn/split; N2 review nguồn/snapshot |
| **N2 — Security/Context/Ranking** | Đọc lời thầy và đề cương nếu nhóm có; định nghĩa phạm vi Web/mobile; chọn một tổ chức giả định | Chốt tài sản, tiêu chí applicability; sửa cách diễn giải sai trong docs; thiết kế câu hỏi và ca nghiên cứu | N1 review khả năng lấy dữ liệu; N3 review khả năng trình bày |
| **N3 — ML/Demo** | Kiểm tra môi trường CPU/GPU; đọc hai module model TODO; đề xuất baseline và đầu vào/đầu ra | Chốt nhãn CVSS 3.1, chia dữ liệu, metric đánh giá; phác thảo demo đọc artifact có sẵn | N1 review cách chạy lại; N2 review ý nghĩa bảo mật |

Mỗi người giữ một chủ sở hữu chính cho file mình phụ trách. File dùng chung như README,
requirements và data contract do N1 tổng hợp sau khi nhận nội dung từ hai người còn lại.

### Khởi tạo Git trong buổi đầu

N1 kiểm tra thay đổi đang có, đưa bộ kế hoạch lên PR trước, rồi tạo `develop` theo
[hướng dẫn Git](../06-git-workflow.md). Sau đó mỗi người tạo branch Phase 0 của mình từ
`develop`, push và mở một PR nhỏ. Cả ba dùng lượt này để kiểm tra quyền push/review trước khi
pipeline và model tạo ra thay đổi lớn. Không chuyển branch khi còn file chưa commit mà chưa rõ owner.

## 3. N1 làm gì, ở file nào?

### 3.1. Đọc hiện trạng, không nhầm TODO với sản phẩm

| File hiện có | Chức năng hiện tại | Việc cần làm trong phase này |
|---|---|---|
| `src/collect/explore_apis.py` | Có code gọi ba nguồn cho một CVE để xem schema | Đọc để hiểu JSON; chưa cần chạy thu thập hàng loạt |
| `src/collect/nvd_collector.py` | Docstring/TODO cho collector NVD | Ghi việc sửa TODO “bỏ CVE không có vector”; master phải giữ các dòng này |
| `src/collect/epss_client.py` | Docstring/TODO cho client EPSS | Thay ý tưởng ngày EPSS khác nhau theo từng CVE bằng snapshot chung T cho bảng ranking chính |
| `src/collect/kev_client.py` | Docstring/TODO cho KEV | Ghi yêu cầu lưu thời điểm tải, metadata catalog và `dateAdded` |
| `README.md` | Mô tả mục tiêu và lệnh chạy dự kiến | Ghi nhận lệnh gọi file chưa tồn tại; chỉ công bố lệnh hoạt động sau khi đã triển khai |
| `requirements.txt`, `.env.example`, `.gitignore` | Khung phụ thuộc và môi trường | Kiểm tra cách giữ API key ngoài Git; dự kiến thêm YAML/test khi cần |

### 3.2. Thiết kế đầu vào dùng chung

**Tạo/chốt `config/project.yaml` — file mới, N1 sở hữu.** File này giúp các script dùng chung
một khoảng thời gian, một ngày EPSS và một seed; tránh mỗi người sửa hằng số trong code riêng.

Các nhóm cấu hình cần có:

- Khoảng ngày NVD: thử trước **2023-01-01 đến 2024-12-31**; đây là giả định chờ pilot xác nhận.
- `snapshot_date`: ngày T của EPSS; lưu riêng thời điểm tải KEV và metadata catalog.
- Đường dẫn raw, processed, sample, reports; `dataset_version`; seed để lấy mẫu tái lập.
- Quy tắc chọn một vector CVSS 3.1 trong nhiều nguồn; quy tắc xử lý rejected/duplicate/missing.
- Cửa sổ train/validation/test; quy tắc lọc phạm vi; tham chiếu phiên bản quy tắc scope.
- Timeout, retry và tốc độ gọi API có thể chỉnh; tra tài liệu chính thức trước khi đặt giá trị.

**Hoàn thiện `docs/data_contract.md` — tài liệu chung, N1 tổng hợp.** Không sao chép một schema
khác vào notebook. Tài liệu phải định nghĩa tên cột, kiểu dữ liệu, nullable, đơn vị, tập giá trị,
khóa ghép, ý nghĩa snapshot và các tập con đủ điều kiện cho ranking/ML.

**Tạo `docs/decisions.md` — file mới.** Mỗi quyết định ghi ngày, người đề xuất, người review,
căn cứ, hệ quả và điều kiện được thay đổi. Ít nhất ghi lựa chọn CVSS 3.1, snapshot T,
phạm vi Web/mobile, nguồn vector ưu tiên, split và điều kiện dừng phần transformer.

Đầu ra ngày 2 là cấu hình/thiết kế có thể review. Pipeline thu thập hoàn chỉnh thuộc Phase 1.

### 3.3. Chốt nguyên tắc thực nghiệm trước khi nhìn kết quả

- Master có một dòng cho mỗi `cve_id`, giữ cả CVE thiếu CVSS 3.1 hoặc thiếu EPSS.
- Lưu raw đủ để kiểm tra lại các vector khác nguồn; không âm thầm lấy vector cao nhất.
- Chỉ dùng CVSS **3.1** cho bộ nhãn tám thành phần; không trộn vector 4.0 vào cùng schema.
- Tách cohort nghiên cứu ranking, cohort huấn luyện và cohort ca nghiên cứu theo tài sản.
- Snapshot hiện tại của CVE cũ là phân tích mô tả tại T; không gọi đó là dự báo tương lai ở thời điểm công bố CVE.
- Dùng split theo thời gian công bố: train 2023; validation nửa đầu 2024; test nửa cuối 2024, **tạm thời**.
- Nếu pilot thiếu lớp hoặc ít mẫu, điều chỉnh khoảng năm/split trước huấn luyện và khóa test.
- Mô tả NVD tải hiện tại có thể đã được sửa sau ngày công bố; split theo ngày công bố không tự loại bỏ hạn chế này.

## 4. N2 làm gì, ở file nào?

### 4.1. Định nghĩa phạm vi thay vì lấy mọi CVE có chữ “web”

**Tạo `docs/scope.md` — file mới, N2 sở hữu.** Ghi đối tượng được nhận, bị loại, chưa xác định
và cách người khác có thể kiểm tra quyết định. Phạm vi gợi ý:

| Nhóm | Ví dụ đối tượng trong phạm vi | Bằng chứng cần có |
|---|---|---|
| Web | CMS/plugin, web framework, application server, web/API backend | Mô tả + advisory/CPE xác định sản phẩm và vai trò Web |
| Mobile | Ứng dụng Android/iOS, SDK/thư viện nhúng trong ứng dụng, thành phần WebView phù hợp | Advisory xác định ứng dụng/SDK và đường tác động tới ứng dụng |
| Có thể thuộc cả hai | Backend phục vụ ứng dụng di động và trình duyệt | Chứng cứ cho cả hai vai trò; dùng nhiều nhãn, không nhân đôi CVE |
| Chưa đủ căn cứ | Mô tả quá ngắn, thư viện đa dụng không rõ triển khai | Đánh dấu chờ review, không tự ép vào cohort chính |
| Ngoài phạm vi chính | Lỗi kernel/driver/firmware thuần túy không gắn bài toán ứng dụng | Ghi lý do loại khỏi ranking Web/mobile; vẫn có thể tồn tại trong master |

Không dùng `AV:N` làm tiêu chí đồng nghĩa với Web; không coi mọi CVE Android là lỗi ứng dụng mobile.
Không yêu cầu một CVE phải vừa Web vừa mobile. Báo cáo cần tối thiểu một case Web và một case
mobile client/framework/SDK có bằng chứng. Nếu cohort mobile nhỏ, công bố số lượng và giới hạn;
có thể dùng case bổ sung ngoài cohort, ghi nhãn rõ và không đưa vào metric định lượng của cohort.

Định nghĩa `domain_tags` là danh sách nhãn `web`/`mobile`; đồng thời có `in_scope`, `scope_reason`,
`scope_evidence` dạng danh sách và `scope_status` (`included`/`excluded`/`needs_review`).
Quy tắc chi tiết nằm trong [data contract](../data_contract.md).

### 4.2. Chọn một bối cảnh nhất quán

**Tạo `config/assets.yaml` — file mới, N2 sở hữu.** Chọn một dịch vụ thương mại điện tử giả định
có Web, mobile và API dùng chung. Bắt đầu với khoảng 5–6 tài sản:

1. Website/CMS công khai.
2. API đăng nhập và tài khoản.
3. Backend đơn hàng/thanh toán.
4. Trang quản trị nội bộ.
5. Ứng dụng Android hoặc SDK nằm trong ứng dụng.
6. Ứng dụng iOS/thành phần client nếu có CVE phù hợp và đủ bằng chứng.

Mỗi tài sản có `asset_id`, chức năng nghiệp vụ, sản phẩm/phiên bản giả định, bề mặt truy cập,
dữ liệu xử lý, mức quan trọng CR/IR/AR và lý do. Không tự bịa một phiên bản bị ảnh hưởng:
chỉ chốt phiên bản sau khi đối chiếu advisory ở Phase 1/3; trạng thái chưa rõ phải được giữ rõ.

**Cập nhật `docs/03-environmental-context.md` — file hiện có, cần sửa nội dung.** Nêu giả định
kiến trúc có căn cứ và tách hai việc: mô tả mức phơi lộ để quyết định vá; thay metric CVSS
khi điều kiện trong đặc tả thật sự thay đổi. Không phải mọi kiểm soát đều dẫn đến sửa vector.

### 4.3. Sửa ngay cách diễn giải gây lệch mục tiêu

| File hiện có | Nội dung phải sửa | Cách diễn giải được chấp nhận |
|---|---|---|
| `docs/01-research-questions.md` | KEV là override vô điều kiện; thêm SSVC như mục tiêu bắt buộc | Kiểm tra applicability trước; SSVC chỉ tham khảo nếu còn thời gian |
| `docs/03-environmental-context.md` | Nội bộ → `MAV:A/L` tự động | Truy cập qua mạng nội bộ vẫn có thể là Network; Adjacent/Local theo điều kiện khai thác trong đặc tả |
| `docs/03-environmental-context.md` | Có WAF, backup, mã hóa → tự tăng/giảm metric | Mỗi thay đổi cần lập luận riêng; chưa đủ bằng chứng thì giữ metric mặc định và ghi kiểm soát ở context |
| `docs/04-patch-playbook.md` | Kiểm tra KEV trước tài sản; mọi KEV vá trong 24–72 giờ | Xác minh sản phẩm/phiên bản trước; SLA là đề xuất cho tổ chức giả định, không là quy tắc CISA áp cho mọi nơi |
| `README.md` | “Pentest”, “quét”, hoặc dự đoán 0-day được trình bày như năng lực đã chứng minh | Gọi đúng là phân tích dữ liệu CVE và thực nghiệm NLP; không có hoạt động khai thác/kiểm thử hệ thống thật |

N2 chuẩn bị nội dung README gửi N1 tích hợp; không sửa cùng lúc nếu N1 đang chỉnh file.

### 4.4. Chốt ba bảng ranking và cách chọn case study

Trong cùng một cohort đủ điều kiện, dự kiến ba chính sách có phá hòa xác định:

- CVSS: Base Score giảm dần; hòa thì `cve_id` tăng dần.
- EPSS: xác suất EPSS giảm dần; hòa thì `cve_id` tăng dần.
- KEV-first: KEV giảm dần → EPSS giảm dần → CVSS giảm dần → `cve_id` tăng dần.

Main ranking dùng CVSS từ nguồn đã chọn, không âm thầm thay bằng dự đoán AI. Dự đoán AI
phục vụ thí nghiệm riêng và màn hình ước lượng; mọi giá trị ước lượng phải có nhãn rõ ràng.

Đề xuất trước các loại case cần tìm: CVSS cao nhưng EPSS thấp; CVSS thấp hơn nhưng KEV/EPSS cao;
cùng CVE nhưng tài sản hoặc mức phơi lộ khác; thiếu điểm/bằng chứng nên cần review.
Không ghi sẵn kết luận từng CVE khi chưa có dữ liệu.

## 5. N3 làm gì, ở file nào?

| File | Trạng thái | Chức năng dự kiến và việc trong phase này |
|---|---|---|
| `config/model.yaml` | Mới | Chốt seed, TF-IDF + Logistic Regression, nhãn, tham chiếu split, ngân sách transformer tùy chọn |
| `src/model/baseline.py` | Có, TODO | Thiết kế 8 bộ phân loại, fit TF-IDF trên train; dự đoán vector và lưu artifact |
| `src/model/distilbert_multihead.py` | Có, TODO | Ghi thiết kế encoder chung + 8 head; chỉ triển khai sau khi baseline và dữ liệu đạt gate |
| `docs/data_contract.md` | Tài liệu chung | Đóng góp schema prediction và các điều kiện đủ nhãn; N1 tổng hợp |
| `docs/decisions.md` | Mới, N1 tổng hợp | Ghi cấu hình máy, giới hạn thời gian, quyết định baseline bắt buộc/transformer tùy chọn |
| `app.py` | Chưa có; triển khai Phase 4 | Phác thảo bằng văn bản ba màn hình: dataset/ranking, case context, ước lượng CVSS |

N3 cần kiểm tra được Python và thư viện cốt lõi cài trên máy mình; không mất ngày đầu sửa GPU
nếu baseline chạy được bằng CPU. Chưa cần tải mô hình lớn hoặc làm giao diện.

Chốt metric: macro-F1 từng thành phần, F1 từng lớp và số mẫu hỗ trợ; exact-vector accuracy;
MAE/RMSE Base Score từ vector hợp lệ. Luôn so với dự đoán lớp phổ biến và TF-IDF baseline.

Nếu CVE Web/mobile quá ít để huấn luyện tám nhãn, cho phép mở cohort ML sang CVE rộng hơn
nhưng giữ cohort ranking Web/mobile. Khi đó báo cáo chất lượng ML riêng trên nhóm Web/mobile,
ghi số mẫu và tránh gộp kết quả để ngụ ý mô hình đã tốt cho mobile.

## 6. Prompt vibe code cho phase này

Chỉ đưa **một việc nhỏ** vào mỗi lượt. Sau khi AI trả code/tài liệu, người sở hữu đọc diff,
kiểm tra tên cột với data contract rồi mới đưa vào nhánh chính. Không gửi API key vào prompt.

**N1 — cấu hình và schema:**

```text
Đọc docs/data_contract.md và src/collect/*.py. Chỉ tạo config/project.yaml
theo các quyết định đã chốt; không viết collector, không gọi mạng.
Đánh dấu khoảng năm và split là quyết định pilot cần khóa trước training.
Không tạo dữ liệu kết quả giả. Liệt kê những tên cột hoặc quy tắc chưa có trong contract.
```

Người kiểm: N3 đọc nhãn/split; N2 đọc snapshot. Không chấp nhận cấu hình có hai ngày EPSS
khác nhau cho cùng bảng ranking hoặc tự xóa dòng thiếu nhãn.

**N2 — rà soát lập luận bảo mật:**

```text
Đọc docs/01-research-questions.md, docs/03-environmental-context.md và
docs/04-patch-playbook.md. Đề xuất diff sửa applicability trước KEV;
loại suy luận tự động intranet -> MAV:A/L và WAF -> MAC:H.
Ghi nguồn FIRST CVSS 3.1 cho mỗi định nghĩa; chưa điền CVE/số liệu minh họa chưa xác minh.
Chỉ sửa nội dung tài liệu, không tạo công thức hay điểm rủi ro mới.
```

Người kiểm: N2 mở nguồn chính thức, tự giải thích được từng sửa đổi; N1 kiểm phạm vi file.

**N3 — hợp đồng đánh giá:**

```text
Đọc docs/data_contract.md và hai file src/model hiện có. Đề xuất config/model.yaml
cho baseline TF-IDF + Logistic Regression với 8 nhãn CVSS 3.1.
Không huấn luyện, không chọn tham số bằng test, không dùng EPSS/KEV làm feature.
Ghi cách xử lý lớp hiếm/thiếu lớp và đầu ra đánh giá cần có.
```

Người kiểm: N1 thử đọc cấu hình; N2 kiểm AI được mô tả là dự đoán severity, không là xác suất khai thác.

## 7. Bàn giao và gate cuối ngày 2

| Bên giao → nhận | Đầu ra phải có | Cách người nhận xác nhận |
|---|---|---|
| N1 → N2, N3 | Data contract và cấu hình dự án | Cả hai chỉ ra được đường dẫn dataset, khóa CVE, tên cột cần đọc |
| N2 → N1 | Scope, quy tắc evidence và tài sản giả định | N1 có thể hiện thực bộ lọc mà không tự quyết định nghiệp vụ |
| N3 → N1 | Yêu cầu nhãn, split, prediction | N1 biết dòng nào đủ điều kiện ML và vì sao |
| Cả nhóm → nhật ký | Quyết định nghiên cứu | Có ngày, chủ sở hữu và reviewer; không để ba bản schema riêng |

- [ ] Cả ba nói được vì sao CVSS cao chưa đủ để quyết định vá trước.
- [ ] Có phạm vi Web/mobile dựa trên sản phẩm và bằng chứng, không chỉ keyword.
- [ ] Đã thống nhất CVSS 3.1, snapshot T, nguồn vector, missing và phá hòa ranking.
- [ ] Phân biệt rõ KEV membership, xác suất EPSS và severity CVSS.
- [ ] Có kế hoạch kiểm tra dữ liệu pilot trước khi khóa split và chạy test.
- [ ] Mỗi file dự kiến có chủ sở hữu; không giao việc chung chung “làm AI” hoặc “viết báo cáo”.

Nếu thiếu đề cương môn học, ghi “chưa nhận đề cương” và dùng lời thầy cùng phạm vi đề tài
làm căn cứ tạm thời; người giữ liên lạc bổ sung đề cương khi có. Không tự khẳng định đã đọc.

Nếu còn tranh luận phạm vi sau hai ngày, chọn kịch bản Web + mobile API gọn nhất có bằng chứng,
ghi giới hạn; không kéo dài thiết kế kiến trúc sang hết tuần đầu.

## 8. Nguồn bắt buộc đọc trước khi triển khai

- [FIRST — CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document): ý nghĩa Base/Environmental và các metric.
- [FIRST — EPSS](https://www.first.org/epss/): EPSS đo gì và giới hạn diễn giải.
- [NVD — Vulnerabilities API](https://nvd.nist.gov/developers/vulnerabilities): trường dữ liệu, phân trang và bộ lọc.
- [CISA — KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): ý nghĩa danh mục và nguồn dữ liệu.

Đây là nguồn định nghĩa/phương pháp. Các kết luận định lượng phải chờ artifact của chính nhóm.
