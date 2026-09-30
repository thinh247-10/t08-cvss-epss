# Phase 5 — Hoàn thiện báo cáo, đóng gói và bảo vệ

**Thời gian:** ngày 26–30; khoảng **6 giờ/người** cho phần việc lên lịch, tổng 18 giờ nhóm. Ngày 29–30 là đệm sửa lỗi và nộp sớm, không dành để mở thêm tính năng.
**Mục tiêu:** giảng viên thấy rõ nhóm hiểu ưu tiên vá lỗ hổng Web/Mobile, biết sử dụng AI có giới hạn, và có thể kiểm tra lại các kết quả đã trình bày.
**Trạng thái:** đây là việc cần thực hiện; mọi checklist để trống cho đến khi nhóm có bằng chứng hoàn thành.

- Kế hoạch chung: [Phân công 30 ngày](../05-ke-hoach-phan-cong.md).
- Đầu vào: [Phase 4 — Tích hợp và demo](phase-4-tich-hop-va-demo.md).
- Quy ước dữ liệu: [data contract](../data_contract.md).
- Git: [quy trình branch/PR](../06-git-workflow.md). N1 `docs/p5-final-integration`; N2 `docs/p5-security-section`; N3 `docs/p5-ml-slides`.
- Đây là phase cuối; deadline chính thức và quy cách nộp phải lấy từ thông báo môn học đã đối chiếu ở Phase 0.

## 1. Điều phải trả lời được khi nộp

“CVSS cao” mô tả mức nghiêm trọng theo những giả định của thang điểm, nhưng thứ tự vá còn phụ thuộc tín hiệu khai thác, mức phơi nhiễm, mức quan trọng của tài sản, việc phiên bản đang dùng có bị ảnh hưởng, và khả năng áp dụng bản vá. Đồ án phải chứng minh lập luận đó bằng kết quả của nhóm, không chỉ lặp lại định nghĩa.

Đề xuất phân bổ nội dung/thời gian: **65% bảo mật và quyết định vá, 25% AI, 10% dữ liệu và khả năng tái lập**. Đây là ưu tiên làm bài của nhóm theo lời thầy, **không phải rubric chấm điểm chính thức**. Nếu đề cương quy định khác, tuân theo đề cương và ghi cập nhật.

Không cần chứng minh EPSS luôn thắng CVSS hoặc Transformer luôn thắng baseline. Một kết quả tốt là mô tả đúng khi nào thứ tự khác nhau, dữ liệu hỗ trợ điều gì và chưa hỗ trợ điều gì.

## 2. Đầu vào phải ổn định trước khi viết kết luận

- Snapshot, tập CVE đủ điều kiện và chính sách ranking đã chốt từ Phase 3/4.
- Ba bảng top-50 khi N > 50; nếu N ≤ 50 thì dùng K < N và ghi giới hạn chưa đạt top-50 có ý nghĩa. Biểu đồ bất đồng, bảng metric và case dùng cùng phiên bản.
- Baseline được đánh giá trên split đã định; Transformer chỉ có trong bảng nếu thật sự đã chạy trên điều kiện so sánh công bố.
- Tối thiểu một case Web, một case Mobile client/SDK/framework, tổng 3–5 case có nguồn và giả định rõ ràng.
- Runbook đã được một người khác chạy, có bằng chứng và giới hạn được ghi lại.
- Notebook/script demo có bản local dự phòng, không bắt buộc internet khi trình bày.
- Nếu thiếu một mục bắt buộc, ghi lỗi vào checklist và ưu tiên sửa; không che thiếu sót bằng kết luận tổng quát.

## 3. Phân công cho ba người: 6 giờ/người

### Người 1 — Chủ biên, dữ liệu, tái lập và nộp bài

1. **1,5 giờ:** viết phần dữ liệu/phương pháp thu thập trong `reports/final-report.md`: phạm vi, nguồn, ngày snapshot, số lượng, thiếu dữ liệu và CVSS source.
2. **1 giờ:** hợp nhất ba phần báo cáo; thống nhất thuật ngữ, hình, bảng, tên file và các câu trả lời RQ.
3. **1 giờ:** hoàn thiện `docs/runbook.md`, README và gói nộp theo đúng yêu cầu môn học.
4. **1 giờ:** đối chiếu checklist và nguồn tham khảo; kiểm tra báo cáo/slide cùng version với artifact.
5. **1 giờ:** diễn tập cùng nhóm, giữ thời gian và ghi câu hỏi còn yếu.
6. **0,5 giờ:** chốt bản nộp, xác minh tên file/link và biên nhận nộp khi thực hiện qua kênh được giảng viên yêu cầu.

**Vibe code/vibe writing ở:** `reports/final-report.md`, `docs/runbook.md`, `reports/release-checklist.md`, README. Chỉ dùng AI biên tập trên các số liệu đã cung cấp; người viết chịu trách nhiệm từng phát biểu.

**Phải hiểu để bảo vệ:** vì sao chọn tập dữ liệu đó; nguồn CVSS có thể khác nhau; snapshot EPSS/KEV mang ý nghĩa gì; ai có thể chạy lại kết quả và cần những file nào.

**Review chéo:** Người 3 kiểm tra lệnh/model version; Người 2 kiểm tra cách diễn giải thiếu dữ liệu và phạm vi Web/Mobile.

### Người 2 — Nội dung bảo mật, case study và chính sách vá

1. **2 giờ:** viết kết quả so sánh CVSS/EPSS/KEV-first và phân tích 3–5 case trong `reports/sections/security.md`; N1 tích hợp sau khi PR được review.
2. **1 giờ:** hoàn thiện phần bối cảnh tài sản và playbook; mô tả hành động, lý do, giả định và hạn chế.
3. **1 giờ:** tạo phần nội dung bảo mật trong `reports/slides-outline.md`; chọn tối đa hai case để trình bày trực tiếp.
4. **1 giờ:** chuẩn bị câu hỏi phản biện; rà soát các kết luận có nguy cơ quá mức chứng cứ.
5. **1 giờ:** diễn tập và review toàn bộ lời dẫn demo; đảm bảo người nghe hiểu “vì sao vá trước”.

**Vibe code/vibe writing ở:** phần RQ2–RQ4 của `reports/final-report.md`, `docs/03-environmental-context.md`, `docs/04-patch-playbook.md`, slide và script. Chỉ sửa `src/analysis/` khi phát hiện lỗi tác động kết quả và được ghi vào checklist.

**Phải hiểu để bảo vệ:** mỗi thang/tín hiệu đo gì; vì sao không có trong KEV không phải nhãn âm; vì sao ranking theo CVE khác hàng đợi theo tài sản; khi nào giả định bối cảnh làm đổi quyết định.

**Review chéo:** Người 1 đối chiếu nguồn và con số; Người 3 kiểm tra hình/bảng thật sự được tạo từ artifact đang nộp.

### Người 3 — Báo cáo ML, slide/demo và giới hạn AI

1. **1,5 giờ:** viết phần dự đoán vector, split, baseline, metric và phân tích lỗi trong `reports/sections/ml.md`; N1 tích hợp sau khi PR được review.
2. **1 giờ:** ghi kết quả Transformer nếu đã có, hoặc phương án giới hạn phạm vi và lý do chưa hoàn thành; không bỏ qua baseline.
3. **1 giờ:** chốt `reports/slides-outline.md` và script cùng hai người còn lại; dựng bộ 9 slide từ template sẵn có, dùng lại hình đã khóa. Nếu dựng slide mất lâu hơn, lấy giờ ở mục 2 khi không có Transformer hoặc chuẩn bị khung từ Phase 4.
4. **1 giờ:** chạy demo lần cuối, xác minh model nạp được và notebook dự phòng còn đúng phiên bản.
5. **1 giờ:** diễn tập, sửa lời giải thích về AI; chuẩn bị một lỗi dự đoán tiêu biểu.
6. **0,5 giờ:** kiểm tra file slide/PDF nếu môn yêu cầu, font, hình, tên file và khả năng mở trên máy khác.

**Vibe code/vibe writing ở:** phần RQ1 của báo cáo, slide outline và demo script. Không mở thêm model mới, prompt LLM hay tính năng app trong phase này.

**Phải hiểu để bảo vệ:** đầu vào/nhãn 8 thành phần, chống leakage, metric cho lớp hiếm, vì sao score suy từ vector dự đoán có thể lệch và vì sao không dùng nó làm ground truth.

**Review chéo:** Người 1 đối chiếu tái lập và model artifact; Người 2 duyệt cách nối AI vào quyết định bảo mật.

## 4. File bàn giao và công dụng

| File/nhóm file | Tình trạng và người phụ trách | Chức năng, đầu vào → đầu ra |
|---|---|---|
| `reports/final-report.md` | Mới theo kế hoạch, Người 1 chủ biên | Tập hợp nguồn + kết quả thực + diễn giải → báo cáo có thể truy nguyên cho RQ1–RQ4 |
| `reports/sections/security.md` | Mới theo kế hoạch, Người 2 | Phần RQ2–RQ4 và case đã review → đầu vào để N1 tích hợp, tránh cùng sửa báo cáo chính |
| `reports/sections/ml.md` | Mới theo kế hoạch, Người 3 | Phần RQ1, metric và lỗi mô hình → đầu vào để N1 tích hợp, giữ observed/predicted riêng |
| `reports/slides-outline.md` | Mới theo kế hoạch, Người 3 tổng hợp | Nội dung báo cáo đã khóa → từng slide, lời nói, thời lượng, người trình bày và hình dùng |
| `reports/demo-script.md` | Bắt đầu Phase 4, Người 2/3 | Artifact + notebook → thao tác demo, lời giải thích, trường hợp lỗi và phương án dự phòng |
| `reports/release-checklist.md` | Bắt đầu Phase 4, Người 1 | Kiểm tra thực tế + log → trạng thái nghiệm thu, lỗi còn mở và xác nhận người review |
| `docs/runbook.md` | Bắt đầu Phase 4, Người 1 | Entry point/config/snapshot → hướng dẫn cài và tái tạo; ghi lệnh đã thử và giới hạn môi trường |
| `docs/references.md` | Có sẵn, Người 1 điều phối | Tài liệu nhóm thực sự đã đọc → trích dẫn, DOI/link và ghi chú dùng cho luận điểm nào |
| `docs/03-environmental-context.md` | Có sẵn, Người 2 | Inventory + mapping + score → giả định tài sản, lý do thay đổi và giới hạn bối cảnh |
| `docs/04-patch-playbook.md` | Có sẵn, Người 2 | Xếp hạng + context → quy trình ưu tiên và SLA đề xuất, có bước xác minh bị ảnh hưởng |
| `README.md` | Có sẵn, Người 1 | Cấu trúc repo + runbook → hướng dẫn bắt đầu nhanh và link sản phẩm nộp |
| `reports/figures/` | Artifact Phase 3/4, Người 2 | Bảng kết quả → hình dùng chung trong báo cáo/slide; không sửa số bằng tay |
| `notebooks/02_model_eval.ipynb` | Mới theo kế hoạch từ Phase 2, Người 3 | Prediction + nhãn/split → bảng metric, confusion matrix và phân tích lỗi |
| `notebooks/03_demo.ipynb` | Mới theo kế hoạch từ Phase 4, Người 3 | Artifact đóng băng → demo tối thiểu và bản dự phòng đã thực thi |
| `data/metadata.json` | Artifact từ các phase trước, Người 1 | Nguồn, ngày, version và thống kê thu thập → căn cứ kiểm tra provenance |
| `data/processed/*.csv`, `cves.parquet` | Artifact từ các phase trước, chủ sở hữu tương ứng | Dataset/prediction/ranking/context → bằng chứng cho mọi con số báo cáo |
| `config/project.yaml`, `assets.yaml`, `model.yaml` | Mới theo kế hoạch từ các phase trước, Người 1/2/3 | Tham số nghiên cứu và giả định → tái tạo phương pháp đã báo cáo |
| `models/` | Artifact Phase 2/3, Người 3 | Model + nhãn + thông tin phiên bản → inference và tái lập có giới hạn đã công bố |
| `reports/final-report.pdf` | **Chỉ tạo nếu quy cách nộp yêu cầu**, Người 1 | Xuất từ bản báo cáo đã khóa → bản đọc cố định; cần mở kiểm tra bố cục |
| `reports/slides.pdf` hoặc file trình chiếu được yêu cầu | **Theo quy cách nộp**, Người 3 | Slide outline + hình → bản trình chiếu; kiểm tra trên máy sử dụng thực tế |

Không bắt buộc commit dữ liệu lớn hoặc model lớn vào Git. Nếu cần gói dữ liệu ngoài repo, runbook phải nói file nào cần, cách lấy, version/hash và vị trí đặt file; thử quyền truy cập từ tài khoản thành viên khác trước khi nộp.

## 5. Dàn ý báo cáo chi tiết

Độ dài đề xuất 15–20 trang nội dung nếu môn không quy định. Phụ lục chứa bảng đầy đủ, thông tin tái lập và metric chi tiết. Không kéo dài bằng mã nguồn hoặc ảnh chụp terminal không có thông tin.

| Phần | Nội dung phải viết | Chủ trì | Bằng chứng |
|---|---|---|---|
| Tóm tắt | Bài toán, phương pháp, kết quả thực tế nổi bật, giới hạn | Người 1, viết cuối | Kết quả đã khóa; không dùng số ước đoán |
| Bài toán và phạm vi | Web/Mobile, câu hỏi “vì sao CVSS cao chưa đủ?”, ngoài phạm vi khai thác CVE | Người 2 | Lời định hướng của thầy + đề cương nhóm đã đối chiếu |
| Cơ sở lý thuyết | CVSS severity; EPSS xác suất khai thác 30 ngày; KEV bằng chứng đã biết | Người 2 | Tài liệu chính thức được dẫn nguồn |
| Dữ liệu | Tiêu chí chọn/loại, CVSS v3.1, nguồn nhãn, ngày snapshot, missingness, giới hạn đại diện | Người 1 | Metadata, EDA, thống kê số CVE qua từng bước |
| Phương pháp NLP | Mô tả → 8 nhãn; split thời gian; baseline; Transformer nếu có; đánh giá | Người 3 | Config, notebook và model metadata |
| Phương pháp xếp hạng | Cùng cohort; 3 chính sách; tie-break; top-50; metric bất đồng | Người 2 | Data contract và logic đã triển khai |
| Kết quả bảo mật | Top-50, giao nhau, bất đồng và coverage KEV của CVSS/EPSS có giới hạn | Người 2 | Ranking và figure tương ứng |
| Bối cảnh tổ chức | Web/Mobile assets, mapping, Environmental, hàng đợi CVE–tài sản | Người 2 | Assets config, mapping và score |
| Case study | 3–5 ca, điều kiện bị ảnh hưởng, dữ kiện vs giả định, hành động và lý do | Người 2 | Advisory/CVE, snapshot và artifact |
| Kết quả NLP | F1 từng metric/lớp, exact-vector accuracy, Base Score MAE/RMSE, coverage prediction hợp lệ và lỗi điển hình | Người 3 | Notebook đánh giá thực tế; thiếu metric bắt buộc phải ghi vào checklist để xử lý |
| Quy trình vá | Xác minh ảnh hưởng → xét tín hiệu/impact → hành động → theo dõi; SLA giả định | Người 2 | Playbook và case hỗ trợ |
| Hạn chế | KEV không đầy đủ, dữ liệu theo snapshot, CVSS nguồn khác nhau, bối cảnh giả định, leakage/shift | Cả nhóm | Các hạn chế đã ghi qua từng phase |
| Kết luận | Trả lời từng RQ bằng phát hiện thực; công dụng và giới hạn của AI | Người 1 | Dẫn ngược đến bảng/hình/case |
| Phụ lục tái lập | Lệnh, môi trường, version, nguồn, tham số, artifact, đóng góp thành viên | Người 1 | Runbook và checklist |

### Mẫu viết một case study

1. **Nhận diện:** CVE, sản phẩm/phiên bản bị ảnh hưởng, nền tảng Web hoặc Mobile; link nguồn và ngày kiểm tra.
2. **Dữ liệu quan sát:** vector/score CVSS và nguồn chấm, EPSS tại ngày nào, có/không có trong KEV snapshot nào.
3. **Bất đồng:** vị trí trong ba ranking, tập CVE được so sánh và nguyên nhân phương pháp dẫn tới khác biệt.
4. **Tài sản giả định:** asset_id, phiên bản, điều kiện truy cập, mức quan trọng; ghi rõ giả định nào không đến từ advisory.
5. **Quyết định:** vá/giảm thiểu/xác minh thêm/theo dõi; giải thích bằng dữ kiện và giả định cụ thể.
6. **Giới hạn:** điều gì chưa biết; thông tin mới nào có thể làm đổi quyết định.

Không điền sẵn kết luận “EPSS tốt hơn” cho mọi case. Nếu điểm và thứ tự nhất quán, có thể dùng làm ca đối chiếu; ca bất đồng mới là trọng tâm giải thích.

## 6. Phân bổ bài trình bày

Ví dụ slot **15 phút chưa tính hỏi đáp**: 9 phút trình bày + 6 phút demo từ Phase 4. Nếu lớp quy định slot khác, giữ tỉ trọng nội dung và giảm số case trình bày trực tiếp.

| Slide | Thời lượng | Người nói | Nội dung và hình cần dùng |
|---|---|---|---|
| 1. Vấn đề | 0:45 | Người 1 | Một câu hỏi quyết định vá; phạm vi Web/Mobile, không mở bằng kiến trúc Transformer |
| 2. Dữ liệu và nghĩa của tín hiệu | 0:45 | Người 1 | Sơ đồ nguồn, snapshot, số CVE; CVSS/EPSS/KEV đo ba thứ khác nhau |
| 3. Thiết kế so sánh | 0:45 | Người 2 | Cohort chung, top-50 và quy tắc KEV-first |
| 4. Kết quả thứ hạng | 1:00 | Người 2 | Hình chính và một phát hiện có số liệu |
| 5. Hai case Web/Mobile | 1:30 | Người 2 | Một cặp ví dụ đủ chứng minh điều kiện và bối cảnh làm đổi ưu tiên |
| 6. Bối cảnh và hành động | 1:00 | Người 2 | Cùng CVE ở tài sản khác, mapping và quyết định có lý do |
| 7. AI dự đoán vector | 1:15 | Người 3 | Baseline, split, 8 nhãn, kết quả thật; Transformer nếu hoàn thành |
| 8. Giới hạn và lỗi AI | 1:00 | Người 3 | Một lỗi điển hình, predicted vs observed, giới hạn dữ liệu |
| 9. Kết luận và tái lập | 1:00 | Người 1 | Câu trả lời cốt lõi, playbook, artifact và chuyển sang demo |
| Demo | 6:00 | Cả nhóm | Theo `reports/demo-script.md`; khoảng 4 phút dành cho kết quả bảo mật |

Phân công nói không nhất thiết bằng nhau từng phút; mọi thành viên đều phải giải thích được câu hỏi cốt lõi và phần việc của mình. Dự kiến Người 1 dẫn mở/kết, Người 2 dẫn phân tích bảo mật, Người 3 dẫn NLP và thao tác demo phù hợp.

## 7. Câu hỏi thầy có thể hỏi và khung trả lời

| Câu hỏi | Khung trả lời cần có bằng chứng |
|---|---|
| Vì sao CVSS cao chưa chắc vá trước? | Nêu severity khác likelihood/bối cảnh; mở một case có số liệu và tài sản; giải thích quyết định cụ thể, không trả lời chỉ bằng định nghĩa |
| Vậy CVSS không còn giá trị? | CVSS giúp mô tả tác động/điều kiện khai thác; kết hợp tín hiệu và tài sản. Dẫn một ca mà impact vẫn quyết định ưu tiên |
| EPSS có phải điểm rủi ro của tổ chức em? | Phân biệt xác suất khai thác ngoài thực tế trong cửa sổ 30 ngày với rủi ro tài sản cụ thể; chỉ ra dữ liệu EPSS không chứa inventory giả định của nhóm |
| Không có trong KEV có nghĩa an toàn không? | Không; catalog chỉ chứa những ca đáp ứng tiêu chí và đã được thêm tại snapshot. Nêu giới hạn khi dùng làm proxy đánh giá |
| Tại sao có “thang thứ ba” KEV? | Nói chính xác đây là KEV-first, một chính sách dùng tín hiệu nhị phân; trình bày tie-break EPSS → CVSS → CVE |
| KEV-first có recall KEV cao nhất thì em đã chứng minh gì? | Chỉ chứng minh đặc tính thiết kế trên catalog đó; không phải đánh giá dự đoán độc lập. So sánh CVSS/EPSS với KEV cũng chỉ là phân tích retrospective có giới hạn |
| Có bị rò rỉ dữ liệu theo thời gian không? | Nêu split và các mốc train/test/snapshot. Phân tích snapshot không phải backtest dự báo tương lai; nếu không có nhãn thời gian độc lập thì không tuyên bố prospective accuracy |
| Mobile ở đâu trong đề tài? | Mở một case client/SDK/framework, giải thích component và điều kiện bị ảnh hưởng; không chỉ dẫn backend của một app di động |
| AI đóng góp gì nếu CVSS đã có sẵn? | Nhãn sẵn có phục vụ train/evaluate; dự đoán có thể hỗ trợ ước lượng ban đầu từ mô tả. Chưa chứng minh đúng với zero-day chỉ bằng dữ liệu CVE công khai |
| Tại sao không chỉ dùng LLM hoặc Transformer? | Baseline bảo đảm khả năng tái lập và chuẩn so sánh; nêu kết quả/giới hạn tài nguyên thực. Nếu Transformer chưa chạy, nói rõ thay vì suy đoán sẽ tốt hơn |
| Làm sao biết Environmental đúng? | Mở vector và cấu hình, nguồn công thức, ca kiểm tra đối chiếu; tách score chuẩn khỏi trọng số/chính sách tự thiết kế |
| Ngưỡng và SLA do ai quy định? | Là đề xuất cho tổ chức giả định, dựa trên phân tích đã trình bày; không là luật chung. Ngưỡng được chốt trên validation hoặc phân tích kịch bản, không tối ưu rồi đánh giá lại trên cùng test |
| Nhóm có khai thác thử CVE chưa? | Không; phạm vi phân tích dữ liệu, advisory và bối cảnh giả định. Không dùng từ “đã pentest hệ thống” để mô tả công việc này |
| Nếu sửa một giả định tài sản thì sao? | Chỉ ra input cần đổi và kết quả nào tính lại; phân biệt đổi queue/context với thay đổi top-50 toàn bộ CVE |
| Em có tái lập nguyên văn bài báo không? | Liệt kê phần đã tái lập và phần điều chỉnh về dữ liệu/model/split; chỉ nhận “tái lập đầy đủ” khi thật sự đáp ứng các điều kiện đó |

Mỗi thành viên tự trả lời các câu hỏi bằng lời của mình trong 30–60 giây, rồi mở đúng artifact hỗ trợ. Không học thuộc số liệu chưa đối chiếu lần cuối.

## 8. Prompt hỗ trợ viết và rà soát

### Người 1 — Biên tập báo cáo từ bằng chứng

```text
Chỉ biên tập reports/final-report.md từ bảng/hình/metadata được cung cấp.
Giữ nguyên số liệu, ngày snapshot, tên chính sách và mức độ chắc chắn.
Mỗi kết luận phải dẫn tới hình/bảng/case hoặc nguồn; thiếu thì ghi [CẦN BẰNG CHỨNG].
Không tự thêm thành tích, số CVE, metric hoặc tuyên bố đã triển khai.
Liệt kê các điểm mâu thuẫn để nhóm kiểm chứng thay vì tự chọn số đúng.
```

### Người 2 — Phản biện lập luận bảo mật

```text
Đọc các đoạn RQ2–RQ4 và case study được cung cấp.
Chỉ tạo danh sách vấn đề: đánh đồng severity với risk, xem KEV âm là an toàn,
đánh giá vòng tròn KEV-first, thiếu bằng chứng Web/Mobile, thiếu mapping tài sản,
trộn snapshot hoặc biến SLA giả định thành nghĩa vụ phổ quát.
Với từng vấn đề, chỉ vị trí, lý do và đề xuất câu sửa có giới hạn chứng cứ.
Không tạo số liệu hoặc nguồn tham khảo chưa kiểm tra.
```

### Người 3 — Chuyển báo cáo thành slide và câu trả lời

```text
Từ báo cáo đã khóa, chỉ cập nhật reports/slides-outline.md.
Tạo 9 slide theo phân bổ thời gian trong Phase 5; mỗi slide nêu người nói,
1 luận điểm, artifact thật sẽ dùng, lời dẫn ngắn và câu hỏi có thể gặp.
AI là phương pháp phục vụ bài toán bảo mật. Giữ separate observed/predicted.
Không thêm claim baseline/Transformer tốt hơn nếu báo cáo chưa có kết quả.
```

Sau khi dùng AI, tác giả đọc lại từng câu. Dùng tìm kiếm trong file để phát hiện `[CẦN BẰNG CHỨNG]`, số mẫu, “TBD”, “TODO” và khẳng định chưa được chứng minh trước khi nộp.

## 9. Nguồn, trích dẫn và giới hạn cần công bố

- Trích nguồn định nghĩa CVSS/EPSS/KEV từ tài liệu chính thức; ghi URL/DOI, tiêu đề và ngày truy cập trong `docs/references.md` theo định dạng môn yêu cầu.
- Chỉ dẫn bài báo cho điều nhóm đã đọc được; DOI có thật không tự bảo đảm đoạn diễn giải đúng nội dung bài.
- Các tài liệu tham khảo đề bài là nền nghiên cứu; ghi rõ bài nào hỗ trợ luận điểm, bài nào hỗ trợ thiết kế mô hình và bài nào nhóm chỉ tham khảo tổng quan.
- Advisory/CVE dùng cho case cần link trực tiếp và giải thích bằng chứng affected product/version; không chỉ dẫn trang chủ nhà cung cấp.
- Công bố đây là phân tích retrospective từ snapshot nếu thực tế làm như vậy; không gọi đó là dự báo khai thác tương lai đã được xác nhận.
- Công bố KEV không là ground truth âm đầy đủ; CVE không có trong KEV không mặc nhiên “không bị khai thác”.
- Giải thích độ bao phủ Web/Mobile và thiên lệch do CVSS v3.1, EPSS thiếu hoặc lọc sản phẩm; không suy rộng tùy ý ra tất cả CVE.
- Nêu bối cảnh tổ chức là giả định; không tuyên bố đã đo giảm rủi ro, giảm thời gian vá hoặc ROI thực tế nếu chưa có vận hành thật.

## 10. Lịch khóa nội dung và dùng hai ngày đệm

| Ngày | Việc chốt | Người chịu trách nhiệm | Điều kiện ra khỏi ngày |
|---|---|---|---|
| 26 | Ba phần báo cáo hoàn chỉnh; thống nhất hình/bảng | Người 1/2/3 theo chuyên môn | Không còn đoạn kết luận chờ số liệu chính |
| 27 | Review chéo, sửa phát biểu quá mức, hoàn thiện slide/script | Người 1 tổng hợp | Mỗi claim quan trọng có bằng chứng |
| 28 | Diễn tập trọn bài, chạy demo, đóng bản nộp | Cả nhóm | Bản có thể nộp ngay, checklist ghi lỗi còn mở |
| 29 | Đệm sửa lỗi ảnh hưởng đúng/sai hoặc quy cách nộp | Chủ sở hữu lỗi | Không thêm tính năng; lỗi sửa có kiểm tra lại |
| 30 | Kiểm tra khả năng mở/quyền truy cập, nộp và giữ biên nhận | Người 1; hai người còn lại xác nhận | Nộp trước giờ khóa theo thông báo môn học |

Nếu deadline chính thức sớm hơn ngày 30, dời toàn bộ mốc khóa lùi tương ứng và giữ ít nhất một ngày đệm. Nếu không cần đệm, dùng để luyện giải thích, không mở thêm hạng mục triển khai.

## 11. Checklist nộp và nghiệm thu cuối

- [ ] Báo cáo trả lời rõ vì sao CVSS cao chưa đủ xác định thứ tự vá.
- [ ] Phạm vi Web và Mobile được chứng minh bằng dữ liệu/case; đủ 3–5 case có bằng chứng.
- [ ] Có biểu đồ top-50 ba chính sách khi N > 50; nếu N ≤ 50, chọn K < N và ghi giới hạn chưa đạt sản phẩm top-50 có ý nghĩa. N < 2 không dùng để kết luận so sánh ưu tiên.
- [ ] CVSS/EPSS/KEV-first dùng cùng cohort/snapshot; nguồn điểm, missingness, tie-break được ghi.
- [ ] Bảng context/queue theo CVE–tài sản không bị đánh đồng với bảng ranking CVE.
- [ ] Không có kết luận vòng tròn “KEV-first tốt nhất vì bắt được chính KEV”.
- [ ] Baseline, split, metric và lỗi mô hình có kết quả thật; Transformer ghi đúng trạng thái.
- [ ] Nhãn quan sát/dự đoán được tách trong code, dữ liệu, hình, demo và văn bản.
- [ ] Có case đổi ưu tiên theo điều kiện tài sản và playbook có bước xác minh bị ảnh hưởng.
- [ ] Tài liệu tham khảo, DOI/link và các phát biểu từ nguồn đã được kiểm tra.
- [ ] Runbook được thành viên khác chạy; ghi rõ môi trường và phần chưa tái lập được nếu còn.
- [ ] Tệp dữ liệu/model lớn có cách lấy, version/hash, đường dẫn và quyền truy cập được thử.
- [ ] Báo cáo, slide, notebook và hình cùng phiên bản; không còn số ví dụ hoặc placeholder.
- [ ] Bản PDF/slide nếu nộp đã mở kiểm tra font, hình, bảng và bố cục trên máy trình bày.
- [ ] Demo có phương án local dự phòng và không phụ thuộc tải API trong lúc bảo vệ.
- [ ] Không đưa API key hoặc thông tin nhạy cảm vào repo, log, ảnh hay gói nộp.
- [ ] Bảng đóng góp ghi đúng file/công việc mỗi thành viên thực hiện và review.
- [ ] Các thành viên trả lời được câu hỏi chính, diễn tập không vượt thời lượng.
- [ ] Gói nộp đáp ứng quy cách môn học; link truy cập được; đã giữ bằng chứng nộp thành công.

**Hoàn thành đồ án** khi sản phẩm đã nộp được, có căn cứ và nhóm giải thích được quyết định bảo mật. Việc hoàn thành dashboard, Docker hoặc Transformer mở rộng không thay thế các yêu cầu này.
