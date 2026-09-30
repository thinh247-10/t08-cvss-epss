# Phase 4 — Tích hợp, kiểm tra và demo có thể chạy lại

**Thời gian:** ngày 21–25 trong kế hoạch 30 ngày; khoảng **8 giờ/người**, tổng 24 giờ nhóm.
**Mục tiêu:** một người khác có thể mở dự án, đọc đúng snapshot, tái tạo kết quả và xem demo trả lời câu hỏi bảo mật của thầy.
**Trạng thái:** đây là kế hoạch thực hiện; các ô chưa đánh dấu là việc sẽ làm, không phải kiểm tra đã hoàn tất.

- Kế hoạch chung: [Phân công 30 ngày](../05-ke-hoach-phan-cong.md).
- Đầu vào: [Phase 3 — Xếp hạng và bối cảnh](phase-3-xep-hang-va-boi-canh.md).
- Tiếp theo: [Phase 5 — Báo cáo và bảo vệ](phase-5-bao-cao-va-bao-ve.md).
- Tên cột, kiểu dữ liệu, khóa ghép: tuân thủ [data contract](../data_contract.md).
- Git: [quy trình branch/PR](../06-git-workflow.md). N1 `chore/p4-repro-runbook`; N2 `docs/p4-playbook-cases`; N3 `feat/p4-demo`. Streamlit/Docker có branch riêng nếu đạt gate.

## 1. Kết quả cần có cuối ngày 25

Nhóm phải có một demo local khoảng 6 phút gồm bốn bước: xem phạm vi Web/Mobile và nguồn dữ liệu; so sánh top-50; mở các ca bất đồng; giải thích một quyết định vá theo tài sản. Phần AI xuất hiện như công cụ ước lượng vector, có nhãn “dự đoán”, có sai số và có giới hạn.

Demo bằng **CLI + notebook là mức tối thiểu được chấp nhận**. Streamlit chỉ thêm khi kết quả nghiên cứu và khả năng chạy lại đã ổn. Docker chỉ xem xét sau khi mọi đầu ra bắt buộc đã đạt; không đặt EC2/cloud thành điều kiện nộp bài.

| Đầu ra | Điều kiện cụ thể | Chủ trì |
|---|---|---|
| Luồng chạy local | Tạo lại bảng xếp hạng và hình từ snapshot cố định theo runbook | Người 1 |
| Demo bảo mật | Mỗi hình và case đều truy ngược được tới CVE, nguồn, ngày snapshot | Người 2 |
| Demo NLP | Hiển thị 8 thành phần AV/AC/PR/UI/S/C/I/A, không tráo dự đoán với nhãn quan sát | Người 3 |
| Bộ kết quả thống nhất | Dataset, model, ranking, figure cùng phiên bản được ghi lại | Cả nhóm |
| Kịch bản dự phòng | Notebook đã thực thi, bảng CSV và ảnh có thể mở khi không có mạng | Người 3 |

## 2. Điều kiện bắt đầu và cách xử lý phần còn thiếu

- Dataset `data/processed/cves.parquet` và `data/metadata.json` đã được đóng băng ở Phase 3.
- `rankings.csv` thể hiện ba chính sách CVSS, EPSS, KEV-first trên cùng tập đủ điều kiện.
- Có bảng `environmental_scores.csv`, ánh xạ `cve_asset_mapping.csv` và hàng đợi `priority_queue.csv` theo cặp CVE–tài sản.
- Baseline NLP đã được đánh giá trên test split cố định; có `predictions.csv` và model artifact.
- Có 3–5 case có bằng chứng; ít nhất một case Web và một case Mobile phía client/SDK/framework.
- Nếu Transformer chưa xong, dùng baseline và ghi rõ lý do, cấu hình đã thử, giới hạn tài nguyên; không chờ Transformer để bắt đầu tích hợp.
- Nếu một đầu ra chưa đạt, chủ sở hữu sửa trước; phần demo tương ứng hiển thị “chưa có dữ liệu”, không tự sinh kết quả thay thế.

## 3. Phân công và ngân sách thời gian

### Người 1 — Dữ liệu, môi trường chạy, nhóm trưởng: 8 giờ

1. **1 giờ:** kiểm kê artifact, đối chiếu `dataset_version`, ngày EPSS, thời điểm tải KEV, nguồn CVSS và split/model version.
2. **2 giờ:** hoàn thiện `docs/runbook.md`; ghi lệnh đúng với CLI thực tế, đường dẫn, môi trường và thời gian chạy đã đo.
3. **2 giờ:** thực hiện một lần tái tạo trên môi trường sạch hoặc máy thành viên khác; lưu log, so sánh các kết quả xác định.
4. **1 giờ:** ghép `reports/release-checklist.md`; ghi lỗi, chủ sở hữu, cách sửa và mức độ chặn demo.
5. **1 giờ:** kiểm tra README, dependency và link tài liệu; bỏ lệnh tham chiếu file không tồn tại.
6. **1 giờ:** họp chốt bản demo, phân loại việc bắt buộc và việc có thể bỏ, xác nhận bàn giao Phase 5.

**Vibe code chủ yếu ở:** script tái tạo nhỏ nếu cần, giao diện CLI hiện hữu và notebook gọi các module hiện hữu. Tránh viết lại collector/model chỉ để tích hợp.

**Review bằng tay:** chọn một CVE, lần theo dữ liệu thô → bản ghi chuẩn hóa → bảng ranking → hình → mô tả case; xác nhận không đổi ngày hoặc nguồn giữa các bước.

**Bàn giao:** runbook + log chạy + danh sách phiên bản vào cuối ngày 23; checklist đóng lỗi vào ngày 25. Người 3 thực thi lại runbook, Người 2 kiểm tra nghĩa của snapshot.

### Người 2 — Bảo mật, chính sách ưu tiên, tính đúng của demo: 8 giờ

1. **2 giờ:** rà soát ba bảng top-50: tập CVE đủ điều kiện, giá trị thiếu, thứ tự khi hòa điểm, số KEV và khả năng truy nguyên.
2. **2 giờ:** rà soát 3–5 case; nối rõ tài sản Web/Mobile, điều kiện bị ảnh hưởng, lý do bất đồng và quyết định vá.
3. **1 giờ:** sửa `docs/04-patch-playbook.md` để xác minh ảnh hưởng tài sản trước khi đưa CVE vào hàng đợi hành động.
4. **1 giờ:** kiểm tra giải thích Environmental và hàng đợi theo CVE–tài sản; tách giả định tổ chức khỏi dữ kiện công khai.
5. **1 giờ:** viết phần bảo mật trong `reports/demo-script.md`, chỉ chọn những ví dụ có trong dữ liệu thực.
6. **1 giờ:** review màn hình/notebook cùng Người 3 và diễn tập các câu hỏi “vì sao vá trước?”.

**Vibe code chủ yếu ở:** sửa lỗi tích hợp có căn cứ trong `src/analysis/compare_rankings.py`, `src/analysis/plots.py`, các module `src/environmental/`. Nội dung kết luận do Người 2 tự kiểm chứng.

**Review bằng tay:** tính lại thứ tự của 5–10 dòng nhỏ bằng quy tắc đã công bố; chọn một cặp CVE–tài sản để kiểm tra mapping và giải thích điểm Environmental.

**Bàn giao:** case và lời giải thích khóa vào ngày 23; rà soát cuối ngày 25. Người 1 kiểm tra nguồn, Người 3 kiểm tra cách hiển thị.

### Người 3 — ML và demo local: 8 giờ

1. **2 giờ:** tạo hoặc hoàn thiện `notebooks/03_demo.ipynb` để đọc artifact, gọi các hàm đã có và dẫn dắt bốn bước demo.
2. **1 giờ:** bổ sung màn hình/bảng phân biệt vector quan sát với vector dự đoán, mô hình sử dụng và giới hạn dự đoán.
3. **1 giờ:** kiểm tra model tải được, đầu vào trống được xử lý, không tự huấn luyện hoặc gọi mạng khi mở demo.
4. **1 giờ:** chạy lại notebook theo runbook Người 1; ghi lỗi phụ thuộc và sai khác đường dẫn.
5. **1 giờ:** chuẩn bị bản notebook đã thực thi, ảnh và CSV để trình bày khi không có mạng.
6. **2 giờ:** sửa lỗi và diễn tập; chỉ dùng phần thời gian còn lại cho `app.py` Streamlit nếu mức tối thiểu đã đạt.

**Vibe code chủ yếu ở:** `notebooks/03_demo.ipynb`, hàm inference hiện hữu của baseline, và `app.py` nếu quyết định làm thêm. Notebook/app chỉ gọi logic nghiệp vụ, không có công thức xếp hạng riêng.

**Review bằng tay:** hiển thị một CVE có nhãn và một mô tả chưa có nhãn trong bộ demo; trường hợp thứ hai chỉ minh họa inference, không được tuyên bố dự đoán đúng khi chưa có ground truth.

**Bàn giao:** notebook chạy được vào ngày 23; bản demo dự phòng và script hoàn chỉnh vào ngày 25. Người 1 chạy lại; Người 2 duyệt ngôn ngữ bảo mật.

## 4. File nào làm gì, đọc gì và tạo gì?

“Có sẵn” nghĩa là file đang tồn tại trong repo khi lập kế hoạch, có thể mới là khung TODO. “Mới theo kế hoạch” không có nghĩa file đã được triển khai. Các artifact được tạo bởi phase trước là đầu vào bắt buộc tại đây.

| File/nhóm file | Trạng thái và người sở hữu | Chức năng, đầu vào → đầu ra |
|---|---|---|
| `docs/runbook.md` | Mới theo kế hoạch, Người 1 | Hướng dẫn từ cài môi trường đến mở demo; config + snapshot → các lệnh, đầu ra kỳ vọng, thời gian đã đo và cách xử lý lỗi |
| `reports/release-checklist.md` | Mới theo kế hoạch, Người 1 | Theo dõi kiểm tra có người chịu trách nhiệm; log + artifact → trạng thái, bằng chứng và lỗi còn mở |
| `reports/demo-script.md` | Mới theo kế hoạch, Người 2/3 | Kịch bản 6 phút; kết quả đã xác minh → lời dẫn, thao tác, CVE chọn trước, phương án dự phòng |
| `notebooks/03_demo.ipynb` | Mới theo kế hoạch, Người 3 | Giao diện demo tối thiểu; các bảng đã tạo + model → bảng, hình, ví dụ inference; không sửa dataset gốc |
| `app.py` | Mới, **tùy chọn**, Người 3 | Streamlit đọc cùng artifact; lựa chọn CVE/tài sản → thông tin, thứ hạng và lý do; không đăng nhập, không database |
| `src/analysis/compare_rankings.py` | Có sẵn khung, Người 2 | Module xếp hạng đã hoàn thiện từ Phase 3; dataset + chính sách → `rankings.csv`; chỉ sửa nếu tích hợp phát hiện lỗi |
| `src/analysis/plots.py` | Có sẵn khung, Người 2 | `rankings.csv` + metadata → hình ở `reports/figures/`; mọi biểu đồ ghi phạm vi, N, ngày dữ liệu |
| `src/environmental/asset_inventory.py` | Có sẵn khung, Người 2 | Đọc inventory giả định + mapping → các cặp CVE–tài sản đã kiểm tra và lý do áp dụng |
| `src/environmental/cvss_environmental.py` | Có sẵn khung, Người 2 | Vector quan sát + cấu hình tài sản → điểm Environmental; dùng chung hàm đã được đối chiếu từ Phase 3 |
| `src/model/baseline.py` | Có sẵn khung, Người 3 | Huấn luyện/lưu baseline từ Phase 2; tích hợp giữ nguyên preprocessing và mapping nhãn |
| `src/model/predict.py` | Mới theo kế hoạch Phase 2, Người 3 | Nạp model đã huấn luyện + mô tả → vector/score dự đoán; notebook/app gọi chung, không tự fit lại |
| `src/model/distilbert_multihead.py` | Có sẵn khung, **tùy chọn**, Người 3 | Inference Transformer nếu có artifact hợp lệ; nếu không dùng thì trình bày baseline rõ ràng |
| `config/project.yaml` | Mới theo kế hoạch Phase 0/1, Người 1 | Mốc snapshot, phạm vi, đường dẫn dùng chung → cấu hình pipeline; không lưu API key |
| `config/assets.yaml` | Mới theo kế hoạch, Người 2 | Inventory giả định, độ quan trọng, giả định môi trường → bối cảnh phân tích tài sản |
| `config/model.yaml` | Mới theo kế hoạch, Người 3 | Seed, model và cấu hình inference → tái tạo kết quả ML; tham chiếu split chung từ project/dataset, không tạo split riêng |
| `data/processed/cves.parquet` | Artifact từ Phase 1–3, Người 1 | Dataset đã chuẩn hóa → input phân tích; giữ nguồn CVSS và thông tin thiếu dữ liệu |
| `data/metadata.json` | Artifact từ Phase 1–3, Người 1 | Ghi provenance, version, ngày tải và snapshot → căn cứ kiểm tra đồng nhất |
| `data/processed/predictions.csv` | Artifact từ Phase 2/3, Người 3 | Dự đoán theo CVE/model/split → demo và đánh giá; không ghi đè vector quan sát |
| `data/processed/rankings.csv` | Artifact từ Phase 3, Người 2 | Thứ hạng CVE theo ba chính sách → biểu đồ top-50 và truy vấn bất đồng |
| `data/processed/cve_asset_mapping.csv` | Artifact từ Phase 3, Người 2 | CVE + asset_id + bằng chứng/giả định → xác định CVE có liên quan tài sản nào |
| `data/processed/environmental_scores.csv` | Artifact từ Phase 3, Người 2 | Điểm theo cặp CVE–tài sản → giải thích tác động của môi trường |
| `data/processed/priority_queue.csv` | Artifact từ Phase 3, Người 2 | Cặp CVE–tài sản + lý do chính sách → danh sách hành động vá trong tổ chức giả định |
| `models/` | Artifact từ Phase 2/3, Người 3 | Model + label mapping + version → nạp inference; đóng gói hoặc hướng dẫn tải theo kích thước |
| `reports/figures/` | Artifact từ Phase 3, Người 2 | Hình PNG/SVG xuất từ số liệu → notebook, báo cáo và slide dùng chung |
| `docs/03-environmental-context.md` | Có sẵn, Người 2 | Tài sản và bằng chứng → giải thích giả định, thay đổi điểm và giới hạn |
| `docs/04-patch-playbook.md` | Có sẵn, Người 2 | Kết quả phân tích → quy trình quyết định; SLA chỉ là đề xuất cho tổ chức giả định |
| `README.md`, `requirements.txt` | Có sẵn, Người 1 | Ghi cách bắt đầu và dependency đã thử → người khác cài/chạy được; thống nhất với runbook |
| `deploy/Dockerfile` | Mới, **tùy chọn sau nghiệm thu**, Người 1 | Đóng gói môi trường local → image tái chạy; không yêu cầu triển khai cloud |

Nếu cần một script điều phối, chốt duy nhất `scripts/reproduce.py` do Người 1 sở hữu: đọc config, gọi các entry point có sẵn, trả mã lỗi khi bước bắt buộc thất bại. Đây là file mới tùy nhu cầu, không phải lý do viết lại toàn bộ pipeline.

## 5. Luồng demo và nội dung phải nhìn thấy

| Thời gian | Thao tác | Điều cần giải thích | Người dẫn |
|---|---|---|---|
| 0:00–0:40 | Mở metadata và phạm vi | Web/Mobile, ngày snapshot, số CVE đủ điều kiện, nguồn CVSS | Người 1 |
| 0:40–2:10 | Mở top-50 của ba chính sách | CVSS là severity, EPSS là dự báo khai thác, KEV-first là chính sách có tín hiệu đã khai thác | Người 2 |
| 2:10–3:40 | Mở một case Web và một case Mobile | Cùng dữ liệu nhưng thứ tự khác; mỗi khác biệt có số liệu và nguồn | Người 2 |
| 3:40–4:40 | Chọn cùng CVE ở tài sản khác nhau | Điều kiện bị ảnh hưởng, mức phơi nhiễm và tác động tài sản làm đổi hành động | Người 2 |
| 4:40–5:35 | Mở ví dụ dự đoán vector | Nhãn quan sát vs dự đoán, một lỗi mô hình, baseline/Transformer thực sự đã chạy | Người 3 |
| 5:35–6:00 | Mở hàng đợi và chốt kết luận | Thứ tự vá có lý do; AI hỗ trợ, người phân tích chịu trách nhiệm | Người 1 |

Không cần click xem mọi CVE trong lúc bảo vệ. Chọn trước ví dụ có bằng chứng; toàn bộ bảng vẫn phải có để giảng viên kiểm tra.

Notebook hoặc app phải cho thấy rõ:

- Bộ lọc chỉ đổi phần đang xem; nếu tái tính ranking sau lọc thì ghi rõ tập mới, không gọi đó là top-50 gốc.
- Tên chính sách thứ ba là **KEV-first**; KEV là tín hiệu nhị phân, không phải điểm số thứ ba liên tục.
- Quy tắc KEV-first: `is_kev` giảm dần → EPSS giảm dần → CVSS giảm dần → `cve_id` tăng dần, trên tập đủ điều kiện đã chốt.
- Điểm CVSS chính thức/quan sát và điểm suy ra từ vector dự đoán nằm ở cột hoặc panel riêng.
- “Không có trong KEV” nghĩa là chưa có trong catalog của snapshot, không kết luận chưa từng bị khai thác.
- Không dùng recall KEV của chính sách KEV-first để chứng minh chính sách đó dự đoán tốt hơn; đó là hệ quả thiết kế.
- Hàng đợi theo CVE–tài sản có đơn vị khác bảng xếp hạng CVE; không gộp số lượng hai bảng làm một.
- Tài sản Mobile phải là client, SDK hoặc framework thực sự liên quan; chỉ có backend Web chưa đủ chứng minh phạm vi Mobile.

## 6. Cách giao việc cho AI theo đơn vị nhỏ

Các prompt dưới đây là mẫu để thành viên tự dùng khi triển khai. Trước mỗi lần chạy, cung cấp `docs/data_contract.md`, nội dung file đang sửa và một mẫu dữ liệu đã bỏ thông tin nhạy cảm. AI không được tự bịa số liệu để lấp chỗ thiếu.

### Prompt A — Người 1: hoàn thiện runbook

```text
Đọc các entry point thực tế và docs/data_contract.md.
Chỉ cập nhật docs/runbook.md: ghi lệnh cài, chạy từ snapshot đã tải,
huấn luyện baseline khi cần, tái tạo ranking/figure và mở notebook demo.
Mỗi lệnh nêu working directory, input, output, điều kiện thành công.
Phân biệt chế độ offline và chế độ tải API. Không khẳng định lệnh đã chạy.
Không thêm cloud, service hoặc thư viện mới chỉ để điều phối.
```

Người 1 chạy từng lệnh thực tế, thay đường dẫn mẫu bằng đường dẫn đúng, rồi nhờ Người 3 thực hiện lại từ đầu. Không coi đoạn lệnh do AI viết là bằng chứng đã tái lập.

### Prompt B — Người 2: rà soát policy và câu chữ

```text
Đọc docs/04-patch-playbook.md, data contract và 10 dòng ranking/mapping
được cung cấp. Chỉ đề xuất bản sửa cho playbook: xác minh ảnh hưởng
tài sản trước khi quyết định hành động, giải thích KEV-first,
giữ riêng chính sách tổ chức và CVSS Environmental chính thức.
Đánh dấu mọi SLA/ngưỡng giả định. Liệt kê phát biểu thiếu bằng chứng.
Không biến KEV recall của KEV-first thành kết luận thắng/thua mô hình.
```

Người 2 tự đọc nguồn và quyết định sửa. Khi cần sửa code, yêu cầu AI chỉ thay một hàm có lỗi cụ thể, kèm dữ liệu nhỏ tái hiện lỗi; không thay chính sách giữa lúc chuẩn bị demo.

### Prompt C — Người 3: notebook demo tối thiểu

```text
Tạo notebooks/03_demo.ipynb theo data contract và artifact hiện có.
Notebook chỉ đọc dữ liệu, gọi module đã có và hiển thị 4 phần:
provenance, top-50/disagreement, context theo CVE–tài sản, NLP inference.
Thiếu file thì dừng với thông báo rõ; không tạo dữ liệu hoặc tự train.
Đặt nhãn observed/predicted, snapshot và mẫu số ở mọi phần phù hợp.
Không thêm công thức ranking trong notebook, không gọi mạng lúc mở demo.
```

Người 3 kiểm tra thứ tự cell, khởi động lại kernel và chạy toàn bộ; nhờ Người 2 xác nhận cách diễn đạt không biến dự đoán thành sự thật.

### Prompt D — Chỉ khi đủ thời gian: Streamlit

```text
Tạo app.py đọc cùng artifact với notebooks/03_demo.ipynb.
Chỉ làm bảng top-50, bộ lọc CVE/tài sản và bảng observed/predicted.
Tái sử dụng module nghiệp vụ, báo rõ file thiếu và dataset version.
Không thêm auth, API server, database, nền tảng cloud hoặc upload file.
Mọi thay đổi dependency phải được liệt kê để nhóm quyết định.
```

Giới hạn lần đầu 90 phút; nếu lỗi UI chưa giải quyết thì quay về notebook. Không lấy giờ sửa case bảo mật để làm đẹp giao diện.

## 7. Kiểm tra bắt buộc và bằng chứng cần giữ

| Kiểm tra | Cách làm có ý nghĩa | Bằng chứng |
|---|---|---|
| Tính đồng nhất | So sánh version/hash đầu vào và metadata giữa các artifact | Dòng checklist dẫn tới log/manifest thực tế |
| Khả năng tái lập | Chạy lại xử lý từ snapshot trên máy khác; so sánh CVE/top-50, metric theo độ chính xác đã quy định | Log và kết quả so sánh |
| Tính đúng của ranking | Kiểm tra tie-break, KEV-first, giá trị thiếu bằng fixture nhỏ của Phase 3 | Các kiểm tra hiện có chạy qua; ví dụ review bằng tay |
| Tính đúng của mapping | So product/version/điều kiện ảnh hưởng với bằng chứng case | Link advisory/CVE và giả định asset |
| Tính đúng của CVSS | Chạy lại các ca kiểm tra công thức đã có; không viết công thức mới ở UI | Kết quả kiểm tra từ Phase 3 |
| Tách predicted/observed | Chọn CVE dự đoán khác nhãn; mở cả CSV và demo | Hai cột khác nhau, giải thích lỗi mô hình |
| Demo không mạng | Mở artifact có sẵn, chạy các cell demo và inference local | Ghi thiết bị, lệnh và trạng thái thực tế |
| Dữ liệu thiếu | Thử thiếu một artifact bản sao và mô tả rỗng | Thông báo lỗi, không có kết quả giả |
| Tài liệu | Mở các link local và thực thi lệnh README/runbook | Các link đúng và lệnh tạo đầu ra |

Không bổ sung hàng chục unit test cho màu sắc hay bố cục notebook. Chạy lại test nghiệp vụ đã có; chỉ thêm kiểm tra khi phát hiện rủi ro thật như trộn snapshot, join nhân dòng hoặc phân loại nhầm CVSS dự đoán.

## 8. Nhịp bàn giao ngày 21–25

| Ngày | Người 1 | Người 2 | Người 3 | Điểm chốt |
|---|---|---|---|---|
| 21 | Kiểm kê version/đường dẫn | Review ranking/case | Dựng notebook | Cùng đọc một bộ artifact |
| 22 | Viết runbook, sửa dependency | Sửa playbook/context | Ghép inference và bảng | Demo tối thiểu không phụ thuộc mạng |
| 23 | Chạy tái lập và giữ log | Khóa ví dụ Web/Mobile | Chạy notebook từ kernel sạch | Bàn giao bản demo đầu tiên |
| 24 | Điều phối sửa lỗi chặn | Review bằng chứng từng lời dẫn | Chuẩn bị demo dự phòng | Một lần diễn tập đầy đủ |
| 25 | Chốt checklist | Duyệt nội dung bảo mật | Đóng phiên bản demo | Chuyển Phase 5, dừng thêm tính năng |

## 9. Khi gặp vấn đề hoặc thiếu giờ

- **API lỗi hoặc mất mạng:** dùng snapshot hợp lệ đã lưu và công bố ngày; không trộn dữ liệu tải mới vào một phần kết quả.
- **GPU/Transformer lỗi:** baseline là đường nộp chính; ghi Transformer là chưa hoàn thành, không dựng bảng metric so sánh giả.
- **Streamlit lỗi:** notebook + CSV + figure vẫn đáp ứng demo; xóa lệnh chạy app chưa hoạt động khỏi hướng dẫn mặc định.
- **Máy thành viên khác chạy khác kết quả:** kiểm tra version, seed, split và sort trước; giữ một bản kết quả đã xác minh, ghi phần chưa tái lập được.
- **N ≤ 50 CVE đủ điều kiện:** chọn K < N (ví dụ top-10 nếu N > 10), công bố N/K và giới hạn chưa đạt top-50 có ý nghĩa; N < 2 chỉ mô tả dữ liệu, không tính so sánh ưu tiên. Không thêm CVE ngoài phạm vi chỉ để đủ biểu đồ.
- **Case Mobile không đủ bằng chứng:** Người 2 thay bằng case client/SDK/framework được xác minh; không đổi nhãn backend thành Mobile để qua checklist.
- **Hình và báo cáo lệch số:** lấy artifact đóng băng làm nguồn, xuất lại hình; tránh sửa nhãn số thủ công trong ảnh.

## 10. Gate kết thúc Phase 4

- [ ] Người 3 tái tạo được kết quả theo runbook Người 1 và lưu bằng chứng.
- [ ] Notebook demo chạy hết từ kernel sạch; không tự tải API hoặc train lại.
- [ ] Ba chính sách dùng cùng tập CVE đủ điều kiện, cùng snapshot và quy tắc hòa điểm.
- [ ] KEV-first được mô tả là chính sách; không có kết luận vòng tròn về recall.
- [ ] Có 3–5 case đã kiểm tra nguồn, bao gồm Web và Mobile thực sự.
- [ ] Quyết định vá có bước xác nhận tài sản bị ảnh hưởng, không suy ra SLA bắt buộc cho mọi tổ chức.
- [ ] Vector/score dự đoán được tách khỏi nhãn/score quan sát ở mọi đầu ra demo.
- [ ] Có bản demo dự phòng, script 6 phút và danh sách hạn chế trung thực.
- [ ] Không còn lỗi chặn việc mở kết quả; lỗi nhỏ có người chịu trách nhiệm và phương án xử lý.
- [ ] Ngày 25 chốt tập artifact để Phase 5 chỉ viết, kiểm chứng và luyện bảo vệ.
