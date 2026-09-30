# Phase 3 — So sánh ưu tiên vá và giải thích bằng bối cảnh Web/mobile

> **Ngày 14–20 / 30 ngày. Ngân sách: khoảng 16 giờ/người.**
> Đây là phase trọng tâm bảo mật; mọi kết quả số trong báo cáo phải sinh từ dữ liệu đã lưu.
> [Kế hoạch tổng](../05-ke-hoach-phan-cong.md) · [Phase trước](phase-2-mo-hinh-nlp.md) · [Phase sau](phase-4-tich-hop-va-demo.md) · [Hợp đồng dữ liệu](../data_contract.md).
> Git: [quy trình branch/PR](../06-git-workflow.md). N1 `test/p3-ranking-quality`; N2 `feat/p3-ranking-context`; N3 `feat/p3-security-plots`.

## 1. Câu hỏi phải trả lời sau phase này

1. Cùng ngân sách vá K CVE Web/mobile, xếp theo CVSS và EPSS chọn những CVE khác nhau như thế nào?
2. Các danh sách đó bao phủ bao nhiêu CVE đã được CISA ghi nhận khai thác trong snapshot của nhóm?
3. Một CVE áp dụng lên tài sản cụ thể nào, tác động nghiệp vụ là gì, và bối cảnh có làm thay đổi thứ tự xử lý không?
4. Mô hình AI ở Phase 2 có sai số nào khiến chuyên viên phải kiểm tra lại trước khi dùng?

**Sản phẩm phải nhìn thấy được:** bảng toàn bộ thứ hạng, biểu đồ top-50 theo ba chính sách, scatter CVSS–EPSS có đánh dấu KEV, đối chiếu bối cảnh trên cohort CVE–asset, 3–5 case study có nguồn và playbook ưu tiên vá.
Kết luận phải dựa trên mẫu quan sát. Không hứa trước một ô CVSS–EPSS sẽ chiếm đa số hoặc chính sách nào luôn tốt nhất.

## 2. Chốt nghĩa của các tín hiệu trước khi viết code

| Thành phần | Dùng để trả lời | Không được diễn giải thành |
|---|---|---|
| CVSS Base quan sát, v3.1 | Đặc tính kỹ thuật và severity của lỗ hổng | Xác suất bị khai thác hoặc quyết định vá cho mọi tổ chức |
| EPSS tại ngày T | Ước lượng khả năng khai thác trong 30 ngày tiếp theo | Xác suất riêng của một tài sản trong công ty |
| `is_kev` tại snapshot T | Có trong danh mục khai thác đã biết hay không | Một điểm số liên tục hoặc nhãn âm chắc chắn khi vắng mặt |
| Environmental | Severity khi xét các yêu cầu/bối cảnh được nêu | Xác suất khai thác hoặc tổn thất tài chính đã đo |
| Hàng đợi bối cảnh | Quy tắc minh bạch của tổ chức giả định | Chuẩn mới thay cho CVSS, EPSS hoặc SSVC |

Tra nghĩa CVSS theo [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document), EPSS theo [FIRST — Using EPSS](https://www.first.org/epss/using-epss), và điều kiện danh mục theo [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Không gọi ba chính sách là “ba thang điểm độc lập”: KEV là danh mục nhị phân, được đưa vào chính sách **KEV-first** có tie-break rõ ràng.

### 2.1. Cùng snapshot, cùng mẫu so sánh

- Ngày T là ngày snapshot thống nhất trong `data/metadata.json`; EPSS dùng `epss_date=T`; KEV phải có lịch sử/snapshot tương thích T và ngày thu thập được ghi lại.
- CVE phải được công bố không muộn hơn T. Không ghép EPSS cũ với KEV hiện tại rồi gọi là thí nghiệm dự báo trong quá khứ.
- Phân tích chính là **đối chiếu quan sát tại snapshot T**. Dữ liệu khai thác có thể đã phản ánh vào EPSS ở T; KEV không phải tập kiểm định dự báo độc lập trong thiết kế này.
- Việc “không thấy trong KEV” nghĩa là không có trong danh mục đã tải; không chứng minh CVE chưa từng bị khai thác.
- Tải KEV lỗi/không đủ snapshot phải là unknown, không điền toàn bộ `false`.
- Không cần triển khai thí nghiệm dự báo tương lai trong một tháng. Nếu mở rộng, phải có EPSS trước cửa sổ và outcome sau cửa sổ; vẫn ghi hạn chế ngày thêm KEV không phải ngày khai thác đầu tiên.

## 3. Hai cohort, hai mục đích — không nhập nhằng mẫu số

### 3.1. Cohort RQ2: một dòng cho mỗi CVE

Điều kiện: `in_scope=true`, CVSS v3.1 hợp lệ và Base Score quan sát, EPSS hợp lệ tại T, trạng thái KEV đã xác định từ snapshot đầy đủ.
Tên trường và biểu diễn missing theo [data contract](../data_contract.md); cột xác suất EPSS là `epss`.
Đây là giao của những CVE đủ cả ba nguồn, dùng nguyên cùng tập ID cho ba chính sách.

Nhóm hướng tới ít nhất **200 CVE đủ điều kiện** để top-50 có khả năng phân biệt, nhưng không bịa hoặc nới scope âm thầm để đạt số này.
Nếu mẫu nhỏ: báo nguyên nhân, mở rộng thu thập trong phạm vi Web/mobile nếu còn giờ, ghi phần mất dữ liệu theo nguồn.
Dùng top-50 chính thức khi `N>50`; chạy thêm K=10/20 nếu phù hợp.
Nếu `N<=50`, bảng toàn bộ vẫn được xuất nhưng so sánh chọn lọc dùng K nhỏ hơn N; đặt tiêu đề “top-K trên N CVE”, không gọi là top-50 có ý nghĩa chọn lọc.
Với `N<2`, dừng tính so sánh thứ hạng và sửa dữ liệu hoặc báo không đủ bằng chứng.

### 3.2. Cohort RQ3: một dòng cho mỗi cặp CVE–tài sản

Tài sản có ứng dụng Web/API và **client/framework/SDK mobile thực sự**; backend phục vụ mobile vẫn chỉ chứng minh phần Web/backend.
Kịch bản ưu tiên: hệ thống thương mại điện tử giả định, 5–6 tài sản; ghi stack/version và đường tiếp cận của từng tài sản.
Chọn khoảng 15–30 cặp CVE–asset có đủ bằng chứng/giả định minh bạch; mở rộng tối đa 50 nếu làm được.
Không ánh xạ toàn bộ CVE vào mọi tài sản. Cặp trùng khóa `(cve_id, asset_id)` là lỗi.

Áp dụng trước xếp ưu tiên: `affected` mới vào danh sách vá; `unaffected` giữ trong bảng đối chiếu kèm lý do; `needs_review` vào danh sách cần xác minh.
KEV trên tài sản `needs_review` phải được đánh dấu cần xác minh sớm, không biến mất và cũng không được coi là chắc chắn affected.
Khi so Base với Environmental, dùng **cùng tập cặp** có đủ cả hai điểm; báo số cặp bị loại.
Một CVE trên hai tài sản là hai đơn vị công việc; bảng phải dùng nhãn `CVE / asset` để tránh hiểu lầm đếm hai lỗ hổng khác nhau.

## 4. Ba chính sách RQ2 và cách đánh giá chính xác

| Chính sách | Thứ tự sort cố định | Lý do |
|---|---|---|
| `cvss` | CVSS Base giảm dần → `cve_id` tăng dần | Quan sát thứ tự chỉ theo severity; tie-break không ngầm sử dụng EPSS |
| `epss` | `epss` giảm dần → `cve_id` tăng dần | Quan sát thứ tự chỉ theo xác suất khai thác |
| `kev_first` | `is_kev` giảm dần → `epss` giảm dần → CVSS Base giảm dần → `cve_id` tăng dần | Ưu tiên bằng chứng khai thác đã biết, sau đó phá hòa minh bạch |

Lưu ranking đầy đủ trước, sau đó cắt top-K để vẽ; không chỉ giữ 50 dòng rồi mới tính thống kê.
`cve_id` tăng dần là thứ tự chuỗi xác định để tái lập, không có ý nghĩa bảo mật.
Nêu số dòng đồng điểm tại ranh giới K để người đọc biết top-K có thể nhạy với tie-break.

| Metric | Công thức / cách dùng | Giới hạn cần ghi |
|---|---|---|
| Jaccard@K | `|topK(A) ∩ topK(B)| / |topK(A) ∪ topK(B)|` | Cùng K, cùng cohort; đo giống danh sách, không đo chất lượng vá |
| Kendall tau-b | Tính trên các cặp điểm CVSS/EPSS gốc cùng CVE, có xử lý ties | Không tính trên ID-order đã phá hòa; hằng số hoặc N nhỏ thì ghi undefined |
| KEV Recall@K | `số KEV trong topK / tổng KEV trong cohort` | Tính quan sát cho `cvss` và `epss`; denominator=0 thì N/A |
| KEV hit count | Số CVE KEV trong top-K, kèm tổng K và tổng KEV | Dễ diễn giải; vắng KEV không là false positive chắc chắn |
| Rank delta | Ví dụ `cvss_rank - epss_rank`, ghi hướng dấu trong bảng | Chỉ trên cùng cohort, dùng để chọn case bất đồng |

**Không tuyên bố KEV-first “chính xác nhất” vì KEV Recall@K cao:** chính sách đã dùng trực tiếp KEV để sort.
Có thể hiển thị vị trí/hit count của KEV-first như đặc tính vận hành; không dùng nó làm kiểm định độc lập.
Không tính “accuracy dự báo khai thác” bằng cách coi mọi CVE không nằm KEV là nhãn âm.

Ngưỡng scatter minh họa dự kiến: CVSS cao `>=7.0`, EPSS cao `>=0.10`; khóa trong `config/project.yaml` trước xem kết quả.
Ngưỡng EPSS 0.10 là lựa chọn minh họa của nhóm, không phải chuẩn bắt buộc; thử thêm 0.01 và 0.50 trong phụ lục nếu đủ dữ liệu.
Các ngưỡng dùng chia ô để đọc case, không thay đổi ba chính sách ranking liên tục.
Nếu dùng trục log cho EPSS, xử lý EPSS=0 bằng quy tắc chỉ dành cho hiển thị, ghi epsilon trong chú thích; không sửa điểm trong CSV.

## 5. Bối cảnh: cách làm đủ đúng và đủ nhỏ cho một tháng

### 5.1. Inventory và bằng chứng ánh xạ

Mỗi tài sản trong `config/assets.yaml` cần `asset_id`, mô tả, loại Web/mobile, sản phẩm/thành phần, phiên bản giả định, exposure, CR/IR/AR và lý do.
Mỗi mapping lưu product/version match, điều kiện affected, URL advisory, ghi chú phần giả định, trạng thái applicability và người review.
Phiên bản giả định phải nằm trong dải affected được nguồn mô tả; không chọn tùy ý rồi tuyên bố đã xác minh trên hệ thống thật.
Kịch bản giả định không cho phép bịa advisory, CVE, vector hoặc bằng chứng khai thác.

### 5.2. Environmental đúng nghĩa

- Dùng cùng Base vector quan sát; lưu vector Environmental và giải thích từng trường thay đổi.
- Mặc định các Modified Metric và CR/IR/AR chưa xác định là `X`; CR/IR/AR chỉ đổi khi inventory có lý do nghiệp vụ.
- Temporal `E/RL/RC` mặc định `X`; không biến EPSS thành `E` hoặc nhân EPSS vào công thức CVSS.
- “Nằm trong intranet” không tự động làm `MAV:A/L`; phân biệt đường truy cập mạng với tấn công đòi adjacent/local.
- “Có WAF” không tự động thành `MAC:H`; phải giải thích điều kiện khai thác nào thực sự bị thay đổi và bằng chứng/giả định nào hỗ trợ.
- “Có backup/HA/mã hóa” không tự động hạ MC/MI/MA; chỉ phản ánh khi có lập luận tác động tương ứng trong kịch bản.
- Khi không đủ căn cứ, giữ `X`, ghi uncertainty/exposure ngoài vector; không ép mọi biện pháp thành một điểm CVSS thấp hơn.

Đối chiếu phần Attack Vector và Environmental trong [đặc tả FIRST v3.1](https://www.first.org/cvss/v3.1/specification-document).
Chỉ cần 1–2 thay đổi có căn cứ mỗi case; không cần chỉnh hết tám metric để làm biểu đồ thay đổi mạnh.
Environmental có thể bằng Base hoặc thứ tự không thay đổi; đó vẫn là kết quả hợp lệ.

### 5.3. Hàng đợi hành động minh bạch

Đề xuất chính sách minh họa `context-v1` trong `src/analysis/context_priority.py`:

1. Kiểm tra applicability. `unaffected` có lý do được giữ trong mapping, không vào patch queue; `needs_review` có `queue_status=review_required`.
2. Exposure chưa biết hoặc thiếu applicability/score/EPSS cũng có `queue_status=review_required`, lý do thiếu được ghi trong `priority_reason`, `recommended_action` yêu cầu xác minh sớm nếu KEV; không điền điểm bằng 0.
3. Với các cặp affected/đủ dữ liệu, sort: KEV giảm dần → exposure priority giảm dần → Environmental giảm dần → `epss` giảm dần → `cve_id`, `asset_id` tăng dần.
4. Exposure priority minh họa: internet=2, internal=1, isolated=0; cấu hình/định nghĩa phải ghi rõ và không tự làm đổi MAV.
5. Xuất các trường theo contract: `queue_status`, `priority_rank`, `priority_reason`, `recommended_action`, `policy_version`, `context_version`, `dataset_version`; cùng ID, applicability và tín hiệu dùng xếp hạng.

Đây là quy tắc của tổ chức giả định, không khẳng định tối ưu cho mọi nơi.
Người 2 kiểm tra sensitivity trên cùng cặp khi đổi thứ tự exposure/Environmental; báo kết quả thay đổi trước khi khuyến nghị chính sách.
`priority_reason` phải đọc được, ví dụ “Áp dụng cho phiên bản giả định; có KEV; public-facing; cần xác minh bản vá với vendor”.
Đối chiếu top-10 trước/sau bối cảnh nếu số cặp đủ; nếu ít hơn, chọn K nhỏ hơn N và ghi K thực tế.
Không quy đổi rank delta thành “tiết kiệm X giờ” hoặc “ngăn Y vụ tấn công” khi chưa có dữ liệu effort/outcome.

## 6. Phân công cụ thể — mỗi người khoảng 16 giờ

### Người 1 — Chất lượng cohort, tái lập và bằng chứng: 16 giờ

| Mã | Việc và đầu ra | File chính | Giờ | Review |
|---|---|---|---:|---|
| P3-N1-1 | Chốt eligibility, bảng loại/missing và kiểm tra snapshot T | `src/collect/build_dataset.py`, `data/metadata.json` | 3 | Người 2 |
| P3-N1-2 | Rà số CVE đủ so top-50; hỗ trợ bổ sung dữ liệu trong scope nếu cần | `config/project.yaml`, `src/collect/filter_scope.py` | 2 | Người 2 |
| P3-N1-3 | Kiểm thử join/key/ranking deterministic bằng dữ liệu nhỏ | `tests/test_rankings.py` (mới), artifact CSV | 3 | Người 2 |
| P3-N1-4 | Viết một case Web có nguồn và kiểm tra nguồn của các case còn lại | `docs/analysis-results.md`, bảng mapping | 3 | Người 2 |
| P3-N1-5 | Chạy lại toàn bộ xuất CSV/plot trên snapshot khóa, kiểm tra metadata | Báo cáo chạy và config | 3 | Người 3 |
| P3-N1-6 | Đóng gói artifact, chốt bàn giao Phase 4, giải quyết blocker | Data contract, bảng task | 2 | Cả nhóm |

### Người 2 — Ranking, bối cảnh và kết luận bảo mật: 16 giờ

| Mã | Việc và đầu ra | File chính | Giờ | Review |
|---|---|---|---:|---|
| P3-N2-1 | Hoàn thiện ranking sơ bộ nhận từ ngày 13 thành ba chính sách, bảng đầy đủ và metric RQ2 | `src/analysis/compare_rankings.py` | 4 | Người 1 |
| P3-N2-2 | Hoàn thiện Environmental, mapping, policy context tối thiểu | `src/environmental/*.py`, `src/analysis/context_priority.py` (mới) | 4 | Người 1 |
| P3-N2-3 | Viết 1–2 case bối cảnh; tích hợp các case từ Người 1/3 | `docs/analysis-results.md` | 3 | Cả nhóm |
| P3-N2-4 | Sửa hướng dẫn Environmental sai/đơn giản hóa; viết playbook | `docs/03-environmental-context.md`, `docs/04-patch-playbook.md` | 3 | Người 3 |
| P3-N2-5 | Review plot, giải thích kết quả và gate cuối phase | Module plot, tài liệu và CSV | 2 | Cả nhóm |

**Cắt phạm vi để vừa giờ:** dùng 15 cặp có căn cứ trước, mở rộng sau; ưu tiên scorer/ba chính sách/ba case hoàn chỉnh hơn 50 case sơ sài.
Nếu tự cài Environmental vượt ngân sách, dùng thư viện triển khai v3.1 sau khi kiểm tra phiên bản và đối chiếu độc lập; vẫn giữ wrapper/interface/tests.
Không đổi sang cộng trọng số tùy ý rồi gọi là CVSS Environmental.

### Người 3 — Biểu đồ, kiểm chứng model và hợp đồng demo: 16 giờ

| Mã | Việc và đầu ra | File chính | Giờ | Review |
|---|---|---|---:|---|
| P3-N3-1 | Viết plot từ artifact đã xuất, không thu thập/train trong plot | `src/analysis/plots.py` qua PR giao riêng | 4 | Người 2 |
| P3-N3-2 | Viết một case mobile client/framework/SDK có nguồn và đường tác động | `docs/analysis-results.md`, mapping | 3 | Người 2 |
| P3-N3-3 | So sánh ranking dự đoán/quan sát trên cùng held-out eligible subset | `src/model/evaluate.py`, `notebooks/02_model_eval.ipynb` | 2 | Người 2 |
| P3-N3-4 | Kiểm tra điểm/vector Environmental và plot với một case bằng tay | `tests/test_cvss.py`, plot/CSV | 3 | Người 2 |
| P3-N3-5 | Chốt trường UI cần đọc, bảng tra CVE, trạng thái missing/review | `docs/data_contract.md`, thiết kế app Phase 4 | 2 | Người 1 |
| P3-N3-6 | Review artifact, caption, mock luồng trình bày từ file offline | Tài liệu/figures | 2 | Cả nhóm |

`plots.py` vẫn thuộc trách nhiệm cuối của Người 2, nhưng Người 3 thực hiện PR này; tránh hai người sửa cùng file đồng thời.
Người 3 không tiếp tục tuning DistilBERT trong phase này; nếu chưa có prediction hợp lệ, ghi thiếu thí nghiệm phụ và hoàn thiện biểu đồ chính.

## 7. Bản đồ file và interface cần triển khai

| File | Hiện trạng / người làm | Chức năng, input → output |
|---|---|---|
| `src/analysis/compare_rankings.py` | Có TODO; Người 2 | `build_rankings(cohort, policies)`; `evaluate_rankings(...)`; dataset → ranking đầy đủ + metric; không tự tải API |
| `src/analysis/plots.py` | Có TODO; Người 3, Người 2 review | Ranking + dataset + context → PNG/SVG và caption; không tự tính một policy khác |
| `src/environmental/asset_inventory.py` | Bổ sung từ Phase 2; Người 2 | `load_assets(path)`, `validate_mapping(...)`; YAML + mapping → inventory/mapping hợp lệ |
| `src/environmental/cvss_environmental.py` | Mở rộng scorer Phase 2; Người 2 | `environmental_score(base_vector, metrics)` → vector/score; kiểm tra v3.1, X, Roundup |
| `src/analysis/context_priority.py` | Mới; Người 2 | `build_priority_queue(...)`; mapping + asset + score/EPSS/KEV → patch queue và review_required |
| `config/assets.yaml` | Tiếp tục Phase 2; Người 2 | Inventory, giả định, CR/IR/AR, exposure; không đưa trực tiếp KEV/EPSS thay đổi từng ngày vào YAML |
| `config/project.yaml` | Người 1 cập nhật yêu cầu Người 2 | Snapshot/cohort/K/ngưỡng minh họa/policy_version; thay đổi có log |
| `docs/analysis-results.md` | Người 2 tổng hợp từ ba người | Phương pháp, kết quả thật, caption, case và hạn chế; link artifact và URL nguồn |
| `docs/03-environmental-context.md` | Có sẵn; Người 2 sửa | Thay quy tắc tự động intranet/WAF/backup; mô tả kịch bản thật của đồ án |
| `docs/04-patch-playbook.md` | Có sẵn; Người 2 sửa | Quy trình applicability → bằng chứng khai thác → bối cảnh → hành động/review; owner và hạn giả định |
| `tests/test_rankings.py` | Mới; Người 1 | Fixture có ties/KEV/missing; kiểm tra cùng cohort, sort, metric và không nhân dòng |
| `tests/test_cvss.py` | Từ Phase 2; Người 3 bổ sung | Expected Environmental đối chiếu độc lập; test X, Scope, tác động 0, giá trị invalid |

**Artifact theo contract:** `data/processed/rankings.csv`, `environmental_scores.csv`, `cve_asset_mapping.csv`, `priority_queue.csv`; đặt chung trong `data/processed/`.
`rankings.csv` một dòng/CVE, có `cvss_base_score`, `epss`, `is_kev`, `cvss_rank`, `epss_rank`, `kev_first_rank`, `epss_date`, `cohort_id`, `policy_version`, `dataset_version`.
`environmental_scores.csv` khóa cặp, có `base_vector`, `base_score`, `environmental_vector`, `environmental_score`, CR/IR/AR, `modification_reason`, `score_source=observed`, `context_version`, `dataset_version`.
Thêm `reports/ranking_metrics.json` và `reports/figures/`; mọi file có metadata hoặc manifest gắn `dataset_version`, snapshot T và `policy_version` khi áp dụng.
`predictions.csv` chỉ phục vụ bảng phụ; không âm thầm thay CVSS quan sát thiếu bằng CVSS dự đoán trong cohort chính.

## 8. Biểu đồ bắt buộc và cách đọc

| File dự kiến trong `reports/figures/` | Hình cần vẽ | Người xem rút được điều gì |
|---|---|---|
| `cvss_epss_scatter.png` | X=CVSS, Y=EPSS, màu/marker KEV; chú thích ngưỡng và T | Hai tín hiệu có thể bất đồng; mỗi điểm có CVE để truy lại |
| `top50_three_policies.png` | Ba panel hoặc bảng màu 50 hàng: CVSS / EPSS / KEV-first | CVE nào được chọn/đổi vị trí; không đặt KEV như điểm cùng trục 0–10 |
| `topk_overlap.png` | Ma trận Jaccard theo cùng K, có N và tie policy | Các chính sách chọn danh sách giống nhau tới đâu |
| `kev_recall_at_k.png` | CVSS và EPSS, K hợp lệ, hit count/tổng KEV | Mức bao phủ KEV quan sát; không là dự báo độc lập |
| `context_rank_changes.png` | Slope/dumbbell Base→Environmental trên cùng CVE–asset | Bối cảnh có làm đổi severity/thứ tự trong kịch bản không |

Hình top-50 phải đủ đọc: có thể chia thành 2 trang/ảnh mỗi trang 25 hàng và kèm CSV đầy đủ; tránh 150 cột chữ quá nhỏ.
Nếu N không đủ, đổi tên file/tiêu đề thành K thực tế và giải thích lý do; không giữ nhãn top-50 giả.
Mỗi caption ghi cohort, N, K, snapshot, tie-break, đơn vị CVE hay cặp CVE–asset và một câu giới hạn diễn giải.

## 9. Case study: mẫu phải điền bằng nguồn thật

Chọn **3–5 case**, tối thiểu một Web và một mobile client/framework/SDK; cố gắng có cùng một CVE ở hai bối cảnh khi evidence/giả định hỗ trợ.
Chọn từ rank delta và/hoặc bối cảnh, không hứa phải lấp đầy cả bốn ô scatter.
Nếu không có mobile trong cohort đủ điểm, bổ sung một case mobile định tính có nguồn, ghi lý do thiếu và không đưa vào bảng số liệu đủ-ba-nguồn.

Mỗi case viết khoảng 0,5–1 trang theo các trường sau:

1. **CVE / thành phần / loại ứng dụng:** sản phẩm, phiên bản bị ảnh hưởng, Web hay mobile thật sự; URL vendor/CNA/NVD và ngày truy cập.
2. **Cơ chế bảo mật:** input/điều kiện có thể bị lợi dụng, cần quyền/tương tác gì, vượt ranh giới nào, tác động C/I/A. Mô tả nguyên lý, không chạy exploit.
3. **Tín hiệu quan sát:** vector, nguồn CVSS, điểm, EPSS/date, KEV/dateAdded; thiếu gì ghi missing.
4. **Bất đồng:** `cvss_rank` / `epss_rank` / `kev_first_rank` trên đúng cohort, hoặc lý do case chỉ định tính.
5. **Tài sản giả định:** version, dữ liệu/nghiệp vụ, exposure, applicability và bằng chứng mapping.
6. **Bối cảnh:** metric Environmental nào đổi/giữ nguyên, lý do và yếu tố ngoài CVSS.
7. **Quyết định và giới hạn:** xử lý trước/sau/xác minh, ai phụ trách, nguồn hướng dẫn vá vendor, điều gì có thể làm quyết định thay đổi.

Không kết luận CVSS cao–EPSS thấp là “vá lãng phí”: xác suất thấp vẫn có thể đáng ưu tiên nếu tác động lớn hoặc tài sản trọng yếu.
Không kết luận CVSS thấp–EPSS cao luôn phải vá trước mọi tài sản: applicability, mức phơi lộ và nghiệp vụ vẫn phải xem xét.

## 10. Prompt vibe code chia nhỏ

**P3-A — Người 2, ranking:**

```text
Đọc docs/data_contract.md và Phase 3. Chỉ sửa compare_rankings.py.
Nhận cùng cohort có CVSS3.1/EPSS/KEV đầy đủ. Implement chính xác 3 sort keys:
CVSS desc,CVE asc; EPSS desc,CVE asc; KEV desc,EPSS desc,CVSS desc,CVE asc.
Xuất ranking đầy đủ và metric Jaccard@K, Kendall tau-b trên score gốc,
KEV Recall@K chỉ CVSS/EPSS. Denominator=0 hoặc điểm hằng thì xuất N/A có lý do.
Không thêm điểm tổng hợp, không gọi API, không fill missing bằng 0.
```

**P3-B — Người 2, context:**

```text
Tạo context_priority.py theo contract. Applicability được xét trước KEV;
unaffected giữ lý do; needs_review/unknown exposure có queue_status=review_required.
Affected và đủ dữ liệu sort KEV, exposure_priority, environmental_score, epss
giảm dần rồi cve_id,asset_id tăng dần. Xuất priority_rank, priority_reason,
recommended_action, policy_version, context_version và dataset_version.
Không suy MAV từ intranet hoặc MAC từ WAF. Không nhân EPSS với CVSS để đặt tên
Environmental. Giữ unknown/missing và đánh dấu KEV cần xác minh.
```

**P3-C — Người 3, plot:**

```text
Chỉ triển khai plots.py đọc các artifact đã xuất. Tạo scatter, ba panel top-K,
Jaccard, KEV recall CVSS/EPSS và context rank changes. Caption có N,K,T,cohort.
Biểu đồ top-K hiển thị CVE và marker KEV; KEV-first là chính sách, không phải score.
Nếu EPSS log-scale, không thay điểm gốc; ghi quy tắc hiển thị EPSS=0.
Nếu thiếu artifact hoặc N quá nhỏ, báo thông tin cụ thể, không tạo dữ liệu giả.
```

**P3-D — Người 1, kiểm tra độc lập:**

```text
Viết tests/test_rankings.py với fixture nhỏ ghi rõ synthetic, tách nghiên cứu.
Kiểm tra ties ổn định, input đảo dòng vẫn cùng ranking, cùng tập CVE giữa policies,
missing bị loại có lý do, KEV=0 tạo Recall N/A, K>=N không được gọi phân tích chọn lọc.
Tính tay một trường hợp Jaccard/Recall, không chỉ gọi lại chính hàm cần kiểm thử.
```

## 11. Lịch ngày 14–20 và gate bàn giao

| Ngày | Người 1 | Người 2 | Người 3 | Đầu ra cần nhìn thấy |
|---|---|---|---|---|
| 14 | Chốt cohort/exclusions | Chạy ba ranking | Chuẩn bị plot từ CSV mẫu thật | Ranking toàn bộ, N/KEV/K rõ |
| 15 | Review ties/metric | Chốt metric và inventory | Scatter + top-K | Bộ hình RQ2 đầu tiên |
| 16 | Viết case Web | Environmental/mapping | Viết case mobile, kiểm tra scorer | Case có URL và applicability |
| 17 | Kiểm tra nguồn/join | Context queue + case hai bối cảnh | Context plot | Mapping/Environmental/queue khớp khóa |
| 18 | Chạy lại pipeline | Tổng hợp kết luận, sửa docs 03/04 | Phân tích phụ held-out model | Bản kết quả và playbook có giới hạn |
| 19 | Fix dữ liệu nếu lỗi; ghi version | Review case/plot | Chốt UI fields/caption | Artifact sạch cho app |
| 20 | Đóng gói/bàn giao | Giải thích bảo mật 5 phút | Demo hình/CSV offline | Gate cuối phase và backlog còn lại |

CLI cần triển khai rồi mới xác minh, chạy từ root:

```powershell
python -m src.analysis.compare_rankings --config config/project.yaml
python -m src.environmental.cvss_environmental --config config/project.yaml --assets config/assets.yaml
python -m src.analysis.context_priority --config config/project.yaml --assets config/assets.yaml
python -m src.analysis.plots --config config/project.yaml
```

- [ ] Cùng cohort/snapshot cho ba policy; eligibility và missing được thống kê; ranking đầy đủ lưu được.
- [ ] Có top-50 khi đủ N, nếu không có K thực tế và kế hoạch/giải thích thay thế; ties được công bố.
- [ ] KEV được dùng đúng: nhị phân, không có trong KEV không là âm chắc chắn; KEV-first không được tự kiểm định bằng KEV.
- [ ] Base/Environmental đối chiếu công thức; assumptions/Temporal X rõ; không suy metric tự động từ intranet/WAF/backup.
- [ ] Applicability trước ưu tiên; unknown có review_required, không mất bản ghi KEV cần xác minh.
- [ ] Ít nhất ba case có nguồn, gồm Web và mobile; bối cảnh có bằng chứng hoặc ghi rõ giả định.
- [ ] Không có khẳng định tiết kiệm effort/giảm sự cố nếu chưa đo; không có số liệu minh họa giả lẫn vào nghiên cứu.
- [ ] Người 3 đọc các CSV để làm app mà không phải tự chấm điểm/tính ranking lại.

Nếu trễ, bỏ bớt biểu đồ phụ và giảm số cặp context; giữ ba policy, scatter, bảng top-K, ba case có nguồn và playbook.
Nếu không có KEV, ghi Recall=N/A; nếu chỉ có ít KEV, vẫn tính nhưng báo mẫu số nhỏ và giới hạn diễn giải. Giữ phân tích bất đồng; không thêm CVE ngoài scope chỉ để có kết quả đẹp.
Nếu không có bất đồng mạnh, báo mức tương đồng và khảo sát bối cảnh, ties hoặc độ phủ mẫu; không điều chỉnh ngưỡng để tạo kết luận định trước.
**Bàn giao:** dataset/metadata khóa, bốn CSV theo contract, ranking metrics, figures, case studies và playbook; phần mở rộng còn thiếu phải được gắn trạng thái rõ cho Phase 4.
