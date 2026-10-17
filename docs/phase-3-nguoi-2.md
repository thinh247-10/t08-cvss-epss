# Phase 3 — Người 2: thống kê ranking, Environmental và giải thích ưu tiên vá

Ngày giao: 17/10/2026. Mốc code đã có: `fb54a11` trên `develop`.
Đây là **bản giao việc**, không phải báo cáo rằng Phase 3 đã chạy xong.
Thời lượng dự kiến: 7 ngày làm việc, khoảng 16 giờ; báo N1 nếu thiếu thời gian.
Đọc cùng [kế hoạch Phase 3](phases/phase-3-xep-hang-va-boi-canh.md),
[data contract](data_contract.md) và [hướng dẫn N3](phase-3-nguoi-3.md).

## 1. Bạn phải tạo ra điều gì?

Bạn phụ trách trả lời: **vì sao CVSS cao không đồng nghĩa phải vá trước trên mọi hệ thống?**
Đầu ra là thống kê ba chính sách trên dữ liệu thật, bảng điểm Environmental,
hàng đợi hành động có lý do, 3–5 case và playbook. Không phải train AI thêm.

| Đã có, dùng lại | Còn phải làm trong Phase 3 |
|---|---|
| `compare_rankings.py`: `build_rankings(...)` và CLI hoạt động | Jaccard, tau-b, KEV coverage, ties, rank delta, metadata |
| `cvss_base.py`: scorer Base đã kiểm | `cvss_environmental.py` hiện TODO: triển khai Environmental |
| `asset_inventory.py`: loader/validator inventory | Validator mapping, applicability, queue và sensitivity |
| 5 cặp mapping v1, 6 tài sản giả định | Rà nguồn, mở rộng có căn cứ nếu đủ thời gian |
| `docs/analysis-results.md`: khung 5 case | Điền kết quả thật, tích hợp case mobile N3 và case Web N1 |
| Phase 2 có model/prediction đã khóa | Chỉ dùng CVSS **quan sát** cho ranking/bối cảnh chính |

## 2. Nhận code và tạo branch riêng

Trong VS Code mở đúng thư mục chứa `.git`, `src`, `README.md`. Thư mục trên máy
N1 bị lồng hai lần; máy bạn có thể khác. Không sao chép đường dẫn máy N1.

```powershell
Get-Location
git rev-parse --show-toplevel
git status --short
```

Nếu báo `not a git repository`, chuyển vào thư mục repo con rồi chạy lại.
Nếu có sửa riêng, lưu/commit đúng file trước; không reset hoặc force-push.
Khi công việc cũ đã lưu:

```powershell
git switch develop
git pull --ff-only origin develop
git merge-base --is-ancestor fb54a11 HEAD
$LASTEXITCODE
git switch -c feat/p3-ranking-context
```

Lệnh kiểm ancestor cần trả `0`. Nếu không, dừng kiểm lại branch/remote với N1.
Nếu branch đã tồn tại, dùng `git switch feat/p3-ranking-context` rồi
`git merge origin/develop` khi working tree đã lưu; xử lý conflict theo nội dung,
không xóa branch để làm lại. Tất cả code Phase 3 N2 push vào branch này.

## 3. Môi trường riêng và API key

Giữ `.venv` riêng đang hoạt động; chỉ tạo mới khi chưa có:

```powershell
py -0p
python -m venv .venv
```

Chọn Python đã cài bằng thông tin `py -0p` nếu `python` không chạy. Ghi phiên bản
thực tế; không sao chép `.venv` của người khác. Cài và kiểm:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt -r requirements-model.txt
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -c "import pandas, pyarrow, yaml, scipy; print('P3 N2 ENV OK')"
```

Không cần Torch, GPU hoặc API key cho phần này. Dữ liệu đã là snapshot offline;
không cần xin key NVD mới, không gửi `.env`/key của mình cho nhóm.
Chỉ truy cập web khi xác minh advisory/đặc tả, không tải lại EPSS/KEV để thay snapshot.

## 4. Nhận và kiểm dữ liệu

N1 gửi `phase1_v1_20261010.zip`; nếu đã có bản đúng hash thì dùng lại.

```powershell
Get-FileHash -LiteralPath "$env:USERPROFILE\Downloads\phase1_v1_20261010.zip" -Algorithm SHA256
```

Hash phải là `215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`,
38.599.819 byte. **Chỉ khi chưa có thư mục release**, giải nén:

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\phase1_v1_20261010.zip" -DestinationPath data/processed
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
```

ZIP đã chứa thư mục `phase1_v1_20261010`; không giải nén lồng thêm một tầng.
Nếu đã có folder, chỉ chạy verifier; không ghi đè. Cần thấy `PHASE1 RELEASE OK`.

| Đầu vào trong `data/processed/phase1_v1_20261010/` | Vai trò |
|---|---|
| `ranking_cohort.parquet` | RQ2: 396 CVE = 388 Web + 8 mobile, 3 KEV |
| `cves.parquet` | Tra description/vector/tín hiệu của case theo ID; không tự lấy toàn master làm ranking |
| `cve_asset_mapping.csv` | 5 cặp gốc; sao chép sang output mới để phát triển |
| `assets.yaml` | Inventory đóng băng để đối chiếu bản mới |
| `metadata.json` | Dataset version, hashes, ngày từng nguồn và số lượng |

Dataset version là `t08-v1.0-20261010`. `config/project.yaml` còn giá trị pilot;
**không lấy `pilot-v0.1` làm version của phân tích này**. Không sửa release v1,
không khử trùng/chia split lại. Snapshot thật: EPSS **2026-09-29**, KEV phát hành
**2026-09-30**, tải **2026-10-01 UTC**. Ghi ba mốc riêng, không ghi cùng ngày T
và không gọi đây là kiểm định dự báo 30 ngày. Chỉ có 3 KEV, mẫu số coverage rất nhỏ.

N2 không cần tải model 253 MB để bắt đầu. Có thể nhận toàn gói Phase 2 theo
[biên bản](phase-2-completion.md) sau; ranking tái tạo được từ release v1 và code hiện có.

## 5. Bước A — chạy lại ranking đã có, khoảng 1 giờ

**Lệnh dưới đây đã được triển khai**, chạy ngay được:

```powershell
.\.venv\Scripts\python.exe -m src.analysis.compare_rankings --input data/processed/phase1_v1_20261010/ranking_cohort.parquet --metadata data/processed/phase1_v1_20261010/metadata.json --output data/processed/p3_n2/rankings.csv
.\.venv\Scripts\python.exe -m unittest tests.test_rankings tests.test_cvss -v
Get-FileHash -LiteralPath data/processed/p3_n2/rankings.csv -Algorithm SHA256
```

Kết quả cần 396 dòng, 3 KEV, hash ranking
`4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.
Nếu khác, đối chiếu input/code/dtype/newline trước; không sửa CSV bằng Excel cho khớp.
Gửi CSV + hash + version cho N3 ngay để họ vẽ song song. Không đợi xong Environmental.

## 6. Bước B — thống kê RQ2, khoảng 3 giờ

**Vibe code trong `src/analysis/ranking_metrics.py` (file mới)**; tái dùng
`build_rankings` hiện có, giữ nguyên output 11 cột của `compare_rankings.py`.
N2 sở hữu ranking trong Phase 3; N1 làm kiểm tích hợp ở file test riêng.

N2 tạo `config/phase3.yaml` ghi dataset/path, K `[10,20,50]`, ngưỡng minh họa
CVSS `7.0`, EPSS `0.10`, policy/context version, ngày nguồn và quy tắc missing.
Đây là đề xuất của nhóm trước khi chạy thống kê; không đổi ngưỡng để tạo bất đồng.
Ghi cấu hình/hash vào metadata từng lần chạy; không sửa config model/split đã khóa.

| Output trong `data/processed/p3_n2/` | Cách tính và trường tối thiểu |
|---|---|
| `ranking_metrics.json` | dataset/cohort/policy, N, total_kev, K, ngày nguồn, các chỉ số và lý do null |
| `topk_metrics.csv` | `policy,k,n,kev_total,kev_hits,kev_recall,cutoff_tie_count,selected_from_cutoff_tie` |
| `overlap.csv` | `policy_a,policy_b,k,intersection,union,jaccard` |
| `rank_deltas.csv` | `cve_id,cvss_rank,epss_rank,kev_first_rank,rank_delta_cvss_epss` |
| `metadata.json` | schema/version, input/output hashes/bytes, câu lệnh, commit, package versions, số dòng |

Schema bổ sung này cần N2 ghi vào `docs/phase-3-artifact-contract.md` rồi gửi N3
trước khi vẽ metric. Đừng đổi tên cột âm thầm sau khi đã gửi.

- Sort gốc giữ nguyên: CVSS giảm → ID tăng; EPSS giảm → ID tăng;
  KEV-first = KEV giảm → EPSS giảm → Base giảm → ID tăng.
- Jaccard cho từng cặp policy tại cùng K: giao/chia hợp. Ví dụ synthetic
  `{A,B}` và `{B,C}` cho `1/3`; chỉ dùng fixture kiểm thử, không trộn nghiên cứu.
- Kendall tau-b dùng **điểm CVSS và EPSS gốc**, không dùng rank đã phá hòa bằng ID.
  N<2 hoặc một cột hằng: `null` + lý do. Không xuất NaN như JSON hợp lệ.
- KEV Recall@K cho CVSS/EPSS = hits / tổng KEV trong cohort; tổng 0 → null.
  KEV-first có hits để mô tả nhưng `kev_recall=null`, lý do policy dùng KEV trực tiếp.
  Không gọi không-KEV là false positive, không tính accuracy exploit từ đó.
- Cutoff ties theo score gốc với CVSS/EPSS, và bộ `(is_kev,epss,base)` với KEV-first;
  không tính ID vào tie group. Báo tổng nhóm hòa và số được lấy trong top-K.
- `rank_delta_cvss_epss = cvss_rank - epss_rank`: dương nghĩa EPSS xếp sớm hơn.
- K không hợp lệ/rỗng báo rõ; K>=N không được trình bày là lựa chọn ưu tiên có phân biệt.

Tạo `tests/test_ranking_metrics.py`: mẫu tính tay Jaccard/recall, ties, đảo input,
cohort khác ID, KEV=0, N nhỏ/điểm hằng. Không viết test chỉ gọi lại chính công thức đang test.
`reports/p3_ranking_results.md` ghi command, số thật, hạn chế, link output/hash.

**CLI dưới đây là interface cần triển khai ở Bước B, chưa có lúc giao việc:**

```powershell
.\.venv\Scripts\python.exe -m src.analysis.ranking_metrics --rankings data/processed/p3_n2/rankings.csv --config config/phase3.yaml --output-dir data/processed/p3_n2
.\.venv\Scripts\python.exe -m unittest tests.test_ranking_metrics -v
```

## 7. Bước C — Environmental và mapping, khoảng 4 giờ

Sửa `src/environmental/cvss_environmental.py`; dùng scorer/parser Base hiện có.
Hàm đề nghị `environmental_score(base_vector, metrics)` trả full vector và score.
Xác minh [đặc tả FIRST v3.1](https://www.first.org/cvss/v3.1/specification-document)
và [calculator v3.1](https://www.first.org/cvss/calculator/3.1) khi triển khai.
Environmental xét bối cảnh; không nhân EPSS với Base để gọi đó là Environmental.

- Temporal E/RL/RC mặc định X; modified metrics mặc định X; CR/IR/AR lấy từ inventory
  có lý do, trường chưa xác định giữ X. Không tự suy MAV từ internal hay MAC từ WAF.
- Kiểm Scope changed/unchanged, Modified Scope khác Base Scope, MPR theo Scope,
  impact bằng 0, trọng số CR/IR/AR, giới hạn impact và Roundup đúng **v3.1**.
- Tất cả Environmental/Temporal X phải trả về Base tương ứng. Test vector malformed,
  metric trùng/giá trị sai, không âm thầm fallback thành 0.
- `tests/test_cvss_environmental.py` có expected từ calculator/đặc tả và giải thích;
  lưu vector/expected/source trong `reports/p3_environmental_check.md`.
  N3 kiểm thêm một case bằng tay, N2 không sửa test N3 để ép pass.

Mapping mới: `data/processed/p3_n2/cve_asset_mapping.csv`, giữ đúng trường contract §8,
khóa `(cve_id,asset_id)`, version dataset không đổi; context mới ví dụ `phase3-context-v1`.
Nếu thay inventory, tạo `config/assets_phase3.yaml` từ inventory v1 và tăng inventory version;
giữ nguyên `config/assets.yaml`/gói v1 để đối chiếu. Tài sản mới phải có stack/version/lý do.
Target 15 cặp có căn cứ; bắt đầu 5 cặp gốc. Không nhân mọi CVE×asset hoặc bịa affected
để đủ 15. Thiếu cặp thì báo số thật và lý do với N1; giữ ít case tốt thay vì số giả.

Mỗi cặp có URL vendor/CNA, ngày đọc, dải affected, assumed_version, điều kiện khai thác,
affected/unaffected/needs_review, lý do, reviewer thực tế. Nguồn advisory mới không
ghi đè nhãn CVSS v1. CVE ngoài RQ2 có thể làm case định tính, không tự thêm vào 396 ID.
`API-02` thiếu product/version: chưa đủ căn cứ gán affected. Hai mobile client không
được tự đổi exposure thành internet hoặc 0. N3 gửi case mobile để bạn tích hợp mapping.

Environmental output `environmental_scores.csv` đúng contract §8: một dòng/cặp đủ
bằng chứng affected và vector hợp lệ, source=observed, giải thích từng thay đổi/giữ X.
Mapping vẫn giữ đủ mọi cặp kể cả không tính được score; báo số loại và lý do.

## 8. Bước D — queue và sensitivity, khoảng 3 giờ

Tạo `src/analysis/context_priority.py`. Input master/cohort, mapping, inventory,
Environmental; join `many_to_one` theo CVE và `one_to_one` theo cặp, kiểm không nhân dòng.
Output `priority_queue.csv` chứa **mọi cặp mapping**, đúng contract §9, thêm lý do/đề nghị.

| Điều kiện | `queue_status` | `priority_rank` |
|---|---|---|
| unaffected có lý do | `not_applicable` | null |
| needs_review, thiếu tín hiệu hoặc exposure chưa hỗ trợ | `review_required` | null |
| affected, đủ dữ liệu, exposure hỗ trợ | `patch` | 1..M chỉ trong patch queue |

Policy `context-v1`: KEV giảm → exposure internet=2/internal=1/isolated=0 giảm →
Environmental giảm → EPSS giảm → CVE/asset tăng. **client giữ review_required**,
không tự có numeric priority; ghi rõ đường tấn công/cần xác minh dù applicability=affected.
KEV+unknown vẫn ở review list với `recommended_action` xác minh sớm, không biến mất.
Missing score/KEV/EPSS không thành 0/false. Lý do phải đọc được, không chỉ ghi “priority high”.

Sensitivity policy riêng `context-v1-env-first`: đổi thứ tự exposure và Environmental,
giữ **cùng tập cặp patch đủ điều kiện**, lưu CSV riêng + rank delta/Jaccard@K hợp lệ.
Base→Environmental cũng so trên cùng cặp; không so 5/15 cặp với top-50 của 396 CVE.
Tạo `context_comparison.csv` có key cặp, Base/Environmental, rank từng cách và version;
ghi chính xác hướng rank delta. Nếu M<2/không đổi thứ tự, báo đúng kết quả, không ép đảo rank.

Thêm `tests/test_context_priority.py`: duplicate/missing joins, unaffected, client,
KEV cần review, shuffled input, ties, queue chỉ đánh rank cho patch.
CLI Environmental/context chưa có: triển khai `--help`, input/output tường minh và
ghi **lệnh thực chạy** vào báo cáo. N3 chỉ đọc artifact; không phải tự tạo scorer/queue.

## 9. Bước E — case, playbook và bàn giao, khoảng 5 giờ

Trong `docs/analysis-results.md`, tổng hợp 3–5 case khoảng 0,5–1 trang/case:
ít nhất một Web và một mobile; dùng 5 case hiện có làm điểm bắt đầu.
N1 viết một case Web riêng; N3 gửi `docs/cases/p3-mobile-n3.md`; bạn là người tích hợp,
hai bạn không sửa trực tiếp file tổng trong lúc bạn viết.

Mỗi case: CVE/product/affected version/nguồn/ngày truy cập; cơ chế bảo mật;
vector/điểm/EPSS/ngày/KEV/rank; applicability/asset; tác động nghiệp vụ;
Environmental và giả định; quyết định vá/xác minh, hướng vendor, giới hạn.
Không khai thác CVE. Không coi “CVSS cao EPSS thấp” là bằng chứng vá lãng phí.
Nếu rank không bất đồng mạnh, vẫn giải thích kết quả và tác động bối cảnh trung thực.

Cập nhật `docs/03-environmental-context.md`, `docs/04-patch-playbook.md`:
ai xử lý, trigger, kiểm phiên bản, backup/rollback, kiểm tương thích, xác nhận sau vá,
ngoại lệ chưa có bản vá/không downtime. SLA nếu đề xuất phải gắn nhãn giả định,
không báo số giờ giảm/số sự cố ngăn chặn khi chưa đo. Kiểm plot/caption N3 bằng CSV nguồn.

## 10. Lịch phối hợp và quyền sửa file

| Ngày kể từ nhận | N2 | Giao cho N3/N1 |
|---|---|---|
| 1 | Kiểm gói, ranking hiện có, chốt schema mới | rankings/hash ngay; contract proposed |
| 2 | RQ2 metrics + tests | metrics/overlap/deltas/metadata thật |
| 3 | Environmental + mở mapping | Interface, vector mẫu, expected có nguồn |
| 4 | Queue + sensitivity | Bảng context và trạng thái missing/review |
| 5 | 3–5 case + playbook | Bản báo cáo cho N1, kiểm caption N3 |
| 6–7 | Fix integration, tái chạy, đóng gói | ZIP/hash, log test và hạn chế còn lại |

N2 sở hữu ranking/context/scorer/mapping và báo cáo tổng. N3 sở hữu `plots.py`,
metric-to-figure, case mobile, thí nghiệm phụ AI/UI contract. N1 sở hữu kiểm tích hợp,
release và quyết định version. Hai file shared `docs/data_contract.md` và kế hoạch
chỉ sửa sau khi báo N1; artifact contract mới N2 tạo để N3 dùng, tránh cùng sửa file.

## 11. Prompt vibe code — gửi từng bước, đọc diff rồi chạy

**Prompt A (metrics):**

```text
Đọc docs/phase-3-nguoi-2.md mục 5–6, code ranking và data contract.
Giữ build_rankings và schema ranking hiện có. Tạo ranking_metrics.py,
config/phase3.yaml và artifact contract; tính Jaccard/Kendall tau-b từ score gốc,
KEV coverage CVSS/EPSS, ties, delta. Null kèm reason, không dùng KEV-first để
tự kiểm định. Thêm test tính tay và CLI theo hướng dẫn. Không gọi API/train/sửa release.
Chạy dữ liệu thật rồi ghi report; chưa làm Environmental trong bước này.
```

**Prompt B (Environmental):**

```text
Làm mục 7: triển khai CVSS3.1 Environmental theo FIRST, giữ scorer Base hiện có.
Tạo tests/test_cvss_environmental.py với expected độc lập và nguồn; ghi vector/score
đối chiếu. Mapping mới ở p3_n2, inventory mới version riêng nếu cần.
Không suy modified metric từ intranet/WAF, không sửa nhãn/dataset v1 hay bịa affected.
```

**Prompt C (context và báo cáo):**

```text
Làm mục 8–9: queue applicability-first, client/missing review_required, không mất
KEV cần xác minh; sensitivity cùng tập cặp. Tái dùng scorer, thêm test join/status/ties.
Xuất schema đúng contract, ghi command thật. Tổng hợp nguồn/case/playbook từ kết quả,
không điền số giả hoặc sửa file plot N3. Báo rõ đầu ra nào hoàn thành/còn thiếu.
```

## 12. Git, ZIP và tiêu chí hoàn tất

Commit từng bước; **chỉ add file đã tồn tại và đã làm**, ví dụ sau Bước B:

```powershell
git add src/analysis/ranking_metrics.py tests/test_ranking_metrics.py config/phase3.yaml docs/phase-3-artifact-contract.md reports/p3_ranking_results.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat(phase3): add ranking metrics and snapshot analysis"
git push -u origin feat/p3-ranking-context
```

Các bước sau add tường minh scorer/context/tests/docs tương ứng, commit rồi push cùng branch.
PR **base develop ← compare feat/p3-ranking-context**. Có thể mở draft sau ranking,
bổ sung tiếp context. N1 tích hợp; không bắt buộc review độc lập hay merge vào main.
Không add `.env`, `.venv`, data lớn; không dùng `git add -f` để vượt ignore.

Sau khi output `data/processed/p3_n2/` đã có metadata/checksum:

```powershell
Compress-Archive -LiteralPath data/processed/p3_n2 -DestinationPath data/processed/p3_n2_handoff.zip
Get-FileHash -LiteralPath data/processed/p3_n2_handoff.zip -Algorithm SHA256
```

Nếu ZIP đã tồn tại, dùng tên revision mới; không ghi đè bản đã gửi. Gửi ZIP riêng,
ghi `docs/handoffs/p3-n2.md`: commit/branch, dataset/context/policy version, tên ZIP,
bytes/hash, lệnh chạy, test thực tế, số dòng/coverage/exclusions, hạn chế còn lại.
Người nhận giải nén dưới `data/processed/` để có `p3_n2/`.

- [ ] Verify v1, ranking 396 ID/3 KEV tái tạo đúng, ba policy không đổi cohort.
- [ ] Metric/ties/null/metadata có test và output thật; đã gửi N3.
- [ ] Environmental đúng v3.1, source=observed, expected đối chiếu độc lập.
- [ ] Mapping có nguồn; số cặp thật được ghi; client/unknown/unaffected không bị mất.
- [ ] Queue và sensitivity cùng cặp; không giả claim tối ưu/khai thác âm tính.
- [ ] Báo cáo 3–5 case và playbook đã điền; nguồn/giả định/ngày lệch rõ ràng.
- [ ] Code push branch, ZIP/hash/command gửi N1 và N3; ghi việc còn thiếu nếu có.

Nguồn tra: [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document),
[FIRST Using EPSS](https://www.first.org/epss/using-epss),
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
EPSS là tín hiệu dự báo khai thác, không phải rủi ro riêng của tài sản; dùng cùng
tác động và bối cảnh để thảo luận. Nguồn web dùng giải nghĩa/advisory; số liệu dùng snapshot khóa.
