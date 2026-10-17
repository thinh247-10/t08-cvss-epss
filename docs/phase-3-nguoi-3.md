# Phase 3 — Người 3: biểu đồ, case mobile và tác động sai số AI

Ngày giao: 17/10/2026. Mốc code đã có `fb54a11` trên `develop`.
Đây là **bản giao việc**, chưa phải kết quả Phase 3. Dự kiến 7 ngày, khoảng 16 giờ.
Đọc [kế hoạch Phase 3](phases/phase-3-xep-hang-va-boi-canh.md),
[hướng dẫn N2](phase-3-nguoi-2.md), [data contract](data_contract.md).

## 1. Vai trò của bạn trong phase này

Bạn biến bảng kết quả thành hình dễ đọc, viết một case mobile có nguồn và giải thích
sai số AI làm thay đổi ranking severity như thế nào. **Không train/tuning model nữa.**
N1 đã chạy thay phần DistilBERT; baseline/prediction/metric đóng băng ở Phase 2.

| Bạn làm | Người khác làm / đầu vào bạn nhận |
|---|---|
| Scatter, top-50, overlap, KEV coverage, context plot | N2 tính ranking, metric, Environmental và queue |
| Case mobile client/framework/SDK | N2 tích hợp vào báo cáo tổng và mapping |
| Thí nghiệm phụ observed-vs-predicted Base rank trên held-out | Dùng prediction đã lưu, không inference lại test để tuning |
| Một đối chiếu Environmental độc lập | N2 viết scorer; bạn kiểm một case theo FIRST |
| Schema đọc cho app Phase 4, captions, notebook | N1 tích hợp/kiểm release; app thực hiện sau |

## 2. Lấy code và tạo branch

Mở terminal tại thư mục có `.git`, `src`, `README.md`:

```powershell
Get-Location
git rev-parse --show-toplevel
git status --short
```

Nếu sai thư mục, chuyển vào repo con. Lưu/commit việc cũ nếu có trước khi chuyển branch;
không reset/force-push để bỏ thay đổi. Sau đó:

```powershell
git switch develop
git pull --ff-only origin develop
git merge-base --is-ancestor fb54a11 HEAD
$LASTEXITCODE
git switch -c feat/p3-security-plots
```

Kiểm ancestor cần `0`. Branch tồn tại thì `git switch feat/p3-security-plots`,
`git fetch origin`, `git merge origin/develop` sau khi lưu công việc riêng.
Khi N2 merge thêm code, dùng fetch/merge như trên; không chuyển sang branch N2 để code.
Nếu conflict, đọc nội dung và báo N1 khi chưa chắc; không xóa file/model để né lỗi.

## 3. Cài môi trường riêng

Giữ `.venv` đang dùng được. Chỉ khi chưa có:

```powershell
py -0p
python -m venv .venv
```

Nếu `python` không tồn tại, chọn Python đã cài từ `py -0p`. Không sao chép `.venv`
từ máy N1/N2. Các lệnh dưới dùng Python trong môi trường nên không cần activate:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt -r requirements-model.txt
.\.venv\Scripts\python.exe -m pip install matplotlib
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -c "import pandas, pyarrow, scipy, matplotlib; print('P3 N3 ENV OK', matplotlib.__version__)"
```

Ghi Python và phiên bản matplotlib thực tế vào `reports/p3_figures_check.md`.
Tạo `requirements-analysis.txt` chứa dependency tối thiểu đã chạy được (tham chiếu
requirements-model/data và pin matplotlib thực tế), không chép pip freeze toàn máy.
Jupyter chỉ cần nếu mở notebook tương tác; phần xuất hình phải chạy được bằng CLI Python.

**Không cần GPU/Torch/API key** để đọc prediction CSV và vẽ. Không tải lại NVD/EPSS/KEV,
không gửi `.env`, API key hay `.venv` qua nhóm. Web chỉ dùng tra advisory/đặc tả.

## 4. Nhận hai gói, đúng cấu trúc

### 4.1. Gói Phase 1 — bắt buộc cho số liệu nguồn

Nếu đã có bản đúng, chạy verifier và dùng lại. Nếu nhận mới:

```powershell
Get-FileHash -LiteralPath "$env:USERPROFILE\Downloads\phase1_v1_20261010.zip" -Algorithm SHA256
```

SHA-256 `215644e804c78db8a20bbff23528ebc752597ee0daa63888c075d7b6b9832ebe`,
38.599.819 byte. **Chỉ khi chưa có thư mục release**, giải nén rồi kiểm:

```powershell
Expand-Archive -LiteralPath "$env:USERPROFILE\Downloads\phase1_v1_20261010.zip" -DestinationPath data/processed
.\.venv\Scripts\python.exe -m src.collect.verify_phase1
```

Cần `PHASE1 RELEASE OK`. ZIP đã chứa `phase1_v1_20261010/`, không thêm tầng thư mục.

### 4.2. Gói Phase 2 — cho prediction và báo cáo AI

N1 gửi `phase2_handoff_20261017.zip`, 253.203.876 byte. Đối chiếu bằng manifest tracked:

```powershell
$p2Receipt = Get-Content -Raw docs/handoffs/phase-2-complete-20261017.json | ConvertFrom-Json
$p2Zip = Join-Path $env:USERPROFILE 'Downloads\phase2_handoff_20261017.zip'
(Get-FileHash -LiteralPath $p2Zip -Algorithm SHA256).Hash -eq $p2Receipt.sha256
(Get-Item -LiteralPath $p2Zip).Length -eq $p2Receipt.bytes
```

Cả hai phải `True`. Nếu false, không dùng gói; báo N1 tải lại đúng file.
Chỉ giải nén khi folder đích chưa có, không ghi đè bản khác:

```powershell
Expand-Archive -LiteralPath $p2Zip -DestinationPath data/processed/phase2_received
Expand-Archive -LiteralPath data/processed/phase2_received/baseline.zip -DestinationPath data/processed/phase2_received/baseline
```

Gói Phase 2 có file trực tiếp ở root (khác ZIP Phase 1). Nếu folder đã có, kiểm đúng
version/hash và dùng lại. Mở cây file, không copy đè source trong ZIP lên repo Git.

| Đường dẫn sau giải nén | Cách dùng |
|---|---|
| `data/processed/phase1_v1_20261010/ranking_cohort.parquet` | 396 CVE quan sát cho RQ2 |
| `data/processed/phase1_v1_20261010/ml_cohort.parquet` | ID/split/nhãn nguồn cho thí nghiệm AI phụ |
| `data/processed/phase2_received/rankings.csv` | Ranking 396 dòng đã kiểm, dùng vẽ ngay |
| `data/processed/phase2_received/distilbert/predictions.csv` | 38.427 prediction validation+test |
| `data/processed/phase2_received/baseline/data/processed/predictions.csv` | 76.854 dòng: TF-IDF và Dummy; phải lọc model_version |
| `data/processed/phase2_received/reports/p2_model_comparison.csv` | Kết quả Phase 2 đã có; không tính lại để chọn model |
| `data/processed/phase2_received/manifest.json` | Hash/bytes các file trong gói ngoài |

Model version cần phân biệt: `tfidf-v1-n1-reproduction-20261017`, bản Dummy thêm
`-dummy`, và `distilbert-v1-n1-20261017`. Đây là artifact N1 chạy; không gọi là
byte-identical với file model gốc N3 chưa bàn giao.

**Nếu chưa nhận ZIP Phase 2, bạn vẫn làm được scatter/top-50/case mobile** bằng Phase 1
và lệnh ranking sau. Chỉ phần thí nghiệm AI phụ cần prediction.

## 5. Bước A — bắt đầu ngay khi N2 chưa xong, khoảng 4 giờ

Lệnh ranking **đã có**; xuất bản tạm của mình, không ghi đè output N2:

```powershell
.\.venv\Scripts\python.exe -m src.analysis.compare_rankings --output data/processed/p3_n3_input/rankings.csv
Get-FileHash -LiteralPath data/processed/p3_n3_input/rankings.csv -Algorithm SHA256
```

Cần 396 dòng, 3 KEV, hash
`4615bd970c5ef589bb7c04e81ecc48217388a79d60ad8b3d5565a3f93f822b67`.
Sau khi N2 giao ranking/metadata mới, đối chiếu cùng ID/policy/hash trước khi đổi input.

**Vibe code trong `src/analysis/plots.py`**, hiện chỉ TODO. N3 sở hữu file này xuyên
Phase 3; N2 góp ý, không cùng sửa trực tiếp. Các hàm phải đọc artifact đã xuất,
không gọi API, train, tự lọc cohort khác hoặc tự viết policy ranking khác.
Tạo `config/phase3_plots.yaml` riêng để lưu màu/font/kích thước/đường dẫn.
Ngưỡng phân tích lấy theo cấu hình N2: CVSS>=7.0, EPSS>=0.10; ghi rõ là minh họa,
không thay score/rank theo ngưỡng. Nếu N2 chưa có config, dùng giá trị đề xuất này
và ghi trạng thái dự thảo; khóa lại trước chạy bộ hình chính thức.

| Hình trong `reports/figures/phase3/` | Yêu cầu |
|---|---|
| `cvss_epss_scatter.png` và `.svg` | X=CVSS0–10, Y=EPSS0–1; 396 điểm, marker KEV khác hình/màu; truy được CVE qua bảng nguồn |
| `top50_three_policies_p1.png/.svg` | Ba cột CVSS/EPSS/KEV-first, vị trí 1–25, ID đọc được, badge KEV |
| `top50_three_policies_p2.png/.svg` | Vị trí 26–50, cùng cách trình bày; không đổi thành top-25 |

Scatter tuyến tính là đủ. Nếu thêm log-scale, giữ zero trong CSV, chỉ dùng epsilon
hiển thị được ghi trong caption; không silently bỏ CVE=0. Không coi percentile là epss.
Top-50 lấy rank<=50 từ bảng đầy đủ; KEV-first là policy, không có “điểm KEV” chung trục 0–10.
Xuất `data/processed/p3_n3/top50_long.csv` gồm `policy,rank,cve_id,cvss_base_score,epss,is_kev`
và version/cohort để N1 kiểm lại từng dòng.

Các hình phải có caption trong `reports/p3_figures.md`: tên file, input/hash, N, K,
đơn vị CVE/cặp, policy/tie-break và **EPSS2026-09-29; KEV phát hành2026-09-30,
tải2026-10-01UTC**. Không ghi chung “snapshot cùng ngày”. 3 KEV là mẫu nhỏ;
không suy ra hiệu quả dự báo tương lai hay không-KEV chưa từng bị khai thác.

**CLI sau là interface cần bạn triển khai, chưa chạy được lúc giao việc:**

```powershell
.\.venv\Scripts\python.exe -m src.analysis.plots --rankings data/processed/p3_n3_input/rankings.csv --output-dir reports/figures/phase3 --tables-dir data/processed/p3_n3
```

Nếu thiếu metric/context, tạo hai nhóm hình có đủ input, ghi nhóm còn chờ rõ ràng;
không dùng số giả để vẽ cho đủ bộ. Thiếu file được yêu cầu phải báo lỗi cụ thể.

## 6. Bước B — hình thống kê và context khi N2 giao, khoảng 3 giờ

N2 giao ZIP chứa `p3_n2/`; giải nén dưới `data/processed/` sau kiểm hash/bytes họ gửi.
Đọc `docs/phase-3-artifact-contract.md` do N2 tạo, đối chiếu version/schema.
Không tự merge hàng theo thứ tự; join CVE hoặc `(cve_id,asset_id)` và kiểm uniqueness.

| Input N2 | Việc bạn làm |
|---|---|
| `overlap.csv` | `topk_overlap.png/.svg`: Jaccard ba policy, K10/20/50, thang0–1; vẽ từ giá trị N2 |
| `topk_metrics.csv` | `kev_recall_at_k.png/.svg`: chỉ CVSS/EPSS, hiển thị hits/3 và tỷ lệ, không KEV-first “thắng” |
| `context_comparison.csv` + `environmental_scores.csv` | `context_rank_changes.png/.svg`: Base→Environmental trên cùng cặp đủ điểm, nhãn CVE/asset |
| `priority_queue.csv` | Bảng số patch/review_required/not_applicable; lý do client/unknown còn review |
| `ranking_metrics.json`, `metadata.json` | Caption tau-b/undefined reason, ngày/version và checksum |

Kendall dùng kết quả trên **score gốc**; không lấy rank ID-order tính thay N2.
Null recall hiển thị N/A + lý do, không biến thành 0. N<2 hoặc không có cặp hợp lệ
thì báo chưa đủ dữ liệu; không vẽ đường giả. Base→Environmental ranking và context
queue là hai phép so khác nhau, không dùng chung tiêu đề “ưu tiên sau bối cảnh”.
Không bỏ client review khỏi báo cáo chỉ vì không có priority_rank; biểu diễn bằng bảng/trạng thái.

Mở từng PNG/SVG bằng VS Code hoặc trình duyệt, kiểm nhãn không đè/cắt, font không lỗi,
legend đọc được và màu/marker phân biệt. Không chỉ kết luận pass vì file PNG tồn tại.
Trong `reports/p3_figures_check.md` ghi file nào đã xem, lỗi đã sửa, dòng CSV được đối chiếu,
ngày chạy và giới hạn. Chọn 5 CVE từ mỗi policy để đối chiếu rank/badge với bảng nguồn.

Tạo `tests/test_plots.py`: nhận đủ ID/top-K, duplicate/missing lỗi rõ, N/A được giữ,
không mutate frame đầu vào. Synthetic fixture phải có nhãn, không đi vào output nghiên cứu.
Không viết test so từng pixel máy khác; kiểm nội dung bảng plot và smoke xuất file nhỏ.

## 7. Bước C — case mobile và kiểm Environmental, khoảng 4 giờ

Bạn tạo **`docs/cases/p3-mobile-n3.md`**, không sửa `docs/analysis-results.md` đồng thời N2.
Bắt đầu từ `CVE-2023-30470` (Hermes) hoặc `CVE-2023-41387` (flutter_downloader)
trong mapping v1; đọc lại nguồn gốc trong `docs/analysis-results.md`, không mặc định
mọi ứng dụng React Native/Flutter đều affected. Case này nằm train, **không** là lỗi held-out.

Case cần 0,5–1 trang có: CVE/component/client thực sự, advisory/affected/fixed version,
URL/ngày đọc, đường dữ liệu attacker có thể kiểm soát, quyền/tương tác cần thiết,
tác động C/I/A, version giả định/applicability, rank và nguồn số, Environmental có lý do,
đề xuất vá hoặc xác minh và giới hạn. Không khai thác CVE hoặc dựng chứng cứ trên máy thật.
Backend phục vụ mobile vẫn là Web/backend, không dùng để thay case mobile client.

Gửi N2 CVE–asset và nguồn/điều kiện nếu muốn mở mapping. Giữ `exposure=client`;
policy hiện tại chưa hỗ trợ auto-rank client nên có thể vẫn `review_required`.
Đây là kết quả hợp lệ. Không đổi thành internet để tạo priority_rank.

Khi N2 có Environmental, chọn một case với vector/CR/IR/AR/modified metrics tường minh.
Dùng [FIRST calculator v3.1](https://www.first.org/cvss/calculator/3.1) hoặc tính theo
[đặc tả](https://www.first.org/cvss/v3.1/specification-document), ghi expected và cách lấy,
so với output N2 tại `reports/p3_environmental_crosscheck_n3.md`.
Nếu thêm test: `tests/test_p3_environmental_crosscheck.py` do N3 sở hữu; không sửa test N2.
Score khác nhau thì báo N2/N1 trước khi vẽ; không lấy score output làm expected của chính nó.

## 8. Bước D — sai số AI làm đổi ranking severity, khoảng 2 giờ

Tạo **`src/analysis/prediction_rank_impact.py`**, đọc prediction đã lưu; giữ nguyên
`src/model/evaluate.py`/notebook Phase 2 để bảo toàn kết quả đã chốt.
Đây là phân tích phụ RQ1, tách khỏi RQ2 dùng 396 CVE quan sát.

1. Lấy ID giao của `ranking_cohort.parquet` với `ml_cohort.parquet` có split validation
   hoặc test. Tách hai split, không gộp; kiểm số từ join, dự kiến69 validation/108test,
   nếu khác báo nguyên nhân. Toàn bộ scoped held-out là Web, không có mobile.
2. Lọc đúng model_version ở từng CSV. Khóa `(cve_id,model_version)` không trùng;
   kiểm dataset/split/prediction_usage. Đếm missing/invalid, không tự thay score bằng0.
3. Chốt quy tắc so sánh trước chạy: cho từng split, dùng cùng tập ID có observation
   và prediction hợp lệ của cả TF-IDF/DistilBERT; báo coverage/mất dòng theo model.
   Nếu đủ tất cả thì dùng nguyên69/108. N<2 không tính tương quan/ranking chọn lọc.
4. Rank Base quan sát giảm→ID tăng và predicted Base giảm→ID tăng trên cùng tập này.
   Tính Jaccard@10/20/50 khi K<N; rank delta định nghĩa rõ; tau-b trên điểm gốc.
   Đây là so thứ tự severity do lỗi ước lượng, không chứng minh policy vá AI hiệu quả.
5. Không ghép prediction train để đủ396. Không đổi cấu hình từ kết quả test,
   không retrain hoặc chọn “mô hình thắng” theo phân tích này.

Xuất `data/processed/p3_n3/predicted_rank_comparison.csv`,
`prediction_rank_metrics.json` và `reports/p3_prediction_rank_impact.md`:
split/model/version/N/coverage/K/metric, phương pháp, link dữ liệu và giới hạn.
Có thể đọc metric Base MAE đã lưu để giải thích, không cần chạy lại toàn bộ test evaluation.
Thêm `tests/test_prediction_rank_impact.py` cho join theoID, duplicate, modelversion,
missing và ties. CLI mới phải ghi `--help` và command thực chạy trong báo cáo.

## 9. Bước E — hợp đồng UI và đóng gói, khoảng 3 giờ

Tạo `docs/phase-4-ui-contract.md` để app sau này chỉ đọc artifact:

| View | Trường/phân biệt bắt buộc |
|---|---|
| Tổng quan | dataset/cohort/version, ngày EPSS và KEV riêng, số CVE/KEV |
| Tra CVE | mô tả, vector/score quan sát + nguồn, EPSS, KEV, rank từng policy |
| AI | predicted vector/score + model_version, nhãn “dự đoán”, khác với quan sát |
| Bối cảnh | CVE/asset, giả định/applicability, Base/Environmental, modified rationale |
| Hành động | queue_status, priority_rank nếu có, reason/action, missing/review rõ |

Không đưa API key vào UI. Không train/gọi API khi mở app; chưa cần code app Phase 4.
Không sửa `docs/data_contract.md` chung nếu chưa báo N1; đề xuất thay đổi trong file UI riêng.

Tạo `notebooks/03_priority_analysis.ipynb` gọi module/đọc output, hiển thị hình và bảng
thật; không chứa một bản sao công thức. Chạy từ đầu tới cuối, ghi đường dẫn, versions,
không để output mock trông như kết quả. Có thể chạy bằng script nếu không dùng Jupyter.

## 10. Lịch phối hợp — việc nào làm ngay, việc nào chờ?

| Ngày | Làm ngay | Cần nhận thêm |
|---|---|---|
| 1 | Git/.venv/verify v1/ranking, scatter | Không cần đợi N2 hoặc model |
| 2 | Top-50 2 trang, top50_long.csv, tests | N2 chốt artifact schema |
| 3 | Case mobile/nguồn, overlap/coverage plot | Metric N2; thiếu thì tiếp tục case |
| 4 | Context plot, Environmental crosscheck | N2 giao scores/queue/comparison |
| 5 | Phân tích phụ predicted rank | Prediction Phase 2; không cần GPU |
| 6–7 | Notebook, captions, UI contract, fix/export | N1/N2 góp ý số liệu/caption |

Không sửa `compare_rankings.py`, scorer N2, mapping hoặc config model đã khóa.
N3 sở hữu plots, plot config/dependencies, case mobile, crosscheck riêng, analysis AI phụ,
UI contract và notebook mới. N1 sở hữu kiểm tích hợp; N2 sở hữu báo cáo tổng.

## 11. Prompt vibe code từng phần

**Prompt A — chạy được ngay:**

```text
Đọc docs/phase-3-nguoi-3.md mục 4–5, schema ranking hiện có và data contract.
Chỉ triển khai plots.py, config/phase3_plots.yaml, tests/test_plots.py:
scatter CVSS-EPSS và top50 2 trang từ ranking thật. Xuất PNG/SVG/top50_long.csv,
caption/manifest có ngày nguồn riêng, cùng396ID/3KEV. Không train/gọiAPI/đổipolicy.
Thiếu metric/context thì ghi chờ, không dùng số giả. Chạy CLI, mở xem hình và báo lỗi.
```

**Prompt B — sau khi N2 giao:**

```text
Đọc artifact contract N2 và verify hash/version. Mở rộng plots.py đọc overlap,
topk_metrics, environmental_scores/context_comparison/queue. Không tự tính lại policy.
N/A giữ N/A, recall chỉCVSS/EPSS, context cùng cặp và giữ client review trong báo cáo.
Xuất hình đọc được, caption và log kiểm thủ công so với CSV. Không sửa file N2 sở hữu.
```

**Prompt C — phân tích AI phụ:**

```text
Làm mục8: prediction_rank_impact.py đọc prediction cố định và giao ID ranking với
ML held-out, táchvalidation/test. Chốt cùng cohort giữa observed/TFIDF/DistilBERT,
báo missing/coverage, tie-break và K. Không train, không gọi evaluation để tuning,
không lấy train bổ sung396. Tests cho join/version/duplicate; ghi report số thật.
```

## 12. Push Git và bàn giao artifact

Ví dụ commit đầu khi các file đã có:

```powershell
git status --short
git add src/analysis/plots.py config/phase3_plots.yaml requirements-analysis.txt tests/test_plots.py reports/p3_figures.md reports/p3_figures_check.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat(phase3): add observed ranking figures"
git push -u origin feat/p3-security-plots
```

Chỉ add file đã tạo. Commit sau add tường minh case, script/tests mới, UI contract,
notebook và báo cáo; push cùng branch. PR **base develop ← compare feat/p3-security-plots**.
Không push thẳng main, không add model/data ignored hoặc `.env`/`.venv`.
Không bắt buộc review độc lập; N1 kiểm tích hợp, N2 đối chiếu cách diễn giải.

Hình PNG/SVG nhỏ chọn lọc có thể commit theo file cụ thể sau `git diff --stat`.
Toàn bộ hình/CSV/metadata bàn giao qua ZIP riêng; không force-add data lớn.
Tạo metadata đầu ra có danh sách file/hash/bytes, input/version/commit, commands,
dependencies, số liệu coverage; lưu trong `data/processed/p3_n3/metadata.json`.

Khi hai thư mục đã tồn tại, tạo ZIP (không ghi đè bản đã gửi):

```powershell
Compress-Archive -Path data/processed/p3_n3,reports/figures/phase3 -DestinationPath data/processed/p3_n3_handoff.zip
Get-FileHash -LiteralPath data/processed/p3_n3_handoff.zip -Algorithm SHA256
```

ZIP chứa `p3_n3/` và `phase3/` ở root. Người nhận giải nén vào thư mục tạm;
đặt `p3_n3/` dưới `data/processed/`, `phase3/` dưới `reports/figures/` sau kiểm hash,
không copy đè thư mục đã có. Ghi cách giải nén này trong `docs/handoffs/p3-n3.md`.
Receipt còn ghi branch/commit, ZIP bytes/hash, dataset/policy/model versions,
lệnh đã chạy, tests/visual QA thực tế, hình nào chưa có và phụ thuộc còn thiếu.

- [ ] Có verify dữ liệu, own venv, input/version/hash rõ; không cần key/GPU.
- [ ] Scatter/top-50 thật đọc được, 396ID/3KEV và ties/ngày nguồn được ghi.
- [ ] Overlap/recall đúng CSV N2; N/A không thành0, KEV-first không là benchmark độc lập.
- [ ] Context cùng cặp, Base/Environmental và queue tách nghĩa; client review không mất.
- [ ] Case mobile có nguồn và điều kiện affected; một score Environmental đối chiếu.
- [ ] Phân tích AI phụ táchsplit/cùngID, hoặc ghi rõ blocker nếu thiếuprediction.
- [ ] Notebook có output thật, hình đã xem, UI contract đủ để Phase4 đọc offline.
- [ ] Code push branch, ZIP/hash/log gửi N1; không tự đánh dấu nhóm đã hoàn tất khi N2 chưa giao.

Nguồn giải nghĩa: [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document),
[FIRST Using EPSS](https://www.first.org/epss/using-epss),
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
Phân tích chính là mô tả trên snapshot khóa; không gọi là thử nghiệm khai thác hoặc dự báo đã kiểm định.
