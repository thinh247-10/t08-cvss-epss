# Phase 4 — Người 2: kịch bản bảo mật và kiểm nội dung demo

Giao sau tích hợp21/10/2026. Khoảng8giờ trong4–5ngày; không train/thu thập lại.
Đọc [nghiệm thu Phase3](phase-3-completion.md), [UI contract](phase-4-ui-contract.md),
[phần N3](phase-4-nguoi-3.md), [kế hoạch Phase4](phases/phase-4-tich-hop-va-demo.md).

## 1. Nhận code và gói chuẩn

Lưu việc cũ trước khi switch; terminal phải ở repo chứa `.git`:

```powershell
git status --short
git switch develop
git pull --ff-only origin develop
git switch -c docs/p4-playbook-cases
```

Branch đã có thì switch vào, fetch/merge origin/develop sau khi lưu sửa riêng.
Không forcepush/reset. Từ đây N2 sở hữu case/narrative, N3 sở hữu demo loader/notebook;
báo N1 trước khi sửa code scorer hoặc policy, không làm lại ranking theo ý demo.

Nhận **phase3_handoff_20261021.zip mới từ N1**, không dùng r1 cho số liệu demo.
Phase1/2 giữ bản đúng đã có. Mỗi người dùng own `.venv`; nếu chưa có tạo bằng
`python -m venv .venv`, sau đó:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe -m pip check
$p3Zip = Join-Path $env:USERPROFILE 'Downloads\phase3_handoff_20261021.zip'
$p3Receipt = Get-Content -Raw docs/handoffs/phase-3-complete-20261021.json | ConvertFrom-Json
(Get-FileHash -LiteralPath $p3Zip -Algorithm SHA256).Hash -eq $p3Receipt.sha256
(Get-Item -LiteralPath $p3Zip).Length -eq $p3Receipt.bytes
```

Cảhai True mới giải nén **thư mục mới**:

```powershell
Expand-Archive -LiteralPath $p3Zip -DestinationPath data/processed/p3_received_20261021
.\.venv\Scripts\python.exe scripts/package_phase3_release.py --verify data/processed/p3_received_20261021
```

Gói giữ cấu trúc repo: dưới staging có `data/processed/p3_n2`, `p3_n3`, `reports/`.
Không copy đè `.git`, config hoặc source; code lấy bằng Git. Không cần API key/GPU.
Ghi máy/Python/commit/hash/checkresult vào `reports/p4_security_acceptance.md`.

## 2. Bước A — kiểm số trên bộ hiện hành (2giờ)

Đọc CSV dưới staging, đối chiếu `reports/p3_figures.md`/`docs/analysis-results.md`.
Expected:396CVE/3KEV;15mapping/10Env/8patch/7review;2client review không rank.
Kiểm ít nhất5dòng mỗi policy, ghi ID/score/rank và kết quả, không chỉ viết “đúng”.
Kiểm tie-break, CVSS quan sát khác predicted; EPSS29/09, KEV30/09/01/10UTC.
Recall@50 CVSS1/3, EPSS3/3; mẫu3KEV nhỏ, không forecast, không “EPSS luôn tốt hơn”.
Nếu khác số, ghi blocker cụ thể và gửi N1/N3; không sửa CSV để khớp caption.

## 3. Bước B — lời thoại6phút (2giờ)

Tạo **`reports/demo-script-security.md`** riêng, N1 ghép script cuối; không cùng
sửa notebook N3. Kịch bản cần chỉ rõ màn hình/file, CVE và câu nói:

| Thời gian | Nội dung |
|---|---|
| 0:00–0:45 | Phạm vi Web/mobile,396CVE, snapshot và câu hỏi “vá trước” |
| 0:45–2:00 | Ba top50, overlap; Base khác likelihood, KEV-first là policy |
| 2:00–3:30 | PgHero/Discourse: applicability, CR/IR/AR, rank severity khác queue |
| 3:30–4:30 | MOB-02: điều kiện iOS/plugin, client còn review dùEnv9.8 |
| 4:30–5:20 | N3 giới thiệu predictedvector/score + sai số; không thay nguồn quan sát |
| 5:20–6:00 | Quyết định xác minh/vá, giới hạn mẫu và chính sách giả định |

Không buộc lời nói đúng từng giây, phải diễn tập đo thật. Chọn từ5case có nguồn,
không thêm CVE ngoài cohort chỉ để có câu chuyện “ấn tượng”. Case Web N1 và case
mobile N3 đã có tại `docs/cases/`; giữ nguồn và khác biệt nhãn advisory/NVD.

## 4. Bước C — Q&A, playbook và xử lý ngoại lệ (2giờ)

Tạo **`docs/demo-qa.md`** ít nhất10 câu, mỗi câu2–4 câu trả lời kèm nguồn/file:
CVSS cao chưa vá trước? EPSS là gì? KEV vắng nghĩa gì? Vì sao ngày khác?
Vì sao3KEV chưa khái quát? Vì sao mobile còn review? Env có phải xác suất?
Vì sao15mapping không15hệthống? AI sai thì sao? Vì sao TF-IDF tốt hơn DistilBERT ở metric này?

Rà `docs/04-patch-playbook.md`: version/applicability trước queue, backup/rollback,
bản sửa còn hỗ trợ, kiểm sau vá, ngoại lệ khôngdowntime/bảnvá chưa có. SLA chỉ là
đề xuất giả định, không ghi đã giảm rủi ro bằng số đo chưa có. Không thêm exploit.
Mỗi sửa chính sách phải có rationale/version; nếu chỉ sửa câu chữ thì không đổi dataset.

## 5. Bước D — nghiệm thu màn hình với N3 (2giờ)

Đợi N3 giao demo; chạy từng flow và ghi vào `reports/p4_security_acceptance.md`:
case, expected, actual, pass/fail, inputversion, screenshot/file liên quan.
Đặc biệt: missing hiển thịN/A; false không-KEV không biến true; client không biến mất;
predicted không nằm cộtobserved; top50 đủ2trang; date/nguồn truy được.
Chưa có demo thì ghi pending, tiếp tục chuẩn bị script/Q&A; không ký pass thay bạn.

## 6. Prompt và bàn giao

```text
Đọc docs/phase-4-nguoi-2.md và biên bản Phase3. Kiểm gói/phiên bản hiện hành,
so CSV/caption, viết demo-script-security và demo-qa từ case có nguồn.
Không train/tảiAPI/sửaCSV để khớp báo cáo; không viết pass cho demo chưa chạy.
N3 sở hữu UI/loader; báo lỗi bằng expected/actual, file/ID cụ thể. Chỉ sửa playbook
khi có căn cứ và giữ giả định tách dữ kiện.
```

Commit chỉ file đã làm:

```powershell
git add reports/demo-script-security.md reports/p4_security_acceptance.md docs/demo-qa.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(phase4): prepare security demo and acceptance evidence"
git push -u origin docs/p4-playbook-cases
```

Nếu có sửa playbook add riêng file đó. PR base develop←branch này. Gửi N1 link/commit,
script, log thực chạy và blocker; không gửi lại model/data nguyên gói.
Hoàn tất khi số liệu đã đối chiếu, script/Q&A có nguồn, demo thực chạy và vấn đề chặn
đã sửa hoặc thống nhất cắt. Không phụ thuộc review độc lập bắt buộc.
