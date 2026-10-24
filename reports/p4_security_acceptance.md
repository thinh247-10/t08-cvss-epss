# Phase 4 — N2 security acceptance

> Cập nhật 2026-10-23: đã nhận/chạy demo N3 `4c15746`, nghiệm thu kỹ thuật/nội dung
> bước D đạt trong phạm vi mục 5 bên dưới. Các dòng pending ngày 21/10 là lịch sử.
> Chưa diễn tập người thật hoặc duyệt runbook cuối N1; không tuyên bố toàn nhóm xong Phase 4.

## 1. Nhận code và xác minh dữ liệu — PASS (2026-10-21)

Phạm vi lần kiểm này chỉ là mục 1 trong `docs/phase-4-nguoi-2.md`.
Chưa nghiệm thu số liệu/caption bước A hoặc CLI/notebook bước D.

### Máy và code

- Máy: `CanhLai`; OS: `Windows-11-10.0.26200-SP0`.
- Python: `3.13.12`, môi trường riêng của repo `.venv`, không dùng system-site-packages.
- Repo: `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/t08-cvss-epss`.
- Đã fetch origin, switch develop, pull `--ff-only`, tạo `docs/p4-playbook-cases`.
- Commit đầu vào: `0f18dd3e852250539e6db303e1be2593b0c054a9`.
- Trước switch không có sửa tracked; file untracked `q` được giữ nguyên, không stage.
- Đã đọc nhiệm vụ N2/N3, UI contract, kế hoạch Phase 4 và biên bản nghiệm thu Phase 3.

### Gói và kết quả thực chạy

- ZIP nhận: `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/4/phase3_handoff_20261021.zip`.
- Receipt: `docs/handoffs/phase-3-complete-20261021.json` tại commit đầu vào.
- Bytes: `2040877`; đối chiếu receipt: **True**.
- SHA-256: `df03b51e7a9572d8ac055f40e6343a3fc827efd286a2e7cb2c862a2776d9cd0a`;
  đối chiếu receipt: **True**.
- ZIP CRC, đường dẫn không thoát staging và tên entry không trùng: **PASS**; 104 entry.
- Đích mới: `data/processed/p3_received_20261021`; trước giải nén chưa tồn tại.
- Không copy đè code/config/source hoặc sản phẩm Phase 3 cũ; toàn bộ gói nằm dưới staging.
- Manifest verifier: **PASS**, 103 file, `context_version=phase3-context-v2`.
  Entry còn lại là `phase3_manifest.json`.

Lệnh verifier đã chạy từ repo root:

```powershell
.\.venv\Scripts\python.exe scripts/package_phase3_release.py --verify data/processed/p3_received_20261021
```

Kết quả:

```json
{"status": "pass", "files": 103, "context_version": "phase3-context-v2"}
```

### Dependencies và khó khăn đã xử lý

Lần đầu pip gặp `UnicodeEncodeError` (cp1252) khi in đường dẫn tiếng Việt, trả exit 2.
Đã chạy lại với UTF-8 và tắt progress bar; install exit 0, sau đó `pip check` exit 0:

```powershell
$env:PYTHONUTF8='1'
$env:PYTHONIOENCODING='utf-8'
.\.venv\Scripts\python.exe -m pip install --progress-bar off -q -r requirements-analysis.txt
.\.venv\Scripts\python.exe -m pip check
```

Output: `No broken requirements found.`

Phiên bản thực tế: pip 25.3, pandas 3.0.6, numpy 2.5.3, scipy 1.18.1,
scikit-learn 1.9.1, pyarrow 25.0.1, PyYAML 6.0.3, matplotlib 3.11.2.
Không cần API key/GPU; không train, inference, tải lại snapshot hay sửa dữ liệu nguồn.
Mạng chỉ dùng để nhận Git/dependencies, chưa phải bằng chứng demo offline.

### Checklist và phần còn lại

- [x] Giữ nguyên việc cũ, cập nhật develop bằng fast-forward.
- [x] Tạo branch N2 Phase 4.
- [x] Nhận gói mới của N1, đối chiếu SHA-256 và bytes.
- [x] Kiểm ZIP và giải nén vào staging mới.
- [x] Xác minh manifest 103 file.
- [x] Cài dependencies và pip check.
- [x] Ghi máy/Python/commit/hash/kết quả kiểm tại báo cáo này.
- [x] Bước A: đối chiếu dòng dữ liệu, policy, caption và ngày nguồn (2026-10-21; xem mục 2).
- [ ] Bước B: đã soạn script, chờ ghép demo và diễn tập đo thật (xem mục 3).
- [x] Bước C: Q&A và rà playbook (2026-10-21; xem mục 4).
- [ ] Bước D: chờ demo N3 và chạy nghiệm thu thật; không ký pass trước.

Không còn blocker cho mục 1. Chưa commit/push hoặc tạo PR Phase 4 trong lần này.

## 2. Bước A — đối chiếu bộ hiện hành (2026-10-21)

**PASS về số liệu; một lưu ý câu chữ lịch sử, không chặn bước B.**
Input lấy từ staging `data/processed/p3_received_20261021`, không dùng thư mục
`data/processed/p3_n2` cũ trên máy. Dataset/context/commit/ZIP như mục 1.
Không sửa CSV, policy, scorer, caption hay gói nhận.

### Phương pháp và kết quả thực chạy

Audit độc lập chỉ đọc bằng Python stdlib CSV/JSON, sắp thứ tự theo quy tắc công bố,
không gọi producer để tự so kết quả với chính nó. Kiểm cả 396 dòng mỗi policy.
Script kiểm: `p4_step_a_audit.py` trong workspace hội thoại (không phải code sản phẩm).
Đọc Parquet bằng Python repo riêng vì runtime bundled không có pyarrow.

| Kiểm tra | Expected | Actual | Kết quả |
|---|---|---|---|
| Manifest sau audit | 103 file nguyên vẹn | Hash/bytes 103 file khớp | PASS |
| Ranking cohort | 396 ID duy nhất, 3 KEV | 396 / 3; bool chỉ True/False | PASS |
| Nguồn quan sát | Cùng cohort Phase 1 | Hash/bytes Parquet khớp metadata; join ID, Base/EPSS/KEV khớp 396 dòng | PASS |
| Ba policy | Rank 1..396 đúng rule | 1.188 vị trí khớp thứ tự tính độc lập | PASS |
| Top-50 N3 | 3×50, đúng ID/score/KEV | 150 dòng khớp; vị trí 1–25 và 26–50 đủ | PASS |
| Mapping / Environmental / queue | 15 / 10 / 15 | Pair key duy nhất, queue giữ đủ mapping | PASS |
| Queue | 8 patch / 7 review | 8 / 7; review rank trống | PASS |
| Client | 2 review, rank null | MOB-01/MOB-02 Env=9.8, review, rank null | PASS |
| API-02 | Environmental thiếu, giữ review | Environmental trống, rank trống, review | PASS |
| Context comparison | Cùng 8 patch pairs | 8 dòng; không dùng 15 mapping làm mẫu số | PASS |
| Overlap | K=10/20/50 | Cả 9 giao/hợp/Jaccard tính lại khớp JSON | PASS |
| Tau-b | Điểm gốc, giữ ties | 0.30569771817081276 | PASS |

Tau-b đếm cặp độc lập: concordant=46513, discordant=23839,
tie CVSS only=7776, tie EPSS only=63. Không tính tau từ rank đã phá hòa.

### Bằng chứng ít nhất 5 dòng mỗi policy

Mỗi dòng dưới có rank expected = actual; score đọc trực tiếp từ CSV đã kiểm với
nguồn Phase 1. CVSS sort Base giảm → ID tăng; EPSS sort EPSS giảm → ID tăng;
KEV-first sort KEV giảm → EPSS giảm → Base giảm → ID tăng.

| Policy | CVE | Base | EPSS | KEV | Rank expected / actual | Kết quả |
|---|---|---:|---:|---|---|---|
| CVSS | CVE-2014-125052 | 9.8 | 0.00643 | false | 1 / 1 | PASS |
| CVSS | CVE-2021-36392 | 9.8 | 0.00841 | false | 2 / 2 | PASS |
| CVSS | CVE-2021-36393 | 9.8 | 0.52299 | false | 3 / 3 | PASS |
| CVSS | CVE-2021-36394 | 9.8 | 0.07034 | false | 4 / 4 | PASS |
| CVSS | CVE-2023-23556 | 9.8 | 0.00891 | false | 5 / 5 | PASS |
| EPSS | CVE-2023-44487 | 7.5 | 0.99999 | true | 1 / 1 | PASS |
| EPSS | CVE-2024-38475 | 9.1 | 0.99957 | true | 2 / 2 | PASS |
| EPSS | CVE-2023-23752 | 5.3 | 0.99827 | true | 3 / 3 | PASS |
| EPSS | CVE-2024-27316 | 7.5 | 0.91327 | false | 4 / 4 | PASS |
| EPSS | CVE-2024-43425 | 8.1 | 0.87536 | false | 5 / 5 | PASS |
| KEV-first | CVE-2023-44487 | 7.5 | 0.99999 | true | 1 / 1 | PASS |
| KEV-first | CVE-2024-38475 | 9.1 | 0.99957 | true | 2 / 2 | PASS |
| KEV-first | CVE-2023-23752 | 5.3 | 0.99827 | true | 3 / 3 | PASS |
| KEV-first | CVE-2024-27316 | 7.5 | 0.91327 | false | 4 / 4 | PASS |
| KEV-first | CVE-2024-43425 | 8.1 | 0.87536 | false | 5 / 5 | PASS |

Cutoff CVSS K=10/20 cùng nhóm 28 CVE Base=9.8, lần lượt chọn 10/20 theo ID.
EPSS và KEV-first trùng top-K set không chứng minh toàn bộ thứ tự giống nhau.

### Recall và thời gian nguồn

| K | CVSS hits / 3 | EPSS hits / 3 | KEV-first recall |
|---|---|---|---|
| 10 | 0/3 | 3/3 | N/A: policy_uses_kev_directly |
| 20 | 0/3 | 3/3 | N/A: policy_uses_kev_directly |
| 50 | 1/3 | 3/3 | N/A: policy_uses_kev_directly |

Ngày kiểm với `ranking_metrics.json`: EPSS `2026-09-29`;
KEV released `2026-09-30T16:59:23.0688Z`;
KEV retrieved `2026-10-01T11:29:35.854976+00:00`.
Ba mốc khác nhau, không gọi chung ngày snapshot duy nhất. Mẫu số 3 KEV nhỏ;
chỉ đối chiếu snapshot, không forecast hay kết luận EPSS luôn tốt hơn.
Không-KEV không chứng minh chưa từng khai thác.

### Đối chiếu case, caption và predicted/observed

- `reports/p3_figures.md` ở repo và staging byte-identical; số N/K, ties,
  ngày nguồn, tau-b và queue khớp các kiểm tra trên.
- `docs/analysis-results.md` repo/staging không khác nội dung theo Git diff
  (hash byte khác vì LF/CRLF). Cả 5 dòng bảng case khớp Base/EPSS/3 ranks/Env/queue:
  WEB-01 7.2/0.00640/152/185/184/7.2/patch5;
  API-01 CVE-2022-46177 8.1/0.00679/55/171/171/8.8/patch2;
  ADMIN-01 7.5/0.00831/75/134/134/9.3/patch8;
  MOB-01 9.8/0.01249/11/86/86/9.8/review;
  MOB-02 9.1/0.00874/30/128/127/9.8/review.
- AI comparison giữ 354 dòng held-out, chỉ validation/test và model không dummy;
  Base quan sát khớp ranking theo ID. Ví dụ CVE-2023-38709 validation TF-IDF:
  observed Base=7.3, predicted=9.1, observed rank=25, predicted rank=2, delta=23.
  Đây là rank severity trên common held-out population, không phải queue hay rank toàn 396.
  Không đổi observed thành predicted. Chưa kiểm cách UI hiển thị (thuộc D).

### Lưu ý và gate tiếp theo

Không có blocker số liệu cần N1/N3 sửa ở bước A. Một lưu ý câu chữ:
`docs/analysis-results.md` mục Hermes còn câu “Chưa tích hợp case mobile riêng của N3”
và tiêu đề mục 7 còn “còn chờ”, trong khi cuối mục 7 và biên bản nghiệm thu đã xác nhận
tích hợp ngày 21/10. Đây là câu lịch sử, không phải thiếu case/dữ liệu hiện tại.
Khi soạn script bước B phải theo biên bản hiện hành, không đọc nguyên câu cũ;
có thể đề nghị N1 đồng bộ câu chữ khi ghép tài liệu. Chưa gửi thông báo thay người dùng.

- [x] Bước A hoàn tất đối chiếu số liệu và ghi bằng chứng.
- [ ] B: phần soạn đã có, diễn tập pending (xem mục 3).
- [x] C: Q&A và playbook đã rà (xem mục 4).
- [ ] D vẫn pending demo N3, không ký pass UI/offline/rehearsal.

## 3. Bước B — lời thoại demo (2026-10-21)

**Phần soạn hoàn tất; diễn tập chưa hoàn tất.** Đầu ra:
`reports/demo-script-security.md`, sáu đoạn theo ngân sách 0:00–6:00 trong nhiệm vụ N2.
Mỗi đoạn có view/file dự phòng, CVE, nguồn và câu nói. Chọn PgHero/Discourse/MOB-02
từ case hiện có; ví dụ AI validation riêng CVE-2023-38709 không giả làm case mobile.

Đã kiểm thực tế: cả 5 ID trong script thuộc cohort; 9 link tài liệu local tồn tại;
6 mục thời gian; PgHero Base rank 2, Env rank 1, context rank 8, sensitivity rank 2
khớp context_comparison. Ví dụ CVE-2023-23752 Base 5.3/EPSS 0.99827, EPSS và
KEV-first rank 3 khớp CSV. Ví dụ AI observed 7.3/predicted 9.1, rank 25/2, delta 23
đã kiểm ở A. Không sửa code scorer/policy/data hay notebook N3.

Hạn chế được ghi rõ trong script:

- Checkout chưa có demo N3, nên chưa biết lệnh/cell thật; không bịa lệnh đã chạy.
- Case mobile N3 còn link r1 và context-v1 lịch sử; narrative có nguồn nhưng demo phải
  dùng số liệu staging context-v2. Không sửa case thuộc N3 hoặc input ZIP trong bước này.
- Comparison Phase 3 không chứa predicted vector. N3 cần lấy đủ 8 metric/vector từ
  prediction Phase 2 đã verify khi ghép panel AI; không suy vector từ Base score.
- Chưa diễn tập, chưa đo thời lượng, chưa kiểm UI/offline; không ghi các mục này pass.

Phần còn lại của B cần N1/N3 ghép thao tác và người trình
bày diễn tập thật, ghi thời gian/commit/mode/lỗi. Chưa commit/push trong bước này.

## 4. Bước C — Q&A, playbook và ngoại lệ (2026-10-21)

**Hoàn tất phần chuẩn bị C**, không thay nghiệm thu demo hoặc phê duyệt vận hành.

- Tạo `docs/demo-qa.md`: 15 câu, mỗi câu 2–4 câu trả lời và có nguồn/file;
  bao phủ 10 chủ đề bắt buộc cùng ties/population, missing, ngoại lệ và đóng ticket.
- Kiểm 34 link local trong Q&A đều tồn tại; đối chiếu số liệu mô hình với
  `reports/p2_model_comparison.csv` và protocol `reports/p2_distilbert_run.md`.
- Không suy nguyên nhân chênh lệch model từ một lần chạy: TF-IDF tốt hơn validation
  macro-F1 toàn ML, nhưng DistilBERT tốt hơn Base MAE scoped test và tau-b rank test.
- Rà playbook theo checklist dưới; chỉ đồng bộ trạng thái tích hợp cũ và bổ sung
  hồ sơ ngoại lệ/trigger tái xét. Đã ghi rationale/revision tài liệu 2026-10-21;
  không đổi policy context-v1, SLA giả định, dataset/context/scorer hoặc CSV.

| Mục rà playbook | Evidence trong docs/04-patch-playbook.md | Kết quả |
|---|---|---|
| Applicability/version trước queue | Mục 2 và 4; unknown không thành unaffected | Đạt |
| Bản còn hỗ trợ chứa fix | Mục 4; không coi mốc fix lịch sử là bản nên cài hiện nay | Đạt |
| Backup/restore/rollback | Mục 4–5; migration không đảo được, mobile forward fix | Đạt |
| Kiểm sau vá/đóng ticket | Mục 5; version, chức năng, quyền và evidence thật | Đạt |
| Chưa patch / không downtime | Mục 6; biện pháp vendor, cửa sổ bảo trì, risk acceptance | Đạt |
| Owner/duyệt/hạn tái xét ngoại lệ | Mục 6; bổ sung trường hồ sơ và trigger mở lại/escalate | Đạt |
| Tách SLA/giả định khỏi dữ kiện | Mục 3 và 5; chưa đo giảm rủi ro/giờ vá | Đạt |
| Không exploit hoặc tự hạ metric | Mục 4 và 6 | Đạt |

Kiểm thực chạy: `python -m unittest tests.test_phase3_reports -q` — 3 tests OK;
verifier gói nhận — pass 103 file/context-v2 sau sửa docs repo (không sửa staging).
Không có blocker cho C. Q&A chưa diễn tập, B còn pending ghép/đo thời lượng,
D còn pending demo N3. Chưa commit/push hoặc gửi thông báo cho N1/N3.

## 5. Bước D — N2 chạy demo N3 (2026-10-23)

**PASS nghiệm thu kỹ thuật và nội dung có công cụ hỗ trợ; rehearsal người thật pending.**
Không ký xác nhận người trình bày/nhóm hoặc runbook N1 chưa nhận.

### Nhận code và input

- N3 `origin/feat/p4-demo`: `4c157465303270106b4d32c13a83d35370abc3a2`.
- Xuất code bằng Git archive vào snapshot riêng trong workspace hội thoại:
  `C:/Users/chann/OneDrive/Tài liệu/ChatGPT/NT 213 - Bảo mật Web và ứng dụng/p4-n3-review-4c15746`.
  Không merge branch N3 vào N2 hoặc ghi đè notebook N3 trong repo chính.
- Runner ghi commit `unavailable` vì snapshot không có `.git`; commit xuất và
  code hashes trong JSON là bằng chứng nguồn, không giả đây là Git checkout sạch.
- Máy CanhLai, Python 3.13.12, Windows 11 10.0.26200, `.venv` repo N2 dùng chung
  để chạy code snapshot; đây là chạy trên máy nhận N2, không môi trường sạch mới.
- Phase 1/3 dùng đường liên kết tới các staging đã kiểm mục 1/A, chỉ đọc.
- Phase 2 ZIP tại `D:/UIT/Tài Liệu/NT/NT213 - Bao Mat Web/T08/3/phase2_handoff_20261017.zip`:
  bytes `253203876`, SHA-256
  `902f97cc84727a98cd36b9f3c17797927979e85f87466972d3f4ab5add1171ce`,
  khớp receipt `docs/handoffs/phase-2-complete-20261017.json` trước giải nén.
  Giải nén Phase 2 và baseline.zip vào thư mục mới trong snapshot; loader kiểm
  outer manifest/nested ZIP/model trước load. Không dùng joblib cũ ở repo root.

### Lệnh thực chạy

Từ root snapshot, dùng executable Python `.venv/Scripts/python.exe` của repo N2:

```powershell
python -X utf8 -m unittest tests.test_demo_data -q
python -X utf8 scripts/execute_demo_notebook.py --output reports/n2_live.ipynb --report reports/n2_live.json
python -X utf8 n2_acceptance_check.py
python -X utf8 scripts/execute_demo_notebook.py --saved-only --output reports/n2_saved.ipynb --report reports/n2_saved.json
python -X utf8 scripts/execute_demo_notebook.py --no-ai --output reports/n2_no_ai.ipynb --report reports/n2_no_ai.json
```

`n2_acceptance_check.py` là harness riêng trong snapshot, không sửa code N3;
kiểm adapter/presentation/CLI với input thật và giữ expected/actual trong JSON.

### Expected / actual và bằng chứng

| Flow/kiểm | Expected | Actual | Kết quả |
|---|---|---|---|
| Test demo | Toàn bộ fixture + smoke release thật | 29 tests OK, không skip, 62.487s | PASS |
| Tổng quan | 396/3, 15 mapping/10 Env, 8 patch/7 review | Khớp; ngày nguồn tách EPSS/released/retrieved | PASS |
| MOB-02 CVE-2023-41387 | Base9.1/EPSS0.00874/rank30,128,127; KEV false | Khớp kiểu boolean, không truthy string | PASS |
| MOB-01/MOB-02 | Env9.8, client review, rank null | Cả hai còn trong left join, không biến mất | PASS |
| API-02 CVE-2023-22626 | Env/rank null có lý do, review | Khớp; bảng HTML có N/A và reason | PASS |
| PgHero ADMIN-01 | Severity Base2/Env1; queue8/sensitivity2 | Khớp cùng 8 patch pairs | PASS |
| AI validation/test | 69 / 108 riêng | Khớp; không ghép train/mobile | PASS |
| AI ví dụ validation | observed7.3/predicted9.1, tách vector/8 metric | Live TF-IDF khớp saved; C:L/I:L/A:L khác C:N/I:H/A:H | PASS |
| AI mobile train | Không prediction held-out | Hiện reason, không lấy train để bù | PASS |
| CLI hai case và ID rỗng | JSON hợp lệ; ID rỗng exit2 không traceback | Khớp | PASS |
| Top-50 | Đủ hai trang 1–25/26–50 và ngày nguồn | Notebook nhúng đủ; đã mở xem cả 2 PNG, nhãn đọc được | PASS |
| Notebook live | 7 cell/7 PNG, không sửa input | 13.8401s; 224 file không đổi | PASS |
| Notebook saved | 7 cell/7 PNG, mode saved | 6.3415s; 224 file không đổi | PASS |
| Notebook no-AI | Vẫn có summary/context/hình | 7 cell/7 PNG; 2.7655s; 119 file không đổi | PASS |
| Offline tiến trình | Chặn socket và thử DNS guard | Guard verified ở cả 3 mode | PASS |

Không tắt card mạng Windows; không gọi kết quả socket guard là kiểm máy mất mạng.
Thời gian trên là thời gian thực thi code, không phải thời gian nói demo 6 phút.
Kiểm HTML/presentation và output notebook bằng artifact thực chạy, chưa phải
người dùng trực tiếp duyệt toàn bộ giao diện Jupyter trên màn hình.

Log giữ trong repo để N1/N3 kiểm:

- [19 kiểm expected/actual N2](p4_n2_demo_checks_20261023.json).
- [Notebook live](p4_n2_demo_live_20261023.json).
- [Notebook saved](p4_n2_demo_saved_20261023.json).
- [Notebook no-AI](p4_n2_demo_no_ai_20261023.json).

Notebook output riêng trong snapshot: `reports/n2_live.ipynb`, `n2_saved.ipynb`,
`n2_no_ai.ipynb`; không commit thêm các notebook lớn. Các JSON chứa code hash,
input paths/model/version và kết quả chạy. Model TF-IDF SHA-256
`c68d530ff7818f5d469da647246e787517d9d213b59286d9a6f67dd647d05265`.

### Vướng mắc và trạng thái cuối

Lần chạy sandbox ban đầu bị quyền Temp/junction (WinError5), không phải lỗi logic
demo. Đã chạy lại ngoài sandbox theo approval: 29 tests không skip và cả ba mode pass.
Tar Windows ban đầu không xử lý đường dẫn Unicode; đã giải archive bằng Python
tarfile với data filter trong snapshot riêng, không chỉnh dữ liệu gốc.

Không phát hiện lỗi chặn kỹ thuật/nội dung ở các flow đã kiểm. N3 đã nhận script
N2 và ghép thao tác trong `reports/demo-script-n3.md`; các phụ thuộc cell/vector
được kiểm lần này, không còn chờ N3 giao code như ngày 21/10.

- [x] D — nhận demo, chạy kiểm kỹ thuật/nội dung và ghi bằng chứng N2.
- [x] B — N3 đã ghép cell/thao tác với lời dẫn N2, vector AI thực đã kiểm.
- [ ] B — người thật diễn tập đo tổng thời lượng và chuyển màn hình.
- [ ] N1 — chốt script/runbook chung, tiếp nhận log và duyệt gate nhóm.
- [ ] Người trình bày — xem output notebook thực trên UI và xác nhận thao tác buổi diễn tập.

N2 không tự ký thay các mục phối hợp còn lại hoặc tuyên bố toàn Phase 4 hoàn tất.
