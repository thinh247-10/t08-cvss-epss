# Phase 4 — Người 3: demo local offline và hiển thị AI

Giao21/10/2026, khoảng8giờ/4–5ngày. Sản phẩm bắt buộc **CLI+notebook6phút**.
Chưa cần Streamlit/Docker/cloud; chỉ mở rộng sau khi demo tối thiểu chạy đúng.
Đọc [nghiệm thu Phase3](phase-3-completion.md), [UI contract](phase-4-ui-contract.md)
và [N2](phase-4-nguoi-2.md). Không train/tuning thêm, không đổi ranking/split.

## 1. Branch, gói và môi trường

Lưu công việc cũ, vào đúng rootrepo rồi:

```powershell
git status --short
git switch develop
git pull --ff-only origin develop
git switch -c feat/p4-demo
```

Branch đã có thì switch, fetch/merge develop sau khi lưu sửa riêng. N3 sở hữu
`src/demo/`, notebook demo/tests/dependencies; N2 sở hữu lời thoại/Q&A; N1 runbook/release.

Nhận **phase3_handoff_20261021.zip mới**, không dùng pinnedr1 ở demo cuối.
Xem mục1 [hướng dẫn N2](phase-4-nguoi-2.md) để kiểm SHA/bytes và giải nén
`data/processed/p3_received_20261021`; chạy `scripts/package_phase3_release.py --verify ...`.
Gói này có15mapping/10Env/8patch/7review,396CVE. Phase1 và Phase2 dùng lại bản đúng.
Model/baseline gốc N3 chưa nhận; dùng version N1 đã khóa, không ghi “model gốc N3”.

Own `.venv` hiện có; nếu thiếu tạo `python -m venv .venv`:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-analysis.txt
.\.venv\Scripts\python.exe -m pip check
```

Không cần API key/GPU cho luồng đọc artifact. TF-IDF inference chạy CPU với
`requirements-model.txt`. DistilBERT live là tùy chọn, có Torch mới bật;
không cài Torch bắt buộc chỉ để mở notebook. Demo dự phòng đọc prediction lưu sẵn,
ghi nhãn “kết quả đã lưu”, không giả là vừa chạy model.

## 2. Bước A — adapter dữ liệu và CLI (2giờ)

Tạo `src/demo/__init__.py`, **`src/demo/data_loader.py`**, **`src/demo/cli.py`**.
Loader nhận `--phase1`, `--phase2`, `--phase3`/configpaths, không hardcodeD:/Downloads.
Tái dùng verifier có sẵn, adapter đọc layout gói Phase3 (`data/processed/p3_n2`,
`p3_n3`, `reports/`) dưới staging. Check manifest, dataset/context version, keyunique,
CSVboolean/ranknullable, và input readonly trước khi hiển thị.

| Hàm/view cần có | Tác dụng |
|---|---|
| `load_release(...)` | Xác minh hash/version, trả dữ liệu đã validate; không gọi API |
| `lookup_cve(cve_id)` | Description/vector/Base nguồn+3rank+EPSS/ngày/KEV; ID không có báo rõ |
| `lookup_asset_pairs(cve_id)` | Leftjoin mapping→scores→queue; giữ đủreview, N/A+reason |
| `lookup_prediction(cve_id,model_version)` | Lọc đúng model/split, hiển thị8predmetrics/vector/score riêng |
| CLI `summary`, `cve`, `predict` | Luồng offline có `--help`, input rỗng/error dễ hiểu |

Hàm trên là interface đề xuất **chưa triển khai lúc giao**. CLI có thể chọn cấu trúc
subcommands, nhưng N3 phải ghi command thực chạy ở `docs/demo-commands.md`.
Thiếu Phase2 chỉ khóa viewAI, không tự dùng model khác. Saihash dừng view liênquan;
không load joblib từ người lạ, chỉ model tin cậy trong receipt của nhóm.

## 3. Bước B — notebook demo và model (2giờ)

Tạo **`notebooks/03_demo.ipynb`**, giữ `03_priority_analysis.ipynb` làm bằng chứng nghiên cứu.
Notebook gọi loader/module, không chép lại scorer/công thức. Luồng6phút:
scope/snapshot→top50→caseWeb→caseMobile→AI→quyếtđịnh/giới hạn.
Mỗi view có tiêu đề tiếngViệt đơn giản, nguồn/ngày khi cần; không phơi stacktrace dài.

AI tối thiểu: một mô tả validation đã có, dùng baseline đã verify để dự đoán thật
bằng `src.model.predict` hiện có (đọc `--help` trước), hiện8metrics và Base;
cho thấy prediction và observed không trùngnghĩa. Ghi mode/modelversion.
Nếu thiếu dependency/model, bảngprediction đã lưu vẫn mở được kèm nhãn mode.
Không dùng kết quảtest để chỉnhmodel; không tự fit khi khởi động demo.

Tạo **`scripts/execute_demo_notebook.py`** nếu dùng runnerstdlib như Phase3;
chạy đủcells, lưu output thật. Hình dùng bộPhase3 đãverified, không vẽ mock để chữa thiếu.
Trốngdescription→thông báo; IDngoàicohort→không có bản ghi; cần không crashing toàn notebook.

## 4. Bước C — test lỗi, offline và dự phòng (2giờ)

Tạo **`tests/test_demo_data.py`**: fixture nhỏ kiểm boolFalse, nullkhác0,
duplicate/version/hash sai, giữclient/review, split/model tách, thiếuAI không phá summary.
Test loader không gọi network/train (mock các entrypoint cấm), không sửa input.
Thêm smoke local với gói thật; không chỉ unitfixture.

`reports/p4_demo_check.md`: command, OS/Python/deps, model/hash/inputversion,
thời gian mở/nạp, expected/actual cho từng lỗi, modeoffline, kết quảmodelsave/load nếu có.
Mạng tắt mà demo vẫn phải có bảng/hình; tải thư viện trước buổi demo, không thửdownload lúc trình bày.

Dự phòng: notebookđãchạy,7PNG/CSV,scriptlờithoại N2, predictionđãlưu; ghi cách mở
trong `docs/demo-commands.md`. Không viết “offlinepass” khi chỉ suy đoán từ code.
Không cần người dùng tự bỏ secret/mở cổng vì demo chỉ đọc filelocal.

## 5. Bước D — ghép lời thoại và chạy lại máy khác (2giờ)

Nhận `reports/demo-script-security.md` từN2; N1 tạo `reports/demo-script.md` cuối.
N3 chạy notebook trên máy mình từ gói mới theo runbookN1; log path/hash/commit,
khác biệt môi trường, screenshot/output và tổngthời gian6phút thực tế.
N2 kiểm “CVSS cao chưa vá trước” và mobile review; bạn sửa cáchhiểnthị đúng feedback.
Nếu có lỗi numerical, trả lại N2/N1 vớiID; không sửaCSV haypolicy cho hợp màn hình.

## 6. Lịch và file ownership

Ngày1 loader/CLI; ngày2 notebook/AI; ngày3 tests/offline/fallback;
ngày4–5 chạy runbookmáyN3 và rehearsal cùngN2/N1. Trong lúc chờN2, dùng case/text
Phase3 làm bảnnháp, không chờ mới code. Không sửa `plots.py`/scorer nếu không cóbug xácnhận.
Nếu muốn Streamlit, báo N1 sau khi các gate bắtbuộc đạt; không lấy giờbáocáo để xâyUI mới.

## 7. Prompt vibe code

```text
Đọc docs/phase-4-nguoi-3.md, UI contract và receipt Phase3 hiệnhành.
Triển khai loader/CLI readonly offline, dùng verifier/scores/rankings đãcó.
Giữcontext-v2, nullable và leftjoin clientreview; vectorAI táchobserved.
Không train/tảiAPI/đổisnapshot. Test missingAI, badhash/version/duplicate/False/null.
Sau loader chạy được mới tạo notebook6phút và runner; chỉ ghi test/demo đãthựcrun.
```

## 8. Commit/push/bàn giao

Chỉadd file đãtạo, ví dụBướcA:

```powershell
git add src/demo/__init__.py src/demo/data_loader.py src/demo/cli.py tests/test_demo_data.py docs/demo-commands.md
git diff --cached --check
git diff --cached --stat
git commit -m "feat(phase4): add verified offline demo loader and CLI"
git push -u origin feat/p4-demo
```

Commit tiếp notebook/runner/report riêng, PRbase develop←feat/p4-demo.
GửiN1 commit, command, report và pending. Notebooknhẹ/hình chọnlọc commitđược;
khôngadd `.venv/.env/models/` hoặc dataignored. Không cần tạo lại góiPhase1/2/3 khi
chỉ thaydemo; nếu output mới lớn thìZIP riêng cóhash/bytes, ghi receipt.
Hoàn tất khi demooffline chạy thật, AI cómode rõ, testpass, N2 đã kiểm nội dung
và runbook đãthử trên máynhận. Chưa có xácnhận thì ghi pending, không tự ký thayN1/N2.
