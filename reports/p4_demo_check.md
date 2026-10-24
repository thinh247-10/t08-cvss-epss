# Phase 4 — kiểm demo Người 3, ngày 22/10/2026

> Trạng thái cập nhật 24/10: N3 đã push4c15746, N2 đã nghiệm thu kỹ thuật/nội dung
> tại55fa749; đã tích hợp develop. Phần dưới giữ lịch sử lần chạy22/10.
> Trạng thái nhóm hiện hành: [release checklist](release-checklist.md).

Đã triển khai và chạy local: loader/CLI chỉ đọc, notebook 6 phút dự kiến,
runner offline, prediction đã lưu và TF-IDF live validation. **Chưa nghiệm thu
toàn nhóm**: chưa có lời thoại/xác nhận N2, runbook N1 hoặc buổi diễn tập có đo giờ.

## Input và môi trường thực chạy

- Windows 11 `10.0.26200`, Python **3.13.16**, `.venv` của workspace.
- pandas 3.0.6, numpy 2.5.3, pyarrow 25.0.1, PyYAML 6.0.3,
  scikit-learn 1.9.1, joblib 1.6.0, scipy 1.18.1, matplotlib 3.11.2.
- `pip check`: **No broken requirements found**. Không cài dependency mới.
- HEAD lúc kiểm: `0f18dd3e852250539e6db303e1be2593b0c054a9`, branch `develop`;
  source demo và nhiều thay đổi có sẵn chưa commit. Đây không phải mã commit riêng
  của sản phẩm N3. Không switch/reset/stash/commit/push các thay đổi có sẵn.
- Phase 1 `data/processed/phase1_v1_20261010`; verifier sẵn có đạt 14 file,
  67.912 Base scores, 0 mismatch; 396 ranking CVE, 3 KEV.
- Phase 2 `data/processed/phase2_received`; Phase 3 mới
  `data/processed/p3_received_20261021`. ZIP được nhận từ `D:/Downloads` trên máy này;
  đường dẫn đó chỉ là provenance, không được hard-code trong loader/CLI/notebook.
- ZIP Phase 3: **2.040.877 bytes**, SHA-256
  `df03b51e7a9572d8ac055f40e6343a3fc827efd286a2e7cb2c862a2776d9cd0a`.
  Kiểm trước giải nén; verifier Phase 3 đạt **103 file**, context-v2.
- ZIP Phase 2: **253.203.876 bytes**, SHA-256
  `902f97cc84727a98cd36b9f3c17797927979e85f87466972d3f4ab5add1171ce`.
  Manifest tại staging byte-identical với manifest trong ZIP đã kiểm receipt.
- Dataset `t08-v1.0-20261010`, cohort `:ranking`, policy
  `cvss-epss-kev-first-v1`, context `phase3-context-v2`, queue `context-v1`.
  EPSS 2026-09-29; KEV released 2026-09-30T16:59:23.0688Z;
  retrieved 2026-10-01T11:29:35.854976+00:00.

Receipt chi tiết: [p4_demo_input_receipt.json](p4_demo_input_receipt.json).

## Lệnh và bằng chứng

Lệnh dùng `.venv/Scripts/python.exe -X utf8` từ root repo:

| Lệnh/kiểm tra | Kết quả thực chạy |
|---|---|
| `-m src.collect.verify_phase1` | PHASE1 RELEASE OK; [log](p4_phase1_verification.log) |
| `scripts/package_phase3_release.py --verify data/processed/p3_received_20261021` (hàm verifier cũng được loader gọi) | 103 file, pass |
| `-m src.demo.cli --json summary` | 396 CVE/3 KEV, 15 mapping/10 Env, 8 patch/7 review |
| CLI `cve`, `predict`, lỗi input | Smoke/commands ghi trong [log CLI](p4_demo_cli_checks.json) |
| `-m unittest tests.test_demo_data tests.test_baseline tests.test_rankings tests.test_ranking_metrics tests.test_context_priority tests.test_prediction_rank_impact -v` | **85 tests OK**, không skip; gồm 26 tests demo và smoke thật |
| `scripts/execute_demo_notebook.py` | 7/7 cell, 7 PNG có manifest, live TF-IDF thành công |
| Runner `--saved-only` | 7/7 cell, 7 PNG, mode saved |
| Runner `--no-ai` | 7/7 cell, 7 PNG, AI unavailable; tổng quan/bối cảnh còn đủ |
| `scripts/receive_demo_inputs.py --archive D:/Downloads/phase3_handoff_20261021.zip --destination data/processed/p4_receive_smoke_20261022` | nhận gói thật, 103 file pass; loader dùng staging khác vẫn trả đủ 396/15/10/8/7 |

[Log tests](p4_demo_tests.log), [exit code/lệnh](p4_demo_test_result.json),
[live execution](p4_demo_execution.json), [saved execution](p4_demo_saved_execution.json),
[no-AI execution](p4_demo_no_ai_execution.json). Thời gian load/cell/tổng chính xác
ở các JSON; phụ thuộc cache và tải máy, không coi là benchmark hiệu năng.
Sau kiểm rank nguyên dương, chạy lại riêng **26 tests demo, OK** trong 12,401 giây:
[log cuối](p4_demo_tests_final.log), [exit code cuối](p4_demo_test_final_result.json).
Lần kiểm ba mode song song ghi load khoảng 0,57–2,02 giây; saved chạy 2,83 giây,
no-AI 1,04 giây. Thời gian live cuối lấy từ `p4_demo_execution.json`.

Notebook đã lưu output thật tại [03_demo.ipynb](../notebooks/03_demo.ipynb), khoảng
1,3 MB. Đã kiểm output không có cell error; mở xem PNG top-50 trang 26–50 thật,
đủ ba chính sách và ngày nguồn. Bảng HTML giữ đầy đủ nội dung source/reason/action.

## Expected/actual các trường hợp lỗi

| Trường hợp | Expected | Actual |
|---|---|---|
| CSV `False` | false, không truthy string | pass, fixture + CVE thật |
| Score 0 và null | 0 còn nguyên; null N/A + lý do | pass |
| API-02 không có Environmental | còn mapping/review, score/rank N/A | pass |
| Client MOB-01/MOB-02 | Environmental có thể 9.8, review, rank null | pass, giữ cả hai client |
| Hash Phase 1/3 sai | dừng dữ liệu liên quan | pass, fixture thay bytes |
| Dataset/context sai dù reseal fixture | từ chối, không trộn v1/v2 | pass |
| Trùng CVE/cặp mapping/queue/prediction | từ chối join nhân dòng hoặc khóa AI | pass |
| Boolean khác true/false; rank 1.5; EPSS 2 | lỗi kiểu/miền | pass; đã sửa parser để không cast 1.5 thành 1 |
| Thiếu Phase 2 hoặc `--no-ai` | summary/hình/bối cảnh vẫn mở | pass, cả notebook thật |
| Hash Phase 2 sai | khóa AI, summary vẫn mở | pass |
| Thiếu file model live | prediction đã lưu vẫn đọc được | pass, fixture |
| Thiếu sklearn/joblib/Torch | đọc artifact được; live fallback saved khi thiếu dependency | pass, mock import/loader |
| Sai split so với ML release | khóa AI | pass |
| Dummy, train hoặc gộp split | từ chối/không có prediction phù hợp | pass; validation 69, test 108 riêng |
| ID rỗng hoặc ngoài cohort | thông báo ngắn, không traceback | pass |
| Mô tả rỗng | thông báo, không gọi model | pass, fixture |
| Hình ngoài manifest | không hiển thị | pass |
| ZIP hash sai/path traversal | không giải nén | pass |
| Network/train/inference khi load | không được gọi | pass với entrypoint bị mock cấm |
| Input sau đọc/live/notebook | không đổi hash | pass; live/saved kiểm 224 file, no-AI 119 file |

## AI và phạm vi offline đã kiểm

Live **CVE-2023-38709**, validation: TF-IDF
`tfidf-v1-n1-reproduction-20261017`; model SHA-256
`c68d530ff7818f5d469da647246e787517d9d213b59286d9a6f67dd647d05265`.
Base quan sát **7.3**, dự đoán **9.1**; C:L/I:L/A:L khác dự đoán C:N/I:H/A:H.
Tám metric, vector, Base và vector_valid khớp prediction đã lưu sau load model.
Live ghi usage `demo`, kết quả đã lưu ghi `evaluation`; không đổi nhãn gốc.
Không save lại model thật, không đánh giá/chọn model từ test, không train release.
Test baseline có save/load trên fixture nhỏ để kiểm hồi quy, không thay model phát hành.
Model N1 được tạo trên Python 3.14.3; máy nhận dùng 3.13.16 và đã kiểm live/saved
khớp ở ví dụ validation nêu trên, không tuyên bố tái lập toàn bộ quá trình train.

Runner bật socket audit hook, chủ động thử DNS và xác nhận bị chặn trước thực thi.
HF_HUB_OFFLINE/TRANSFORMERS_OFFLINE bật; cả ba mode đã chạy với guard.
**Không tắt card mạng Windows**; đây là bằng chứng không cần socket mạng ở tiến trình
demo, không phải kiểm toàn bộ hệ điều hành đã mất kết nối. Không tải API/snapshot.

## Bàn giao và phần chưa xác nhận

Source: `src/demo/`, runner, receiver và `tests/test_demo_data.py`; không sửa scorer,
ranking/split/model/config của release. Lệnh và dự phòng:
[docs/demo-commands.md](../docs/demo-commands.md).

- Pending N2: `reports/demo-script-security.md` và kiểm lời dẫn/màn hình; file chưa có
  trên workspace khi kiểm. Không tự ký thay N2.
- Pending N1: `docs/runbook.md`/script cuối; chưa có để chạy theo runbook chính thức.
  Đã chạy gói nhận trên workspace Windows hiện tại, không coi đó là kiểm runbook chưa nhận.
- Pending diễn tập người thật khoảng 6 phút, tổng thời gian nói/thao tác và feedback nhóm.
- Chưa commit/push/PR. Không đánh dấu gate Phase 4 của cả nhóm đã hoàn tất.
