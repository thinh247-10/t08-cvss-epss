# Phase 3 N2 — kiểm chứng Environmental và mapping (mục 7)

**Fixture scorer vẫn áp dụng; bảng mapping bên dưới mô tả r1/context-v1.**
Mapping hiện hành context-v2 có 15 cặp/10 scored; xem báo cáo independent completion.
Không dùng số cặp cũ để chú thích hình của output v2.

Ngày 2026-10-19, branch `feat/p3-ranking-context`. Không thay scorer Base, inventory
`phase1-v1`, release v1, nhãn nguồn hay cohort 396 CVE. Không suy MAV từ internal,
MAC từ WAF hoặc Modified C/I/A từ backup. CR/IR/AR từ lý do tài sản giả định.

## Nguồn expected độc lập

- FIRST đặc tả v3.1 §7.3/7.4, Appendix A:
  https://www.first.org/cvss/v3.1/specification-document.
- Calculator https://www.first.org/cvss/calculator/3.1, mã chính thức
  https://www.first.org/_/cvsscalc31.js?20240610063942 (đọc trước khi đối chiếu).
- `scripts/check_environmental_first.py` dùng calculator JS chính thức trong bộ nhớ,
  không dùng hàm Python dưới test để tạo expected. Oracle JSON lưu URL/hash nguồn,
  24 ca S/PR/zero/cap/MS và 256 fixture random seed=42; không trộn fixture vào cohort.
- N3 vẫn cần kiểm độc lập một case; kiểm của N2 không thay cho xác nhận N3.

Base fixture B=`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`.

| B + metric bổ sung | Expected FIRST | Actual |
|---|---:|---:|
| Không thêm (tất cả X) | 7.1 | 7.1 |
| MS:C | 8.5 | 8.5 |
| MS:C/MPR:N | 9.3 | 9.3 |
| MS:C/MPR:L | 8.5 | 8.5 |
| MS:C/MPR:H | 7.6 | 7.6 |
| CR:H/IR:H/AR:H | 8.6 | 8.6 |
| CR:L/IR:L/AR:L | 5.2 | 5.2 |
| MC:N/MI:N/MA:N | 0.0 | 0.0 |
| E:U/RL:O/RC:U | 5.7 | 5.7 |
| MAV:A/MAC:H/MPR:H/MUI:R/MS:C/MC:H/MI:H/MA:H/CR:H/IR:H/AR:H/E:P/RL:T/RC:R | 6.5 | 6.5 |

## Ngoại lệ cần N1 đính chính trong bản giao việc

Yêu cầu “tất cả X luôn bằng Base” không đúng cho mọi vector Scope Changed v3.1.
FIRST có ModifiedImpact khác BaseImpact: hệ số 0.9731, lũy thừa 13, cap MISS 0.915.
Calculator xác nhận `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H`:
Base=9.9, Environmental (tất cả X)=10.0. Giữ đúng FIRST, có regression test ngoại lệ,
không shortcut thành Base để ép pass yêu cầu không chính xác. Scope U all-X và các
fixture C không rơi vào ngoại lệ vẫn đối chiếu bình đẳng với Base.
Cap H/H/H, Scope U và CR/IR/AR:H trả 9.8 (không tự nâng thành 10).

## API và lệnh

`environmental_score(base_vector, metrics)` trả `(full_vector, score)`;
`score_environmental_vector(vector)` parse vector đầy đủ, không âm thầm fallback 0.
Full vector ghi đủ 8 Base + 14 Temporal/Environmental, X rõ ràng; PR theo Modified Scope.

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_cvss_environmental tests.test_context_priority tests.test_ranking_metrics tests.test_rankings tests.test_cvss tests.test_phase1_release tests.test_asset_inventory -q
.\.venv\Scripts\python.exe -m scripts.check_environmental_first --output data/processed/p3_n2/environmental_first_check.json
.\.venv\Scripts\python.exe -m src.analysis.context_priority --master data/processed/phase1_v1_20261010/cves.parquet --mapping config/phase3_mapping.yaml --inventory config/assets.yaml --config config/phase3.yaml --output-dir data/processed/p3_n2
```

## Mapping có điều kiện, không đủ target 15

`config/phase3_mapping.yaml` giữ 5 cặp gốc có nguồn + một candidate API-02 needs_review.
Output có 6 cặp, 5 affected có điều kiện, không có unaffected được khẳng định thực tế.
Không coi candidate unknown là bằng chứng PgHero được cài ở API-02.
Chưa đạt target 15; báo số thật cho N1 thay vì nhân CVE×asset/bịa version.
Evidence URL/ngày đọc/dải affected/conditions/limitations/reviewer ghi từng dòng.
Reviewer ghi Codex-assisted review, không gán xác nhận người dùng/N3 chưa có.

| Cặp | Nguồn đối chiếu | Base → Environmental |
|---|---|---:|
| 2018-25067 / WEB-01 | JoomGallery release 3.3.4 + commit dc414ee, range từ v1 | 7.2 → 7.2 |
| 2022-46177 / API-01 | GHSA-5www-jxvf-vrc3 stable <=2.8.13 | 8.1 → 8.8 |
| 2023-22626 / ADMIN-01 | PgHero issue 439, 0.1.1–3.0.1 | 7.5 → 9.3 |
| 2023-30470 / MOB-01 | Meta CNA, fix commit; untrusted JS + optimization | 9.8 → 9.8 |
| 2023-41387 / MOB-02 | CNA description + project iOS 1.11.2 security changelog | 9.1 → 9.8 |
| 2023-22626 / API-02 | Chưa biết product/version, candidate kiểm tra | Không tính |

Nguồn đã đọc 2026-10-19: các URL từng dòng trong mapping. Meta web chặn truy cập,
đã dùng https://cveawg.mitre.org/api/cve/CVE-2023-30470 và commit chính thức;
Flutter CNA đọc https://cveawg.mitre.org/api/cve/CVE-2023-41387.
Vendor Base khác v1 ở Discourse được ghi hạn chế, không thay nhãn để tính.
5 Environmental rows đều source=observed; 1 exclusion có lý do. Tính score cho mobile
không cho phép tự xếp numeric priority client.
