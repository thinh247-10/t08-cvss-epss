# N3 — đối chiếu Environmental độc lập

Ngày đọc nguồn: 2026-10-21. Cặp `CVE-2023-41387 / MOB-02`; dataset
`t08-v1.0-20261010`, context `phase3-context-v1`. Input r1 đã kiểm hash:
`environmental_scores.csv`, SHA-256 `1d40e31ed9341b90a8af93ca2dc5a3c9788ad0bd76cc3890fb6d2c17d8b2cf33`.

Expected lấy bằng thay số độc lập theo [FIRST CVSS 3.1 §7.3–7.4](https://www.first.org/cvss/v3.1/specification-document#7-3-Environmental-Metrics-Equations),
không dùng scorer hoặc expected do N2 xuất. Script dùng Decimal chính xác cho cặp cố
định này; không phải triển khai Environmental tổng quát.

Base vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` (Base 9.1).
Environmental nối thêm:
`E:X/RL:X/RC:X/CR:H/IR:H/AR:M/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X`.
Modified X kế thừa Base, Temporal X có hệ số 1; CR/IR=1.5, AR=1.

| Bước thay số | Kết quả độc lập |
|---|---:|
| MISS trước cap = 1 − (1 − 1.5×0)(1 − 1.5×0.56)(1 − 1×0.56) | 0.9296 |
| MISS = min(0.9296, 0.915) | 0.915 |
| Modified Impact, Scope unchanged = 6.42×MISS | 5.87430 |
| Modified Exploitability = 8.22×0.85×0.77×0.85×0.85 | 3.8870427750 |
| Tổng, giới hạn 10 | 9.7613427750 |
| Roundup trong, rồi Temporal ×1×1×1 và Roundup ngoài | **9.8** |
| N2 Environmental / chênh lệch | **9.8 / 0.0** |

```powershell
.\.venv\Scripts\python.exe scripts/check_phase3_environmental_n3.py
.\.venv\Scripts\python.exe -m unittest tests.test_p3_environmental_crosscheck -v
```

Kết quả máy đọc được: [environmental_crosscheck_n3.json](../data/processed/p3_n3/environmental_crosscheck_n3.json).
Không đổi C:N thành C:H, MAV hoặc policy queue; client vẫn review_required/N/A.
Đối chiếu này xác nhận số cho giả định đã nêu, không xác minh applicability thực tế,
không chứng nhận toàn bộ nhánh Scope Changed hoặc mọi vector của scorer N2.
