# Phase 0 — Hướng dẫn riêng cho Người 2: phạm vi bảo mật và bối cảnh hệ thống

**Người nhận:** Người 2 — Security/Context/Ranking.  
**Branch làm việc:** `docs/p0-security-scope`. **Branch tích hợp:** `develop`.  
**Mục tiêu thời gian:** khoảng 4 giờ làm việc, bố trí trong 1–2 ngày; ghi thời hạn thực tế với nhóm.  
**Môi trường hướng dẫn:** Windows, VS Code, PowerShell. Cập nhật hướng dẫn: 01/10/2026.

Đọc và làm từ trên xuống. Bạn có thể dùng riêng file này để bắt đầu; không cần thư mục `.venv`
hay API key của Người 1. Nhóm không yêu cầu review độc lập trước merge: bạn tự kiểm tra đầu ra,
đưa vào PR để lưu dấu vết, rồi merge khi có quyền. Việc trao đổi quy tắc dữ liệu là phối hợp thiết kế.

## 1. Bạn cần hoàn thành điều gì?

Câu hỏi trung tâm là: **vì sao một CVE có CVSS cao chưa chắc cần ưu tiên vá trước?**
Bạn xác định hệ thống nào thuộc phạm vi Web/mobile, tài sản nào cần quan tâm và bằng chứng nào
đủ để kết luận một CVE phù hợp. AI dự đoán CVSS là phương pháp thực nghiệm của nhóm;
phần bảo mật phải giải thích được quyết định ưu tiên vá.

| Việc bắt buộc trong Phase 0 | Đầu ra cụ thể |
|---|---|
| Có môi trường riêng, lấy được repo và tạo đúng branch | `.venv` trên máy bạn; Git nhận diện đúng branch |
| Định nghĩa phạm vi Web/mobile có căn cứ | Tạo `docs/scope.md` |
| Chọn một tổ chức và hệ thống giả định nhất quán | Tạo `config/assets.yaml`, khoảng 5–6 tài sản |
| Sửa các lập luận bảo mật chưa đúng trong tài liệu cũ | Cập nhật `docs/01-research-questions.md`, `docs/03-environmental-context.md`, `docs/04-patch-playbook.md`; rà `docs/02-scoring-systems.md` |
| Đề xuất quy tắc ranking và những điểm cần N1 tổng hợp | Ghi trong `docs/scope.md` và phần mô tả PR |
| Bàn giao kết quả trên Git | Commit/push branch của bạn, tích hợp vào `develop` |

**API key không phải điều kiện hoàn thành Phase 0.** Chỉ cần khi bạn chủ động chạy thử phần gọi NVD.
Phân loại đủ 30 CVE, ghép EPSS/KEV, tính Environmental Score và vẽ top-50 là công việc Phase 1 trở đi.

N1 đã có pilot 543 CVE công bố trong 01–07/01/2023, gồm 451 ứng viên có nhãn và 92 Rejected.
Gói mẫu nhỏ có 35 dòng. Những số này thuộc snapshot đã tải, không phải thống kê toàn bộ NVD.
Nguồn nội bộ: [metadata mẫu](../data/sample/metadata.json) và [hướng dẫn bàn giao](pilot-handoff.md).

## 2. Lấy repo và tạo branch — khoảng 15 phút

### 2.1. Chuẩn bị quyền truy cập

- Dùng tài khoản GitHub riêng đã được N1 cấp quyền vào repo `thinh247-10/t08-cvss-epss`.
- Mở VS Code → Terminal → New Terminal, chọn PowerShell.
- Nếu máy chưa có Git, cài từ [Git for Windows](https://git-scm.com/download/win), mở lại terminal.

Kiểm tra:

```powershell
git --version
python --version
```

Nếu chưa có Python, cài Python cho Windows từ [trang chính thức](https://www.python.org/downloads/windows/),
mở terminal mới rồi kiểm tra lại. N1 đã chạy phần dữ liệu với Python 3.14.3; nếu bạn dùng bản khác,
ghi rõ phiên bản và xác nhận cài thư viện thành công. Không cần đổi một môi trường đang chạy tốt.

### 2.2. Nếu CHƯA clone repo

Đứng ở thư mục cha nơi muốn đặt dự án, chạy:

```powershell
git clone --branch develop https://github.com/thinh247-10/t08-cvss-epss.git
cd t08-cvss-epss
```

Nếu Git yêu cầu đăng nhập, dùng tài khoản của bạn. Nếu báo không có quyền, gửi N1 tên tài khoản
và thông báo lỗi để được thêm quyền. Không tạo một repo khác thay cho repo nhóm.

### 2.3. Nếu ĐÃ clone repo

Mở đúng thư mục chứa `README.md`, `src`, `config`, rồi kiểm tra:

```powershell
Get-Location
git status --short
git remote -v
```

Nếu có thay đổi cá nhân chưa lưu, xử lý trên branch đang làm trước khi chuyển branch;
không dùng lệnh xóa/reset để làm sạch. Khi thư mục làm việc đã sẵn sàng:

```powershell
git fetch origin
git switch develop
git pull --ff-only origin develop
```

Nếu `develop` chưa có trên máy và Git không tự tạo tracking branch:

```powershell
git switch --track origin/develop
```

### 2.4. Tạo branch công việc

Chạy một lần khi đang ở `develop`:

```powershell
git switch -c docs/p0-security-scope
git branch --show-current
```

Kết quả cuối phải là `docs/p0-security-scope`. Những lần làm tiếp, dùng
`git switch docs/p0-security-scope`, không tạo lại bằng `-c`.

## 3. Tạo `.venv` của riêng bạn — khoảng 15–30 phút

`.venv` là môi trường Python dành cho repo trên máy bạn. Mỗi người tự tạo từ danh sách thư viện;
không chuyển nguyên môi trường giữa các máy. Hướng dẫn này gọi thẳng Python trong `.venv`,
không cần chạy `Activate.ps1`. [Tài liệu Python venv](https://docs.python.org/3/library/venv.html).

Tại thư mục gốc repo:

```powershell
if (-not (Test-Path -LiteralPath ".venv")) {
    python -m venv .venv
}
```

Nếu máy dùng launcher `py` và `python` chưa hoạt động, có thể kiểm tra `py --version` rồi
dùng `py -m venv .venv` ở bước tạo môi trường. Những lệnh sau vẫn dùng đường dẫn dưới đây:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-data.txt
.\.venv\Scripts\python.exe -c "import requests, dotenv, pandas, pyarrow, yaml; print('DATA ENV OK')"
```

Kết quả cần có `DATA ENV OK`. Ghi phiên bản môi trường để bàn giao:

```powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -c "import sys; print(sys.executable)"
.\.venv\Scripts\python.exe -m pip show pandas pyarrow PyYAML
```

Đường dẫn interpreter phải trỏ vào `.venv` của repo. N2 dùng bộ thư viện dữ liệu ở Phase 0;
`requirements.txt` đầy đủ còn gồm các thư viện mô hình mà bạn chưa cần cài.
Trong VS Code, nếu cần chọn interpreter, chọn file `.venv\Scripts\python.exe` của chính repo này.

## 4. API key và `.env` — tùy chọn, không chặn Phase 0

### 4.1. Khi nào bạn cần key?

| Công việc | Cần NVD API key của riêng bạn? |
|---|---|
| Đọc Markdown, CSV mẫu, thống kê nhãn | Không |
| Viết scope, assets và các lập luận bảo mật | Không |
| Mở advisory trên trình duyệt | Không dùng NVD API key |
| Tự chạy script gọi NVD | Có thể cấu hình key riêng theo hướng dẫn này |
| Dùng EPSS/KEV trong script hiện tại | Script không gửi NVD API key tới hai nguồn này |

Đừng chờ nhận key mới bắt đầu viết tài liệu. Người 1 đã chuẩn bị mẫu để bạn làm offline.

### 4.2. Đăng ký key riêng nếu muốn thử API

1. Mở [NVD — Request an API Key](https://nvd.nist.gov/developers/request-an-api-key).
2. Điền email của bạn và các thông tin biểu mẫu yêu cầu; thực hiện bước xác thực trên trang.
3. Kiểm tra email, kể cả thư rác, và làm theo hướng dẫn NVD để nhận/kích hoạt key.
4. Giữ key trên máy mình. N1 không cần nhận key của bạn; bạn cũng không cần key của N1.

Biểu mẫu, cách xác thực và thông báo từ NVD là căn cứ thực hiện; hướng dẫn này không giả định
thời gian cấp key hay thời hạn kích hoạt cụ thể. Nếu trang đang lỗi, tiếp tục phần offline.

### 4.3. Tạo `.env` mà không ghi đè cấu hình đã có

```powershell
if (-not (Test-Path -LiteralPath ".env")) {
    Copy-Item -LiteralPath ".env.example" -Destination ".env"
} else {
    Write-Output ".env da ton tai; mo file de kiem tra tren may cua ban."
}
```

Mở `.env` trong VS Code, thay giá trị mẫu bằng key thật của bạn:

```dotenv
NVD_API_KEY=KEY_RIENG_CUA_BAN
```

`KEY_RIENG_CUA_BAN` chỉ là chỗ giữ chỗ, không phải key sử dụng được. Nếu chưa có key, để
`NVD_API_KEY=` trống thay vì giữ `your-key-here` từ file mẫu.

Kiểm tra key có được đọc mà không in giá trị:

```powershell
.\.venv\Scripts\python.exe -c "from dotenv import load_dotenv; import os; load_dotenv('.env'); k=(os.getenv('NVD_API_KEY') or '').strip(); print('KEY CONFIGURED' if k and k not in ('your-key-here','KEY_RIENG_CUA_BAN') else 'KEY NOT CONFIGURED')"
git check-ignore -v .env .venv/
git ls-files -- .env ".venv/*"
```

`KEY CONFIGURED` chỉ xác nhận đã đọc cấu hình, chưa chứng minh key được NVD chấp nhận.
Lệnh `check-ignore` cần chỉ ra quy tắc bỏ qua; `git ls-files` cần không liệt kê file secret/môi trường.
Nếu `.env` đã bị Git theo dõi, báo N1 để xử lý trước khi push. Chỉ chia sẻ trạng thái kiểm tra,
không gửi key qua chat, ảnh chụp hoặc PR. `.env.example` trên Git giữ giá trị mẫu.

### 4.4. Thử kết nối một CVE — không bắt buộc

Khi cấu hình key đã sẵn sàng:

```powershell
.\.venv\Scripts\python.exe -m src.collect.explore_apis CVE-2021-44228
```

Đọc kết quả NVD, EPSS và KEV. Script có thể tạo `sample_CVE-2021-44228.json` đã được Git bỏ qua.
CVE này dùng kiểm tra kết nối, ngoài khoảng công bố 2023–2024 dự kiến của dataset chính.
Nếu HTTP lỗi, gửi N1 mã lỗi và endpoint, không gửi key hay header. Không cần chạy collector lớn ở Phase 0.

## 5. Đọc đúng tài liệu trước khi viết — khoảng 30 phút

Đọc theo thứ tự:

1. Lời thầy: trọng tâm bảo mật Web và ứng dụng di động; AI là phương pháp giải quyết bài toán.
2. [Phase 0 chung](phases/phase-0-pham-vi-va-thiet-ke.md), tập trung phần Người 2.
3. [Data contract](data_contract.md), phần scope, ranking, tài sản và applicability.
4. `docs/01-research-questions.md` đến `docs/04-patch-playbook.md`: đây là bản cần rà soát,
   không mặc định mọi ví dụ hiện có đều đúng.
5. Đề cương thật nếu nhóm đã có. Nếu chưa nhận, ghi rõ tình trạng; không ghi đã đối chiếu.

Nguồn để tự kiểm tra lập luận:

- Severity và Environmental: [FIRST CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document).
- EPSS ước lượng xác suất khai thác trong 30 ngày tới: [FIRST EPSS](https://www.first.org/epss/).
- Nguồn catalog KEV: [repo chính thức của CISA](https://github.com/cisagov/kev-data).

Kết quả cần giải thích được: severity, khả năng khai thác, bằng chứng trong KEV và mức ảnh hưởng
đến tài sản là các thông tin khác nhau. Giá trị EPSS thiếu không đồng nghĩa 0;
không có tên trong KEV không chứng minh chưa từng bị khai thác.

## 6. Tạo `docs/scope.md` — khoảng 45–60 phút

**Chức năng file:** quy tắc nghiệp vụ để N1 hiện thực bộ lọc và để người khác hiểu lý do nhận/loại CVE.
Bạn viết quy tắc trước; chưa cần điền hết 30 dòng annotation.

File phải có các mục sau:

| Mục cần viết | Nội dung cụ thể |
|---|---|
| Mục tiêu | Web/mobile, câu hỏi CVSS cao chưa chắc vá trước; không khai thác CVE |
| Đối tượng nhận | CMS/plugin, web framework, application server/API; ứng dụng Android/iOS, SDK hoặc thành phần client có căn cứ |
| Đối tượng ngoài phạm vi | Ví dụ kernel/driver/firmware không gắn bài toán ứng dụng; ghi lý do theo quy tắc |
| Trường hợp chưa rõ | Thư viện đa dụng, mô tả ngắn, thiếu advisory; giữ `needs_review` |
| Bằng chứng | Advisory sản phẩm, mô tả, CPE/reference phù hợp; cách lưu URL và lý do |
| Cách gán nhãn | Ý nghĩa `included`/`excluded`/`needs_review`, `domain_tags`, `in_scope`, `scope_evidence` |
| Thiếu dữ liệu/Rejected | Giữ truy vết trong raw/master; Rejected không vào cohort nghiên cứu; thiếu điểm không tự xác định scope |
| Phạm vi ba tập | Phân biệt tập ranking Web/mobile, tập ML có nhãn và ca nghiên cứu theo tài sản |
| Ranking dự kiến | Ba chính sách và quy tắc phá hòa đã có trong data contract |
| Giới hạn và đề xuất cho N1 | Coverage mobile chưa biết, đề cương đã nhận/chưa nhận, các quy tắc cần tổng hợp |

Các quy ước đã có trong nhóm cần giữ nhất quán:

- Một CVE có thể thuộc Web, mobile, cả hai hoặc chưa đủ căn cứ; không bắt buộc vừa Web vừa mobile.
- `AV:N` không phải điều kiện đủ để gán Web. Backend phục vụ điện thoại không thay thế được
  yêu cầu tìm ít nhất một case client/framework/SDK mobile có bằng chứng ở các phase sau.
- `needs_review` đi với `in_scope=false` vì chưa được nhận vào cohort; khác với đã xác nhận `excluded`.
- Ba ranking dùng cùng tập đủ điều kiện: CVSS giảm dần; EPSS giảm dần; KEV-first theo
  KEV → EPSS → CVSS giảm dần. Phá hòa cuối bằng CVE ID tăng dần.
- Dùng CVSS quan sát cho bảng ranking chính. Điểm AI dự đoán phải có nhãn ước lượng riêng.

Hãy viết ít nhất ba tình huống để thử quy tắc: một đối tượng Web rõ, một SDK/client mobile,
một thư viện đa dụng chưa rõ triển khai. Có thể dùng tình huống giả định và ghi rõ là giả định;
nếu nêu CVE thật thì phải có nguồn đã đọc, không điền điểm/EPSS/KEV từ trí nhớ.

## 7. Tạo `config/assets.yaml` — khoảng 30–45 phút

**Chức năng file:** mô tả tài sản của một dịch vụ thương mại điện tử giả định để dùng thống nhất
ở phần phân tích bối cảnh. Đây là thiết kế tài sản, chưa phải kết luận tài sản bị CVE nào tác động.

Chọn khoảng 5–6 tài sản với ID duy nhất, chẳng hạn:

| ID gợi ý | Vai trò |
|---|---|
| `WEB-01` | Website/CMS bán hàng công khai |
| `API-01` | API đăng nhập và tài khoản |
| `API-02` | Backend đơn hàng/thanh toán |
| `ADMIN-01` | Trang quản trị nội bộ |
| `MOB-01` | Ứng dụng Android hoặc SDK trong ứng dụng |
| `MOB-02` | Ứng dụng iOS hoặc thành phần client nếu chọn thêm |

Mỗi tài sản có `asset_id`, `name`, `function`, `domain`, `product`, `version`, `exposure`,
`data_type`, `CR`, `IR`, `AR`, `rationale`, `assumptions`. Product/version chưa chọn thì để null
và ghi điều kiện sẽ xác minh; không bịa một phiên bản bị ảnh hưởng để lấp ô trống.

Mẫu khởi đầu cho **một tài sản**, cần bổ sung các tài sản còn lại và điều chỉnh giả định:

```yaml
inventory_version: "draft-v0.1"
scenario_type: "hypothetical"
organization: "Dich vu thuong mai dien tu gia dinh"
assets:
  - asset_id: "WEB-01"
    name: "Website ban hang"
    function: "Hien thi san pham va tiep nhan don hang"
    domain: "web"
    product: null
    version: null
    exposure: "internet"
    data_type: ["thong tin san pham", "du lieu dat hang"]
    CR: "M"
    IR: "H"
    AR: "H"
    rationale: "Gia dinh tinh dung dan don hang va tinh san sang quan trong voi dich vu"
    assumptions:
      - "Kien truc gia dinh, chua kiem thu he thong that"
      - "San pham/phien ban se chon sau khi doi chieu advisory"
```

CR/IR/AR mô tả yêu cầu bảo mật theo bối cảnh; lựa chọn trong ví dụ là giả định cần giải thích,
không phải kết quả tính điểm. Khi dùng vào scorer, đối chiếu định nghĩa
[Environmental metrics của FIRST](https://www.first.org/cvss/v3.1/specification-document).

## 8. Rà và sửa tài liệu cũ — khoảng 45 phút

| File | Việc cần sửa cụ thể |
|---|---|
| `docs/01-research-questions.md` | Bỏ diễn giải KEV ưu tiên vô điều kiện bất kể tài sản; SSVC là tham khảo; không viết sẵn “chiếm đa số” trước khi có thống kê |
| `docs/02-scoring-systems.md` | Rà định nghĩa CVSS/EPSS/KEV, phân biệt xác suất với percentile; giữ SSVC ngoài đầu ra bắt buộc |
| `docs/03-environmental-context.md` | Sửa các dòng tự đổi mạng nội bộ → MAV:A/L, WAF → MAC:H, backup/mã hóa → giảm tác động; mỗi thay đổi cần điều kiện cụ thể |
| `docs/04-patch-playbook.md` | Applicability trước ưu tiên vá; SLA 24–72 giờ nếu dùng là đề xuất của kịch bản, không áp thành quy tắc phổ quát; thiếu CVSS xác định từ dữ liệu metric, không chỉ tên trạng thái |

Tài liệu sau sửa phải cho phép trường hợp chưa đủ bằng chứng: giữ quyết định chưa rõ và đề xuất
xác minh. Kiểm soát như WAF/backup có thể được mô tả trong bối cảnh mà chưa đủ căn cứ để sửa vector.
Đối chiếu [đặc tả CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document) trước khi giữ một ví dụ điều chỉnh metric.

Các ngưỡng EPSS hoặc SLA do nhóm đề xuất phải có nhãn chính sách giả định. Dùng KEV-first rồi đo
độ bao phủ chính KEV không chứng minh một mô hình dự báo độc lập tốt hơn.
Gửi đề xuất chỉnh README cho N1 trong PR; N1 tổng hợp các file dùng chung như README/data contract/decisions.

## 9. Gói bàn giao mẫu dùng đến đâu trong Phase 0?

Bạn có thể đọc 2–3 dòng mẫu để hiểu dữ liệu và thử quy tắc scope. **Chưa cần phân loại đủ 30 dòng**
để kết thúc Phase 0. Sau khi thiết kế scope đã có, sang Phase 1 mới xử lý annotation theo
[hướng dẫn bàn giao](pilot-handoff.md).

Nếu muốn kiểm tra máy đọc được mẫu, chạy tại gốc repo:

```powershell
.\.venv\Scripts\python.exe -c "import pandas as pd; from src.collect.prepare_handoff import SAMPLE_DTYPES; df=pd.read_csv('data/sample/cves_sample.csv', dtype=SAMPLE_DTYPES, keep_default_na=False, na_values=[''], true_values=['True'], false_values=['False']); print('rows:',len(df)); print(df[['cve_id','vuln_status','scope_status']].head().to_string(index=False))"
```

Mẫu hiện tại có 35 dòng. Nếu chưa có file mẫu trên branch của bạn, kiểm tra đã lấy `develop` mới
hay chưa; thiếu mẫu không ngăn bạn viết quy tắc Phase 0 từ tài liệu và nguồn chính thức.

## 10. Prompt hỗ trợ viết — mỗi lần một việc

### Prompt A — tạo scope

```text
Tôi là Người 2 của T08, đang ở Phase 0, branch docs/p0-security-scope.
Đọc docs/data_contract.md và docs/phases/phase-0-pham-vi-va-thiet-ke.md.
Chỉ tạo docs/scope.md: định nghĩa nhận/loại/chưa rõ cho Web/mobile, bằng chứng,
domain_tags, in_scope và scope_status. AV:N không đồng nghĩa Web.
Phân biệt tập ranking, ML và case theo tài sản. Không tự điền 30 annotation,
không bịa CVE/điểm/nguồn, không viết collector. Đánh dấu giả định và thông tin còn thiếu.
```

### Prompt B — cấu hình tài sản

```text
Dựa trên docs/scope.md và data contract, tạo config/assets.yaml cho hệ thống
thương mại điện tử giả định với 5–6 tài sản gồm Web/API và mobile client/SDK.
Dùng asset_id duy nhất; ghi chức năng, exposure, dữ liệu, CR/IR/AR và lý do.
Product/version chưa có căn cứ để null và ghi giả định. Chưa gán CVE ảnh hưởng,
chưa tính điểm, không tự thay MAV/MAC từ nhãn internet/intranet/WAF.
```

### Prompt C — sửa lập luận

```text
Rà docs/01-research-questions.md đến docs/04-patch-playbook.md theo scope đã chốt.
Sửa applicability trước ưu tiên vá, bỏ KEV override vô điều kiện, giữ SSVC tham khảo.
Loại suy luận tự động intranet->MAV:A/L hoặc WAF->MAC:H.
Dẫn nguồn FIRST/CISA cho các định nghĩa; không tự sinh kết quả thực nghiệm.
Chỉ sửa bốn tài liệu này; ghi đề xuất cho README/decisions để N1 tổng hợp.
```

Bạn cần đọc lại và tự giải thích được các quyết định; đoạn AI viết chưa được đối chiếu nguồn
không tự trở thành bằng chứng bảo mật.

## 11. Tự kiểm tra rồi commit/push

Kiểm YAML và ID tài sản sau khi đã tạo file:

```powershell
.\.venv\Scripts\python.exe -c "from pathlib import Path; import yaml; c=yaml.safe_load(Path('config/assets.yaml').read_text(encoding='utf-8')); a=c['assets']; ids=[x['asset_id'] for x in a]; assert 5 <= len(a) <= 6; assert len(ids)==len(set(ids)); print('ASSETS YAML OK:',len(a))"
git diff --check
git diff --stat
git status --short
```

`ASSETS YAML OK` chỉ kiểm cú pháp/số lượng/ID; bạn vẫn phải kiểm tính hợp lý của nội dung.
Mở các Markdown bằng Preview trong VS Code để xem bảng và link.

Stage đúng file của N2:

```powershell
git add docs/scope.md config/assets.yaml
git add docs/01-research-questions.md docs/02-scoring-systems.md docs/03-environmental-context.md docs/04-patch-playbook.md
git diff --cached --stat
git diff --cached --name-only
git commit -m "docs(p0): define security scope and asset context"
git push -u origin docs/p0-security-scope
```

Nếu Git yêu cầu danh tính khi commit, cấu hình **trong repo** bằng tên/email thật của bạn rồi chạy lại commit:

```powershell
git config user.name "TEN_CUA_BAN"
git config user.email "EMAIL_CUA_BAN"
```

Trên GitHub tạo PR:

- **Base:** `develop`.
- **Compare:** `docs/p0-security-scope`.
- **Tiêu đề:** `[Phase 0][N2] Phạm vi Web/mobile và bối cảnh tài sản`.
- **Mô tả:** liệt kê scope, tài sản, tài liệu đã sửa, kiểm tra đã chạy và các quyết định còn cần N1 tổng hợp.

Tự kiểm tab Files changed. Theo quy ước nhóm, không phải chờ một lượt review độc lập.
Có quyền merge thì chọn Squash and merge → Confirm; nếu không có quyền, gửi link PR cho N1 tích hợp.
Sau khi PR hiển thị Merged, cập nhật máy:

```powershell
git switch develop
git pull --ff-only origin develop
```

Phase 1 sau đó dùng branch `feat/p1-scope-assets` tạo từ `develop` mới; chưa cần tạo khi vẫn đang làm Phase 0.

## 12. Checklist kết thúc Phase 0 của N2

- [ ] Có `.venv` riêng và chạy được `DATA ENV OK`.
- [ ] API key: ghi rõ không cần/chưa đăng ký/đã cấu hình riêng; không chia sẻ key. Thiếu key không chặn hoàn thành.
- [ ] Giải thích được CVSS cao không tự quyết định thứ tự vá.
- [ ] `docs/scope.md` có điều kiện nhận/loại/chưa rõ và yêu cầu evidence cho Web lẫn mobile.
- [ ] Đã phân biệt rõ mobile client/SDK với backend phục vụ mobile.
- [ ] `config/assets.yaml` có 5–6 tài sản, ID duy nhất, giả định và lý do CR/IR/AR.
- [ ] Các lập luận sai ở tài liệu cũ đã được sửa; số liệu chưa kiểm chứng được loại hoặc ghi giả định.
- [ ] Ghi nhận đã có/chưa có đề cương thật; liệt kê đề xuất N1 cần đưa vào decisions/data contract.
- [ ] Các file của bạn đã commit/push; PR đã tích hợp hoặc đã gửi N1 nếu thiếu quyền merge.

Khi đạt các mục nội dung, phần việc chuyên môn Phase 0 của bạn hoàn tất. N1 tổng hợp thiết kế chung.
Không cần đợi train AI, download đủ dataset hoặc phân loại xong 30 CVE để báo xong Phase 0.

Mẫu thông báo bàn giao để tự gửi cho nhóm:

```text
N2 đã hoàn thành Phase 0.
Branch/PR: <link>
Đầu ra: docs/scope.md, config/assets.yaml, các tài liệu bảo mật đã sửa.
Môi trường: <Python và kết quả kiểm tra>.
Đề cương: <đã nhận/chưa nhận>.
Các giả định/quyết định N1 cần tổng hợp: <nội dung cụ thể>.
Phase 1 tiếp theo: phân loại mẫu scope và chuẩn bị applicability theo tài sản.
```
