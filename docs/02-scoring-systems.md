# Cac thang do uu tien va — tong quan

## CVSS (Common Vulnerability Scoring System)

- **Do cai gi:** muc do nghiem trong **neu** lo hong bi khai thac
- **Khong do:** kha nang bi khai thac
- **Nhom metric:** Base (noi tai) / Temporal (theo thoi gian) / Environmental (theo to chuc)
- **Van de da duoc chi ra trong tai lieu:** phan lon to chuc chi dung Base Score;
  cach cham diem khong nhat quan giua cac nguoi danh gia (Wunder et al. 2024);
  thang diem 0-10 tao cam giac chinh xac gia (Spring et al. 2021, Howland 2023)

**Phien ban:** do an dung **v3.1** lam nhan chinh (khoi luong du lieu lich su lon nhat).
v4.0 con it du lieu — co the nhac trong phan ban luan.

Nguon dinh nghia: [FIRST CVSS v3.1](https://www.first.org/cvss/v3.1/specification-document).

## EPSS (Exploit Prediction Scoring System — FIRST.org)

- **Do cai gi:** xac suat (0-1) lo hong bi khai thac **trong 30 ngay toi**
- **Du lieu dau vao:** tin hieu quan sat thuc te (du lieu quet mang, thao luan exploit,
  ma PoC cong khai...)
- **Cap nhat:** hang ngay
- **Phien ban:** ghi ro dang dung phien ban nao tai thoi diem lay du lieu
- **Probability (`epss`):** xac suat uoc luong mot CVE bi khai thac trong 30 ngay toi
- **Percentile (`epss_percentile`):** vi tri tuong doi cua diem EPSS so voi cac CVE
  khac trong cung lan cham; khong phai mot xac suat thu hai

**Luu y quan trong khi so sanh:** EPSS thay doi theo ngay. Bang ranking chinh
cua do an dung mot snapshot chung tai ngay T cho toan bo cohort. `epss_date`
phai duoc luu cung dataset de co the tai lap ket qua.

Neu dung snapshot EPSS hien tai cho cac CVE cu, ket qua chi duoc dien giai la
phan tich mo ta tai thoi diem T; khong duoc goi la du bao hoi cu tai thoi diem
CVE moi cong bo.

Nguon dinh nghia: [FIRST EPSS](https://www.first.org/epss/).

## CISA KEV (Known Exploited Vulnerabilities)

- **La gi:** danh sach CVE CISA **xac nhan** da bi khai thac thuc te
- **Dung lam gi:** bang chung tham chieu ve khai thac da duoc CISA ghi nhan;
  do an dung KEV de doi chieu cac ranking.
- **Han che:** KEV khong phai ground truth day du. Khong co trong KEV khong
  chung minh CVE chua tung bi khai thac.

Nguon catalog: [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

## SSVC (Stakeholder-Specific Vulnerability Categorization) — tham khảo

SSVC không nằm trong đầu ra bắt buộc của đồ án. Phần này chỉ dùng để tham khảo
cách một framework có thể chuyển thông tin lỗ hổng thành hành động vận hành.
- **Khac biet:** cho ra **hanh dong** (Track / Track* / Attend / Act), khong phai con so
- **Dau vao:** Exploitation, Automatable, Technical Impact, Mission Prevalence...
- **Vi sao dua vao do an:** thuan bao mat, khong co ML, va gan voi quyet dinh van hanh
  hon la mot con so
- **Nguon du lieu:** NVD API tra ve truong `ssvcV203` cho mot so CVE

## Bang so sanh

| | CVSS | EPSS | KEV | SSVC ( Tham khảo ) |
|---|---|---|---|---|
| Tra loi | Nguy hiem den dau? | Co bi khai thac khong? | Da bi khai thac chua? | Nen lam gi? |
| Dang ket qua | Diem 0-10 | Xac suat 0-1 | Co/Khong | Hanh dong |
| Biet ve he thong cua ban? | Chi qua Environmental | Khong | Khong | Co (Mission Prevalence) |
| Cap nhat | Hiem khi | Hang ngay | Khi CISA xac nhan | Theo danh gia |
