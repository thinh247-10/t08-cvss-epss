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

## EPSS (Exploit Prediction Scoring System — FIRST.org)

- **Do cai gi:** xac suat (0-1) lo hong bi khai thac **trong 30 ngay toi**
- **Du lieu dau vao:** tin hieu quan sat thuc te (du lieu quet mang, thao luan exploit,
  ma PoC cong khai...)
- **Cap nhat:** hang ngay
- **Phien ban:** ghi ro dang dung phien ban nao tai thoi diem lay du lieu

**Luu y quan trong khi so sanh:** EPSS thay doi theo ngay. Phai chon ro 1 moc
(vi du: EPSS tai thoi diem 30 ngay sau khi CVE publish) va neu ro gia dinh —
neu dung EPSS hom nay de xep hang CVE cu, mo hinh "biet truoc tuong lai".

## CISA KEV (Known Exploited Vulnerabilities)

- **La gi:** danh sach CVE CISA **xac nhan** da bi khai thac thuc te
- **Dung lam gi:** proxy cho ground truth ve khai thac
- **Han che:** chac chan undercount — chi gom nhung gi CISA xac nhan duoc.
  Phai neu ro trong phan ban luan.

## SSVC (Stakeholder-Specific Vulnerability Categorization)

- **Khac biet:** cho ra **hanh dong** (Track / Track* / Attend / Act), khong phai con so
- **Dau vao:** Exploitation, Automatable, Technical Impact, Mission Prevalence...
- **Vi sao dua vao do an:** thuan bao mat, khong co ML, va gan voi quyet dinh van hanh
  hon la mot con so
- **Nguon du lieu:** NVD API tra ve truong `ssvcV203` cho mot so CVE

## Bang so sanh

| | CVSS | EPSS | KEV | SSVC |
|---|---|---|---|---|
| Tra loi | Nguy hiem den dau? | Co bi khai thac khong? | Da bi khai thac chua? | Nen lam gi? |
| Dang ket qua | Diem 0-10 | Xac suat 0-1 | Co/Khong | Hanh dong |
| Biet ve he thong cua ban? | Chi qua Environmental | Khong | Khong | Co (Mission Prevalence) |
| Cap nhat | Hiem khi | Hang ngay | Khi CISA xac nhan | Theo danh gia |
