# N3 — Audit ML toàn khoảng (Phase 1, bước 3)

Ngày chạy thực tế (Asia/Saigon): 2026-10-07T21:29:04.820780+07:00.

Dataset version: `pilot-v0.1-nvd-20261002T171532_735222Z-joined-20261005T164912_356960Z`; schema version: `0.1`.

Đọc 71,653 dòng; 71,653 ID duy nhất. Ứng viên ML theo điều kiện nhãn: **67,912**; đã đối chiếu vector/version: **67,912**.

Báo cáo này dùng bảng ghép toàn khoảng 2023–2024; mẫu cũ 35 dòng và 451 ứng viên pilot được báo cáo riêng trong pilot_ml_audit.md.

## 1. Provenance, checksum và môi trường

| File thực sự đọc/kiểm | SHA-256 |
| --- | --- |
| data\processed\joined_pilot_20261005T164912_356960Z\cves.parquet | 5adda10bf13407c582e3e33b716e55378757cea549a7fadaa85067dcc59ffc01 |
| data\processed\joined_pilot_20261005T164912_356960Z\metadata.json | 23856ea5eaf71336a134083f59e00b4fbc4c77b350811251aa9e8a3272cbf1b6 |
| config\project.yaml | dc8ba19b3de6b7b7cad5bd4a04dee7377f8b879a59735507db8d566080d4e3d4 |
| docs\handoffs\phase-1-joined-20261005.json | 841ca2dd3c892fca65b9003ee748c44abe008120579f1b82cb9079f2c2add8be |
| data\processed\joined_pilot_20261005T164912_356960Z\cves.csv | 5b69b6b2447a8b1ace12ca615ec75cab2f2995a124672440f233424f598be3ca |
| data\processed\joined_pilot_20261005T164912_356960Z\data_quality.md | 859356f3b484b85e2bf42b4eccb4241009550d1d31c1fe7db106f293361b6996 |
| C:\Users\ASUS\Downloads\t08-p1-joined-20261005T164912_356960Z.zip | 46c9b87228b42af7fd8da3d96c93da1fce522eea92cd40c10768756a67f0bf26 |

Metadata được xác minh qua manifest độc lập: True. Đã đối chiếu cả 4 entry của gói về hash và dung lượng. Hash nguồn raw trong metadata chưa kiểm lại vì raw không có trong gói.

| Thành phần | Phiên bản |
| --- | --- |
| Python | 3.13.16 |
| pandas | 3.0.6 |
| pyarrow | 25.0.1 |
| PyYAML | 6.0.3 |
| Platform | Windows-11-10.0.26200-SP0 |

Config SHA-256 khớp bản build. Scope_reviewed=False; training_ready=False; split chưa khóa. Input NLP chỉ description; tám metric là target. EPSS/KEV không làm feature.

## 2. Schema và dtype

| Cột | Kiểu thực tế (pandas) | Contract | Khớp vật lý | Ghi chú |
| --- | --- | --- | --- | --- |
| cve_id | string | string / enum | True |  |
| published | datetime64[us, UTC] | UTC timestamp | True |  |
| last_modified | datetime64[us, UTC] | UTC timestamp | True |  |
| vuln_status | string | string / enum | True |  |
| description | string | string / enum | True |  |
| cvss_version | string | string / enum | True |  |
| cvss_vector | string | string / enum | True |  |
| cvss_base_score | Float64 | nullable float | True |  |
| cvss_source | string | string / enum | True |  |
| cvss_type | string | string / enum | True |  |
| AV | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| AC | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| PR | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| UI | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| S | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| C | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| I | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| A | string | categorical nullable | False | Stored as text; class membership is checked separately. No source cast. |
| has_cvss31_label | boolean | boolean (nullable is_kev) | True |  |
| epss | Float64 | nullable float | True |  |
| epss_percentile | Float64 | nullable float | True |  |
| epss_date | string | date nullable | False | Calendar values checked separately; ISO text serialization is recorded without a source cast. |
| is_kev | boolean | boolean (nullable is_kev) | True |  |
| kev_date_added | string | date nullable | False | Calendar values checked separately; ISO text serialization is recorded without a source cast. |
| kev_known_ransomware | string | string / enum | True |  |
| domain_tags | object | list[string] | False | Pandas object values checked separately; typed string elements require Arrow schema verification. |
| in_scope | boolean | boolean (nullable is_kev) | True |  |
| scope_reason | str | string / enum | True |  |
| scope_evidence | object | list[string] | False | Pandas object values checked separately; typed string elements require Arrow schema verification. |
| scope_status | str | string / enum | True |  |
| split | string | string / enum | True |  |
| dataset_version | str | string / enum | True |  |
| retrieved_at | datetime64[us, UTC] | UTC timestamp | True |  |
| epss_status | string | string / enum | True |  |

Cột bổ sung ngoài contract mẫu: epss_status. epss_status là trường provenance của builder.

Parquet lưu tám metric dưới dạng string thay cho categorical; epss_date/kev_date_added là ISO date string thay cho date vật lý. Timestamps UTC và nullable float/boolean đọc đúng. Các khác biệt dtype được giữ nguyên và báo cho N1; giá trị được kiểm trong bộ nhớ.

Schema Arrow thực tế (list rỗng có thể là list<null>, chưa chứng minh list<string> cho file này):

```text
cve_id: large_string
published: timestamp[us, tz=UTC]
last_modified: timestamp[us, tz=UTC]
vuln_status: large_string
description: large_string
cvss_version: large_string
cvss_vector: large_string
cvss_base_score: double
cvss_source: large_string
cvss_type: large_string
AV: large_string
AC: large_string
PR: large_string
UI: large_string
S: large_string
C: large_string
I: large_string
A: large_string
has_cvss31_label: bool
epss: double
epss_percentile: double
epss_date: large_string
is_kev: bool
kev_date_added: large_string
kev_known_ransomware: large_string
domain_tags: list<element: null>
  child 0, element: null
in_scope: bool
scope_reason: large_string
scope_evidence: list<element: null>
  child 0, element: null
scope_status: large_string
split: large_string
dataset_version: large_string
retrieved_at: timestamp[us, tz=UTC]
epss_status: large_string
-- schema metadata --
pandas: '{"index_columns": [], "column_indexes": [], "columns": [{"name":' + 4152
```

## 3. Missing, nhãn, loại mẫu và đối chiếu metadata

| Chỉ số | Thực tế |
| --- | --- |
| total_records | 71653 |
| unique_cve_count | 71653 |
| ml_candidates | 67912 |
| strict_valid_candidates | 67912 |
| missing_description | 0 |
| rejected_records | 2884 |
| assigned_source_split | 0 |
| candidate_without_epss | 0 |
| non_rejected_missing_labels | 857 |
| valid_vectors | 67912 |
| label_vector_mismatches | 0 |
| in_kev | 325 |
| epss_present | 68769 |

| Trạng thái NVD | Số dòng |
| --- | --- |
| Modified | 42665 |
| Analyzed | 18329 |
| Deferred | 7769 |
| Rejected | 2884 |
| Undergoing Analysis | 6 |

| Cột | Số missing |
| --- | --- |
| cve_id | 0 |
| published | 0 |
| last_modified | 0 |
| vuln_status | 0 |
| description | 0 |
| cvss_version | 3741 |
| cvss_vector | 3741 |
| cvss_base_score | 3741 |
| cvss_source | 3741 |
| cvss_type | 3741 |
| AV | 3741 |
| AC | 3741 |
| PR | 3741 |
| UI | 3741 |
| S | 3741 |
| C | 3741 |
| I | 3741 |
| A | 3741 |
| has_cvss31_label | 0 |
| epss | 2884 |
| epss_percentile | 2884 |
| epss_date | 2884 |
| is_kev | 0 |
| kev_date_added | 71328 |
| kev_known_ransomware | 71328 |
| domain_tags | 0 |
| in_scope | 0 |
| scope_reason | 0 |
| scope_evidence | 0 |
| scope_status | 0 |
| split | 71653 |
| dataset_version | 0 |
| retrieved_at | 0 |
| epss_status | 0 |

Điều kiện ML: status có giá trị được hỗ trợ, không Rejected; description có nội dung; đủ tám nhãn hợp lệ. Đếm thêm strict_valid_candidates sau kiểm vector Base 3.1/version/nhãn khớp. Missing EPSS không được dùng làm điều kiện loại.

| Lý do loại chính (không đếm trùng) | Số dòng |
| --- | --- |
| eligible | 67912 |
| rejected | 2884 |
| missing_or_invalid_labels | 857 |

| Lý do kiểm (có thể giao nhau) | Số dòng |
| --- | --- |
| rejected | 2884 |
| missing_description | 0 |
| missing_or_invalid_labels | 3741 |
| vector_invalid_or_mismatch | 0 |
| unknown_status | 0 |

| Chỉ số đối chiếu | Metadata | Audit | Khớp |
| --- | --- | --- | --- |
| total_records | 71653 | 71653 | True |
| unique_cve_count | 71653 | 71653 | True |
| rejected_records | 2884 | 2884 | True |
| description_and_label_candidates_before_scope | 67912 | 67912 | True |
| available_epss | 68769 | 68769 | True |
| in_kev | 325 | 325 | True |
| assigned_split | 0 | 0 | True |

Phát hiện lỗi ngoài các missing/Rejected đã giữ: **0**. Mỗi phát hiện có CVE ID, cột, mã và mức độ trong file findings. Không sửa nhãn để khớp vector.

| CVE ID ví dụ | Cột | Phát hiện |
| --- | --- | --- |
| CVE-2017-20190 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2019-17082 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2019-2483 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-12491 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-12492 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-26066 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-26306 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-26307 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-26309 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-26310 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-3420 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |
| CVE-2020-3532 | AV\|AC\|PR\|UI\|S\|C\|I\|A | At least one Base label absent; no relabelling |

Nếu bảng nhãn/version/hash không khớp, cần N1 sửa/build lại và N3 kiểm lại version mới; không dùng lỗi audit để âm thầm loại mẫu test.

## 4. Split dự kiến và hỗ trợ lớp

| Split | Khoảng [start,end_exclusive) UTC | Master | ML | Web/mobile |
| --- | --- | --- | --- | --- |
| train | [2023-01-01, 2024-01-01) | 30949 | 28815 | pending/N/A |
| validation | [2024-01-01, 2024-07-01) | 20916 | 19921 | pending/N/A |
| test | [2024-07-01, 2025-01-01) | 19788 | 19176 | pending/N/A |

Ứng viên không có proposed_split: 0; split nguồn đã gán: 0. proposed_split chỉ trong bộ nhớ.

| Metric | Lớp | Toàn bộ ML | train | validation | test |
| --- | --- | --- | --- | --- | --- |
| AV | N | 49131 | 21730 | 13867 | 13534 |
| AV | A | 1770 | 491 | 705 | 574 |
| AV | L | 16484 | 6378 | 5212 | 4894 |
| AV | P | 527 | 216 | 137 | 174 |
| AC | L | 64673 | 27790 | 18762 | 18121 |
| AC | H | 3239 | 1025 | 1159 | 1055 |
| PR | N | 34962 | 16123 | 9791 | 9048 |
| PR | L | 26668 | 9746 | 8495 | 8427 |
| PR | H | 6282 | 2946 | 1635 | 1701 |
| UI | N | 45509 | 18691 | 13596 | 13222 |
| UI | R | 22403 | 10124 | 6325 | 5954 |
| S | U | 52900 | 22904 | 15435 | 14561 |
| S | C | 15012 | 5911 | 4486 | 4615 |
| C | N | 14976 | 5491 | 4928 | 4557 |
| C | L | 17341 | 6794 | 5334 | 5213 |
| C | H | 35595 | 16530 | 9659 | 9406 |
| I | N | 19888 | 8087 | 6011 | 5790 |
| I | L | 18091 | 6885 | 5758 | 5448 |
| I | H | 29933 | 13843 | 8152 | 7938 |
| A | N | 27824 | 12528 | 7984 | 7312 |
| A | L | 3748 | 473 | 1520 | 1755 |
| A | H | 36340 | 15814 | 10417 | 10109 |

Ngưỡng cảnh báo hiếm dùng cho audit: 0 < support < 20 ở từng cohort; đây là quy ước thống kê, chưa là quyết định train.

| Cohort | Metric | Lớp | Support |
| --- | --- | --- | --- |

Cảnh báo mất cân bằng bổ sung: lớp có tỷ lệ dưới 1% trong cohort; không đổi nhãn hay ranh giới split vì cảnh báo này.

| Cohort | Metric | Lớp | Support | Tỷ lệ |
| --- | --- | --- | --- | --- |
| all | AV | P | 527 | 0.776% |
| train | AV | P | 216 | 0.750% |
| validation | AV | P | 137 | 0.688% |
| test | AV | P | 174 | 0.907% |

Target chỉ một lớp: [].

Giữ toàn bộ mapping lớp, cả support 0. Lớp vắng ở train phải ghi không có dữ liệu học; target train chỉ một lớp cần constant/Dummy fallback. Không gộp/xóa lớp khó. Nếu cần mở rộng năm, N1 ghi version/quyết định trước khi đánh giá test. Không đổi ranh giới hoặc chọn tham số bằng kết quả mô hình trên test.

## 5. Nguồn nhãn và last_modified

| Nguồn | Type | Support ML |
| --- | --- | --- |
| nvd@nist.gov | Primary | 49670 |
| 134c704f-9b21-4f2e-91b3-4a467353bcc0 | Secondary | 5732 |
| audit@patchstack.com | Secondary | 2613 |
| security@wordfence.com | Secondary | 2111 |
| secure@microsoft.com | Secondary | 1734 |
| psirt@adobe.com | Secondary | 1077 |
| secalert_us@oracle.com | Secondary | 614 |
| security-advisories@github.com | Secondary | 561 |
| nvd@nist.gov | Secondary | 393 |
| twcert@cert.org.tw | Secondary | 226 |
| secure@intel.com | Secondary | 186 |
| cna@vuldb.com | Secondary | 182 |
| productcert@siemens.com | Secondary | 182 |
| secalert@redhat.com | Secondary | 154 |
| sirt@juniper.net | Secondary | 154 |
| psirt@cisco.com | Secondary | 135 |
| info@cert.vde.com | Secondary | 134 |
| product-security@qualcomm.com | Secondary | 126 |
| iletisim@usom.gov.tr | Secondary | 126 |
| talos-cna@cisco.com | Secondary | 98 |
| psirt@lenovo.com | Secondary | 81 |
| help@fluidattacks.com | Secondary | 78 |
| psirt@us.ibm.com | Secondary | 75 |
| cve-coordination@incibe.es | Secondary | 73 |
| ics-cert@hq.dhs.gov | Secondary | 70 |
| cve@mitre.org | Secondary | 68 |
| cna@sap.com | Secondary | 62 |
| security@zyxel.com.tw | Secondary | 53 |
| psirt@autodesk.com | Secondary | 49 |
| security-alert@hpe.com | Secondary | 46 |
| report@snyk.io | Secondary | 43 |
| ecc0f906-8666-484c-bcf8-c3b7520a72f0 | Secondary | 43 |
| security@vmware.com | Secondary | 40 |
| prodsec@nozominetworks.com | Secondary | 39 |
| psirt@nvidia.com | Secondary | 32 |
| cna@cyber.gov.il | Secondary | 28 |
| f5sirt@f5.com | Secondary | 27 |
| vultures@jpcert.or.jp | Secondary | 23 |
| vulnreport@tenable.com | Secondary | 21 |
| security@opentext.com | Secondary | 20 |
| psirt@hcl.com | Secondary | 20 |
| cybersecurity@se.com | Secondary | 19 |
| meissner@suse.de | Secondary | 17 |
| Mitsubishielectric.Psirt@yd.MitsubishiElectric.co.jp | Secondary | 17 |
| security@ubuntu.com | Secondary | 16 |
| psirt@amd.com | Secondary | 15 |
| cve@gitlab.com | Secondary | 15 |
| reefs@jfrog.com | Secondary | 15 |
| security-officer@isc.org | Secondary | 14 |
| patrick@puiterwijk.org | Secondary | 13 |
| psirt@honeywell.com | Secondary | 13 |
| responsibledisclosure@mattermost.com | Secondary | 13 |
| cybersecurity@ch.abb.com | Secondary | 12 |
| product-security@silabs.com | Secondary | 12 |
| product-security@axis.com | Secondary | 12 |
| trellixpsirt@trellix.com | Secondary | 12 |
| security@open-xchange.com | Secondary | 12 |
| cybersecurity@hitachienergy.com | Secondary | 11 |
| disclosures@gallagher.com | Secondary | 11 |
| security@trendmicro.com | Secondary | 11 |
| 3DS.Information-Security@3ds.com | Secondary | 10 |
| ff89ba41-3aa1-4d27-914a-91399e9639e5 | Secondary | 10 |
| hirt@hitachi.co.jp | Secondary | 9 |
| cve@rapid7.com | Secondary | 9 |
| psirt@sick.de | Secondary | 9 |
| 171caf72-b841-4e04-a68e-93493aff2b94 | Secondary | 9 |
| 430a6cef-dc26-47e3-9fa8-52fb7f19644e | Secondary | 9 |
| security@zabbix.com | Secondary | 9 |
| f946a70c-00eb-42ce-8e9b-634d1f7b5a6f | Secondary | 9 |
| securities@openeuler.org | Secondary | 8 |
| security@qnapsecurity.com.tw | Secondary | 8 |
| cert@ncsc.nl | Secondary | 8 |
| disclosure@vulncheck.com | Secondary | 8 |
| vulnerability@ncsc.ch | Secondary | 8 |
| mobile.security@samsung.com | Secondary | 8 |
| productsecurity@baxter.com | Secondary | 8 |
| vulnerability@kaspersky.com | Secondary | 7 |
| security@hashicorp.com | Secondary | 7 |
| 6f8de1f0-f67e-45a6-b68f-98777fdb759c | Secondary | 7 |
| security@vivo.com | Secondary | 6 |
| hp-security-alert@hp.com | Secondary | 6 |
| psirt@solarwinds.com | Secondary | 6 |
| security@octopus.com | Secondary | 6 |
| security@tibco.com | Secondary | 6 |
| security@php.net | Secondary | 6 |
| 0fc0942c-577d-436f-ae8e-945763c79b02 | Secondary | 6 |
| productsecurity@jci.com | Secondary | 6 |
| secure@blackberry.com | Secondary | 6 |
| psirt@huawei.com | Secondary | 5 |
| jordan@liggitt.net | Secondary | 5 |
| PSIRT@rockwellautomation.com | Secondary | 5 |
| psirt@teamviewer.com | Secondary | 5 |
| VulnerabilityReporting@secomea.com | Secondary | 4 |
| cve@asrg.io | Secondary | 4 |
| cvd@cert.pl | Secondary | 4 |
| 7bc73191-a2b6-4c63-9918-753964601853 | Secondary | 4 |
| security@synology.com | Secondary | 4 |
| security-alert@sophos.com | Secondary | 4 |
| security@ni.com | Secondary | 4 |
| security@otrs.com | Secondary | 4 |
| security@puppet.com | Secondary | 4 |
| 68630edc-a58c-4cbd-9b01-0e130455c8ae | Secondary | 4 |
| df4dee71-de3a-4139-9588-11b62fe6c0ff | Secondary | 4 |
| psirt@moxa.com | Secondary | 4 |
| 7168b535-132a-4efe-a076-338f829b2eb9 | Secondary | 4 |
| 36c7be3b-2937-45df-85ea-ca7133ea542c | Secondary | 4 |
| CybersecurityCOE@eaton.com | Secondary | 3 |
| psirt@esri.com | Secondary | 3 |
| cve-coordination@palantir.com | Secondary | 3 |
| psirt@bosch.com | Secondary | 3 |
| responsible-disclosure@pingidentity.com | Secondary | 3 |
| security@grafana.com | Secondary | 3 |
| psirt@arista.com | Secondary | 3 |
| fc9afe74-3f80-4fb7-a313-e6f036a89882 | Secondary | 3 |
| 41c37e40-543d-43a2-b660-2fee83ea851a | Secondary | 3 |
| psirt@okta.com | Secondary | 3 |
| 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | Secondary | 3 |
| 9119a7d8-5eab-497f-8521-727c672e3725 | Secondary | 3 |
| vdisclose@cert-in.org.in | Secondary | 3 |
| security@zoom.us | Secondary | 3 |
| hsrc@hikvision.com | Secondary | 3 |
| security@dotcms.com | Secondary | 3 |
| PSIRT@samsung.com | Secondary | 3 |
| psirt@sailpoint.com | Secondary | 3 |
| cna@mongodb.com | Secondary | 3 |
| security@sierrawireless.com | Secondary | 2 |
| psirt@paloaltonetworks.com | Secondary | 2 |
| psirt@forcepoint.com | Secondary | 2 |
| cna@python.org | Secondary | 2 |
| a341c0d1-ebf7-493f-a84e-38cf86618674 | Secondary | 2 |
| security@proofpoint.com | Secondary | 2 |
| psirt-info@cyber.jp.nec.com | Secondary | 2 |
| disclosure@synopsys.com | Secondary | 2 |
| 103e4ec9-0a87-450b-af77-479448ddef11 | Secondary | 2 |
| cf45122d-9d50-442a-9b23-e05cde9943d8 | Secondary | 2 |
| infosec@edk2.groups.io | Secondary | 2 |
| dl_cve@linecorp.com | Secondary | 2 |
| security@elastic.co | Secondary | 2 |
| 85b1779b-6ecd-4f52-bcc5-73eac4659dcf | Secondary | 2 |
| PSIRT@sonicwall.com | Secondary | 2 |
| dc3f6da9-85b5-4a73-84a2-2ec90b40fca5 | Secondary | 2 |
| biossecurity@ami.com | Secondary | 2 |
| product-security@gg.jp.panasonic.com | Secondary | 2 |
| cve_disclosure@tech.gov.sg | Secondary | 2 |
| sep@nlnetlabs.nl | Secondary | 2 |
| 10b61619-3869-496c-8a1e-f291b0e71e3f | Secondary | 2 |
| psirt@fortinet.com | Secondary | 2 |
| psirt@servicenow.com | Secondary | 2 |
| a5532a13-c4dd-4202-bef1-e0b8f2f8d12b | Secondary | 2 |
| prodsec@splunk.com | Secondary | 2 |
| zowe-security@lists.openmainframeproject.org | Secondary | 2 |
| security@progress.com | Secondary | 2 |
| 22d9ba52-f336-4b0d-bf1f-0efbdcc3c1de | Secondary | 1 |
| productsecurity@carrier.com | Secondary | 1 |
| info@cybellum.com | Secondary | 1 |
| dsap-vuln-management@google.com | Secondary | 1 |
| zdi-disclosures@trendmicro.com | Secondary | 1 |
| PSIRT@synaptics.com | Secondary | 1 |
| security@baicells.com | Secondary | 1 |
| cybersecurity@bd.com | Secondary | 1 |
| 54bf65a7-a193-42d2-b1ba-8e150d3c35e1 | Secondary | 1 |
| a6d3dc9e-0591-4a13-bce7-0f5b31ff6158 | Secondary | 1 |
| 5d1c2695-1a31-4499-88ae-e847036fd7e3 | Secondary | 1 |
| ot-cert@dragos.com | Secondary | 1 |
| 6b35d637-e00f-4228-858c-b20ad6e1d07b | Secondary | 1 |
| security@eset.com | Secondary | 1 |
| f86ef6dc-4d3a-42ad-8f28-e6d5547a5007 | Secondary | 1 |
| security@selinc.com | Secondary | 1 |
| f98c90f0-e9bd-4fa7-911b-51993f3571fd | Secondary | 1 |
| security-alert@netapp.com | Secondary | 1 |
| psirt@wdc.com | Secondary | 1 |
| cve@zscaler.com | Secondary | 1 |
| vuln@krcert.or.kr | Secondary | 1 |
| security@tcpdump.org | Secondary | 1 |
| security@temporal.io | Secondary | 1 |
| security@openanolis.org | Secondary | 1 |
| cve@checkpoint.com | Secondary | 1 |
| 416baaa9-dc9f-4396-8d5f-8c081fb06d67 | Secondary | 1 |
| product-cna@github.com | Secondary | 1 |
| facts@wolfssl.com | Secondary | 1 |
| security.vulnerabilities@hitachivantara.com | Secondary | 1 |
| security@huntr.dev | Secondary | 1 |
| psirt@purestorage.com | Secondary | 1 |
| incident@nbu.gov.sk | Secondary | 1 |
| psirt@tigera.io | Secondary | 1 |
| research@onekey.com | Secondary | 1 |
| cve-coordination@logitech.com | Secondary | 1 |
| security@m-files.com | Secondary | 1 |
| 596c5446-0ce5-4ba2-aa66-48b3b757a647 | Secondary | 1 |
| SecurityResponse@netmotionsoftware.com | Secondary | 1 |
| security@snowsoftware.com | Secondary | 1 |
| security@apache.org | Secondary | 1 |
| security@xiaomi.com | Secondary | 1 |
| 20be33e2-bf35-4d13-8fad-18bd2f3e3659 | Secondary | 1 |
| security-report@netflix.com | Secondary | 1 |
| cve-coordination@google.com | Secondary | 1 |
| 1443cd92-d354-46d2-9290-d812316ca43a | Secondary | 1 |
| 1e3a9e0f-5156-4bf8-b8a3-cc311bfc0f4a | Secondary | 1 |
| security@nortonlifelock.com | Secondary | 1 |
| security@documentfoundation.org | Secondary | 1 |
| info@starlabs.sg | Secondary | 1 |
| cb7ba516-3b07-4c98-b0c2-715220f1a8f6 | Secondary | 1 |
| security@genetec.com | Secondary | 1 |
| arm-security@arm.com | Secondary | 1 |

| Split | Nguồn | Type | Support ML |
| --- | --- | --- | --- |
| train | nvd@nist.gov | Primary | 26516 |
| train | secure@microsoft.com | Secondary | 773 |
| train | psirt@adobe.com | Secondary | 461 |
| train | secalert_us@oracle.com | Secondary | 272 |
| train | nvd@nist.gov | Secondary | 258 |
| train | security@wordfence.com | Secondary | 101 |
| train | twcert@cert.org.tw | Secondary | 89 |
| train | info@cert.vde.com | Secondary | 75 |
| train | iletisim@usom.gov.tr | Secondary | 72 |
| train | sirt@juniper.net | Secondary | 53 |
| train | productcert@siemens.com | Secondary | 48 |
| train | help@fluidattacks.com | Secondary | 47 |
| train | security@zyxel.com.tw | Secondary | 23 |
| train | f5sirt@f5.com | Secondary | 17 |
| train | security-officer@isc.org | Secondary | 5 |
| train | 134c704f-9b21-4f2e-91b3-4a467353bcc0 | Secondary | 2 |
| train | psirt@esri.com | Secondary | 2 |
| train | psirt@solarwinds.com | Secondary | 1 |
| validation | nvd@nist.gov | Primary | 12105 |
| validation | 134c704f-9b21-4f2e-91b3-4a467353bcc0 | Secondary | 3373 |
| validation | audit@patchstack.com | Secondary | 1028 |
| validation | security@wordfence.com | Secondary | 754 |
| validation | secure@microsoft.com | Secondary | 422 |
| validation | security-advisories@github.com | Secondary | 300 |
| validation | psirt@adobe.com | Secondary | 288 |
| validation | secalert_us@oracle.com | Secondary | 214 |
| validation | cna@vuldb.com | Secondary | 104 |
| validation | secure@intel.com | Secondary | 78 |
| validation | secalert@redhat.com | Secondary | 74 |
| validation | talos-cna@cisco.com | Secondary | 64 |
| validation | productcert@siemens.com | Secondary | 64 |
| validation | nvd@nist.gov | Secondary | 60 |
| validation | cve-coordination@incibe.es | Secondary | 58 |
| validation | psirt@autodesk.com | Secondary | 48 |
| validation | product-security@qualcomm.com | Secondary | 47 |
| validation | ecc0f906-8666-484c-bcf8-c3b7520a72f0 | Secondary | 43 |
| validation | psirt@lenovo.com | Secondary | 41 |
| validation | ics-cert@hq.dhs.gov | Secondary | 40 |
| validation | twcert@cert.org.tw | Secondary | 39 |
| validation | psirt@cisco.com | Secondary | 38 |
| validation | iletisim@usom.gov.tr | Secondary | 34 |
| validation | help@fluidattacks.com | Secondary | 30 |
| validation | sirt@juniper.net | Secondary | 30 |
| validation | info@cert.vde.com | Secondary | 27 |
| validation | cve@mitre.org | Secondary | 25 |
| validation | security@vmware.com | Secondary | 24 |
| validation | cna@sap.com | Secondary | 22 |
| validation | psirt@us.ibm.com | Secondary | 20 |
| validation | security-alert@hpe.com | Secondary | 19 |
| validation | security@opentext.com | Secondary | 18 |
| validation | vulnreport@tenable.com | Secondary | 18 |
| validation | prodsec@nozominetworks.com | Secondary | 17 |
| validation | psirt@nvidia.com | Secondary | 15 |
| validation | psirt@hcl.com | Secondary | 13 |
| validation | psirt@honeywell.com | Secondary | 12 |
| validation | security@zyxel.com.tw | Secondary | 10 |
| validation | report@snyk.io | Secondary | 10 |
| validation | cybersecurity@hitachienergy.com | Secondary | 9 |
| validation | 171caf72-b841-4e04-a68e-93493aff2b94 | Secondary | 9 |
| validation | 430a6cef-dc26-47e3-9fa8-52fb7f19644e | Secondary | 9 |
| validation | securities@openeuler.org | Secondary | 8 |
| validation | f5sirt@f5.com | Secondary | 8 |
| validation | vulnerability@kaspersky.com | Secondary | 7 |
| validation | security@ubuntu.com | Secondary | 7 |
| validation | product-security@silabs.com | Secondary | 7 |
| validation | 3DS.Information-Security@3ds.com | Secondary | 7 |
| validation | trellixpsirt@trellix.com | Secondary | 7 |
| validation | security@open-xchange.com | Secondary | 7 |
| validation | responsibledisclosure@mattermost.com | Secondary | 7 |
| validation | cybersecurity@ch.abb.com | Secondary | 6 |
| validation | patrick@puiterwijk.org | Secondary | 6 |
| validation | Mitsubishielectric.Psirt@yd.MitsubishiElectric.co.jp | Secondary | 6 |
| validation | security@tibco.com | Secondary | 6 |
| validation | reefs@jfrog.com | Secondary | 6 |
| validation | hirt@hitachi.co.jp | Secondary | 5 |
| validation | security-officer@isc.org | Secondary | 5 |
| validation | security@qnapsecurity.com.tw | Secondary | 5 |
| validation | vulnerability@ncsc.ch | Secondary | 5 |
| validation | 6f8de1f0-f67e-45a6-b68f-98777fdb759c | Secondary | 5 |
| validation | psirt@solarwinds.com | Secondary | 4 |
| validation | 7bc73191-a2b6-4c63-9918-753964601853 | Secondary | 4 |
| validation | security@php.net | Secondary | 4 |
| validation | cybersecurity@se.com | Secondary | 4 |
| validation | 68630edc-a58c-4cbd-9b01-0e130455c8ae | Secondary | 4 |
| validation | psirt@amd.com | Secondary | 3 |
| validation | VulnerabilityReporting@secomea.com | Secondary | 3 |
| validation | psirt@arista.com | Secondary | 3 |
| validation | fc9afe74-3f80-4fb7-a313-e6f036a89882 | Secondary | 3 |
| validation | product-security@axis.com | Secondary | 3 |
| validation | disclosure@vulncheck.com | Secondary | 3 |
| validation | vdisclose@cert-in.org.in | Secondary | 3 |
| validation | hsrc@hikvision.com | Secondary | 3 |
| validation | psirt@sailpoint.com | Secondary | 3 |
| validation | 7168b535-132a-4efe-a076-338f829b2eb9 | Secondary | 3 |
| validation | psirt@bosch.com | Secondary | 2 |
| validation | security@octopus.com | Secondary | 2 |
| validation | security@grafana.com | Secondary | 2 |
| validation | cna@python.org | Secondary | 2 |
| validation | cve@rapid7.com | Secondary | 2 |
| validation | security@proofpoint.com | Secondary | 2 |
| validation | 103e4ec9-0a87-450b-af77-479448ddef11 | Secondary | 2 |
| validation | dl_cve@linecorp.com | Secondary | 2 |
| validation | psirt@teamviewer.com | Secondary | 2 |
| validation | mobile.security@samsung.com | Secondary | 2 |
| validation | 0fc0942c-577d-436f-ae8e-945763c79b02 | Secondary | 2 |
| validation | security@puppet.com | Secondary | 2 |
| validation | PSIRT@sonicwall.com | Secondary | 2 |
| validation | vultures@jpcert.or.jp | Secondary | 2 |
| validation | security@dotcms.com | Secondary | 2 |
| validation | jordan@liggitt.net | Secondary | 2 |
| validation | PSIRT@samsung.com | Secondary | 2 |
| validation | cna@mongodb.com | Secondary | 2 |
| validation | security@synology.com | Secondary | 2 |
| validation | cve_disclosure@tech.gov.sg | Secondary | 2 |
| validation | cve-coordination@palantir.com | Secondary | 1 |
| validation | 22d9ba52-f336-4b0d-bf1f-0efbdcc3c1de | Secondary | 1 |
| validation | productsecurity@carrier.com | Secondary | 1 |
| validation | responsible-disclosure@pingidentity.com | Secondary | 1 |
| validation | info@cybellum.com | Secondary | 1 |
| validation | cvd@cert.pl | Secondary | 1 |
| validation | dsap-vuln-management@google.com | Secondary | 1 |
| validation | zdi-disclosures@trendmicro.com | Secondary | 1 |
| validation | PSIRT@synaptics.com | Secondary | 1 |
| validation | psirt@forcepoint.com | Secondary | 1 |
| validation | security@baicells.com | Secondary | 1 |
| validation | 41c37e40-543d-43a2-b660-2fee83ea851a | Secondary | 1 |
| validation | infosec@edk2.groups.io | Secondary | 1 |
| validation | 5d1c2695-1a31-4499-88ae-e847036fd7e3 | Secondary | 1 |
| validation | ot-cert@dragos.com | Secondary | 1 |
| validation | 6b35d637-e00f-4228-858c-b20ad6e1d07b | Secondary | 1 |
| validation | 9119a7d8-5eab-497f-8521-727c672e3725 | Secondary | 1 |
| validation | security@eset.com | Secondary | 1 |
| validation | f86ef6dc-4d3a-42ad-8f28-e6d5547a5007 | Secondary | 1 |
| validation | security@selinc.com | Secondary | 1 |
| validation | f98c90f0-e9bd-4fa7-911b-51993f3571fd | Secondary | 1 |
| validation | PSIRT@rockwellautomation.com | Secondary | 1 |
| validation | psirt@wdc.com | Secondary | 1 |
| validation | disclosures@gallagher.com | Secondary | 1 |
| validation | security@elastic.co | Secondary | 1 |
| validation | cve@zscaler.com | Secondary | 1 |
| validation | security@otrs.com | Secondary | 1 |
| validation | security@tcpdump.org | Secondary | 1 |
| validation | psirt@paloaltonetworks.com | Secondary | 1 |
| validation | security@temporal.io | Secondary | 1 |
| validation | security@openanolis.org | Secondary | 1 |
| validation | psirt@esri.com | Secondary | 1 |
| validation | 416baaa9-dc9f-4396-8d5f-8c081fb06d67 | Secondary | 1 |
| validation | security@zoom.us | Secondary | 1 |
| validation | product-cna@github.com | Secondary | 1 |
| validation | cna@cyber.gov.il | Secondary | 1 |
| validation | facts@wolfssl.com | Secondary | 1 |
| validation | security@huntr.dev | Secondary | 1 |
| validation | incident@nbu.gov.sk | Secondary | 1 |
| validation | security@trendmicro.com | Secondary | 1 |
| validation | psirt@tigera.io | Secondary | 1 |
| validation | secure@blackberry.com | Secondary | 1 |
| validation | psirt@moxa.com | Secondary | 1 |
| validation | security@hashicorp.com | Secondary | 1 |
| validation | research@onekey.com | Secondary | 1 |
| validation | cve-coordination@logitech.com | Secondary | 1 |
| validation | security@ni.com | Secondary | 1 |
| validation | security@m-files.com | Secondary | 1 |
| validation | 596c5446-0ce5-4ba2-aa66-48b3b757a647 | Secondary | 1 |
| validation | security@snowsoftware.com | Secondary | 1 |
| validation | product-security@gg.jp.panasonic.com | Secondary | 1 |
| validation | 20be33e2-bf35-4d13-8fad-18bd2f3e3659 | Secondary | 1 |
| validation | security-report@netflix.com | Secondary | 1 |
| validation | dc3f6da9-85b5-4a73-84a2-2ec90b40fca5 | Secondary | 1 |
| validation | cve-coordination@google.com | Secondary | 1 |
| validation | disclosure@synopsys.com | Secondary | 1 |
| validation | df4dee71-de3a-4139-9588-11b62fe6c0ff | Secondary | 1 |
| validation | 1e3a9e0f-5156-4bf8-b8a3-cc311bfc0f4a | Secondary | 1 |
| test | nvd@nist.gov | Primary | 11049 |
| test | 134c704f-9b21-4f2e-91b3-4a467353bcc0 | Secondary | 2357 |
| test | audit@patchstack.com | Secondary | 1585 |
| test | security@wordfence.com | Secondary | 1256 |
| test | secure@microsoft.com | Secondary | 539 |
| test | psirt@adobe.com | Secondary | 328 |
| test | security-advisories@github.com | Secondary | 261 |
| test | secalert_us@oracle.com | Secondary | 128 |
| test | secure@intel.com | Secondary | 108 |
| test | twcert@cert.org.tw | Secondary | 98 |
| test | psirt@cisco.com | Secondary | 97 |
| test | secalert@redhat.com | Secondary | 80 |
| test | product-security@qualcomm.com | Secondary | 79 |
| test | cna@vuldb.com | Secondary | 78 |
| test | nvd@nist.gov | Secondary | 75 |
| test | sirt@juniper.net | Secondary | 71 |
| test | productcert@siemens.com | Secondary | 70 |
| test | psirt@us.ibm.com | Secondary | 55 |
| test | cve@mitre.org | Secondary | 43 |
| test | psirt@lenovo.com | Secondary | 40 |
| test | cna@sap.com | Secondary | 40 |
| test | talos-cna@cisco.com | Secondary | 34 |
| test | report@snyk.io | Secondary | 33 |
| test | info@cert.vde.com | Secondary | 32 |
| test | ics-cert@hq.dhs.gov | Secondary | 30 |
| test | security-alert@hpe.com | Secondary | 27 |
| test | cna@cyber.gov.il | Secondary | 27 |
| test | prodsec@nozominetworks.com | Secondary | 22 |
| test | vultures@jpcert.or.jp | Secondary | 21 |
| test | iletisim@usom.gov.tr | Secondary | 20 |
| test | security@zyxel.com.tw | Secondary | 20 |
| test | meissner@suse.de | Secondary | 17 |
| test | psirt@nvidia.com | Secondary | 17 |
| test | security@vmware.com | Secondary | 16 |
| test | cve@gitlab.com | Secondary | 15 |
| test | cve-coordination@incibe.es | Secondary | 15 |
| test | cybersecurity@se.com | Secondary | 15 |
| test | psirt@amd.com | Secondary | 12 |
| test | Mitsubishielectric.Psirt@yd.MitsubishiElectric.co.jp | Secondary | 11 |
| test | ff89ba41-3aa1-4d27-914a-91399e9639e5 | Secondary | 10 |
| test | disclosures@gallagher.com | Secondary | 10 |
| test | security@trendmicro.com | Secondary | 10 |
| test | product-security@axis.com | Secondary | 9 |
| test | psirt@sick.de | Secondary | 9 |
| test | reefs@jfrog.com | Secondary | 9 |
| test | security@ubuntu.com | Secondary | 9 |
| test | security@zabbix.com | Secondary | 9 |
| test | f946a70c-00eb-42ce-8e9b-634d1f7b5a6f | Secondary | 9 |
| test | cert@ncsc.nl | Secondary | 8 |
| test | productsecurity@baxter.com | Secondary | 8 |
| test | patrick@puiterwijk.org | Secondary | 7 |
| test | cve@rapid7.com | Secondary | 7 |
| test | psirt@hcl.com | Secondary | 7 |
| test | cybersecurity@ch.abb.com | Secondary | 6 |
| test | security@vivo.com | Secondary | 6 |
| test | hp-security-alert@hp.com | Secondary | 6 |
| test | responsibledisclosure@mattermost.com | Secondary | 6 |
| test | security@hashicorp.com | Secondary | 6 |
| test | productsecurity@jci.com | Secondary | 6 |
| test | mobile.security@samsung.com | Secondary | 6 |
| test | psirt@huawei.com | Secondary | 5 |
| test | trellixpsirt@trellix.com | Secondary | 5 |
| test | disclosure@vulncheck.com | Secondary | 5 |
| test | security@open-xchange.com | Secondary | 5 |
| test | product-security@silabs.com | Secondary | 5 |
| test | secure@blackberry.com | Secondary | 5 |
| test | cve@asrg.io | Secondary | 4 |
| test | security-officer@isc.org | Secondary | 4 |
| test | hirt@hitachi.co.jp | Secondary | 4 |
| test | PSIRT@rockwellautomation.com | Secondary | 4 |
| test | security-alert@sophos.com | Secondary | 4 |
| test | security@octopus.com | Secondary | 4 |
| test | 0fc0942c-577d-436f-ae8e-945763c79b02 | Secondary | 4 |
| test | 36c7be3b-2937-45df-85ea-ca7133ea542c | Secondary | 4 |
| test | CybersecurityCOE@eaton.com | Secondary | 3 |
| test | security@qnapsecurity.com.tw | Secondary | 3 |
| test | cvd@cert.pl | Secondary | 3 |
| test | psirt@okta.com | Secondary | 3 |
| test | 3DS.Information-Security@3ds.com | Secondary | 3 |
| test | jordan@liggitt.net | Secondary | 3 |
| test | 3c1d8aa1-5a33-4ea4-8992-aadd6440af75 | Secondary | 3 |
| test | vulnreport@tenable.com | Secondary | 3 |
| test | vulnerability@ncsc.ch | Secondary | 3 |
| test | psirt@teamviewer.com | Secondary | 3 |
| test | security@ni.com | Secondary | 3 |
| test | df4dee71-de3a-4139-9588-11b62fe6c0ff | Secondary | 3 |
| test | security@otrs.com | Secondary | 3 |
| test | psirt@moxa.com | Secondary | 3 |
| test | security@opentext.com | Secondary | 2 |
| test | security@sierrawireless.com | Secondary | 2 |
| test | a341c0d1-ebf7-493f-a84e-38cf86618674 | Secondary | 2 |
| test | 9119a7d8-5eab-497f-8521-727c672e3725 | Secondary | 2 |
| test | psirt-info@cyber.jp.nec.com | Secondary | 2 |
| test | security@synology.com | Secondary | 2 |
| test | cf45122d-9d50-442a-9b23-e05cde9943d8 | Secondary | 2 |
| test | responsible-disclosure@pingidentity.com | Secondary | 2 |
| test | 85b1779b-6ecd-4f52-bcc5-73eac4659dcf | Secondary | 2 |
| test | biossecurity@ami.com | Secondary | 2 |
| test | security@zoom.us | Secondary | 2 |
| test | sep@nlnetlabs.nl | Secondary | 2 |
| test | f5sirt@f5.com | Secondary | 2 |
| test | 6f8de1f0-f67e-45a6-b68f-98777fdb759c | Secondary | 2 |
| test | 10b61619-3869-496c-8a1e-f291b0e71e3f | Secondary | 2 |
| test | psirt@fortinet.com | Secondary | 2 |
| test | cve-coordination@palantir.com | Secondary | 2 |
| test | psirt@servicenow.com | Secondary | 2 |
| test | a5532a13-c4dd-4202-bef1-e0b8f2f8d12b | Secondary | 2 |
| test | prodsec@splunk.com | Secondary | 2 |
| test | security@puppet.com | Secondary | 2 |
| test | zowe-security@lists.openmainframeproject.org | Secondary | 2 |
| test | 41c37e40-543d-43a2-b660-2fee83ea851a | Secondary | 2 |
| test | security@php.net | Secondary | 2 |
| test | security@progress.com | Secondary | 2 |
| test | cybersecurity@hitachienergy.com | Secondary | 2 |
| test | VulnerabilityReporting@secomea.com | Secondary | 1 |
| test | psirt@paloaltonetworks.com | Secondary | 1 |
| test | psirt@forcepoint.com | Secondary | 1 |
| test | cybersecurity@bd.com | Secondary | 1 |
| test | disclosure@synopsys.com | Secondary | 1 |
| test | 54bf65a7-a193-42d2-b1ba-8e150d3c35e1 | Secondary | 1 |
| test | a6d3dc9e-0591-4a13-bce7-0f5b31ff6158 | Secondary | 1 |
| test | security-alert@netapp.com | Secondary | 1 |
| test | vuln@krcert.or.kr | Secondary | 1 |
| test | cve@checkpoint.com | Secondary | 1 |
| test | security.vulnerabilities@hitachivantara.com | Secondary | 1 |
| test | psirt@solarwinds.com | Secondary | 1 |
| test | dc3f6da9-85b5-4a73-84a2-2ec90b40fca5 | Secondary | 1 |
| test | psirt@purestorage.com | Secondary | 1 |
| test | PSIRT@samsung.com | Secondary | 1 |
| test | security@elastic.co | Secondary | 1 |
| test | infosec@edk2.groups.io | Secondary | 1 |
| test | SecurityResponse@netmotionsoftware.com | Secondary | 1 |
| test | security@dotcms.com | Secondary | 1 |
| test | security@apache.org | Secondary | 1 |
| test | security@xiaomi.com | Secondary | 1 |
| test | psirt@bosch.com | Secondary | 1 |
| test | 1443cd92-d354-46d2-9290-d812316ca43a | Secondary | 1 |
| test | security@nortonlifelock.com | Secondary | 1 |
| test | security@grafana.com | Secondary | 1 |
| test | cna@mongodb.com | Secondary | 1 |
| test | security@documentfoundation.org | Secondary | 1 |
| test | psirt@honeywell.com | Secondary | 1 |
| test | info@starlabs.sg | Secondary | 1 |
| test | cb7ba516-3b07-4c98-b0c2-715220f1a8f6 | Secondary | 1 |
| test | product-security@gg.jp.panasonic.com | Secondary | 1 |
| test | security@genetec.com | Secondary | 1 |
| test | psirt@autodesk.com | Secondary | 1 |
| test | arm-security@arm.com | Secondary | 1 |
| test | 7168b535-132a-4efe-a076-338f829b2eb9 | Secondary | 1 |
| test | help@fluidattacks.com | Secondary | 1 |

Nguồn ngoài NVD không tự gọi là CNA; bảng chỉ thống kê địa chỉ nguồn đã chọn. Các metric nguồn thay thế và xung đột ưu tiên cần raw NVD để kiểm lại.

| Chỉ số thời gian | Thực tế |
| --- | --- |
| published min/max | ['2023-01-01T01:15:10.057000+00:00', '2024-12-31T23:15:41.553000+00:00'] |
| last_modified min/max | ['2023-11-07T02:03:29.727000+00:00', '2026-10-02T13:58:26.843000+00:00'] |
| last_modified > published (master) | 71312 |
| last_modified > published (ML) | 67912 |
| ID mang năm khác published | 14848 |

| Split | ML có last_modified >= end_exclusive |
| --- | --- |
| train | 28815 |
| validation | 19921 |
| test | 19176 |

| Năm last_modified của ứng viên ML | Số dòng |
| --- | --- |
| 2026 | 67912 |

Chia theo published, không dùng năm CVE ID. Snapshot hiện tại đã chỉnh sửa sau công bố, nên chia thời gian không phục hồi dữ liệu lịch sử as-known-then. last_modified cho thấy thời điểm sửa record, chưa chứng minh trường description/metric cụ thể đã đổi.

## 6. ID và mô tả trùng xuyên split

ID trùng: 0 nhóm; chi tiết: [].

Quy tắc mô tả: **Unicode NFKC -> collapse whitespace -> strip -> casefold**. Chỉ kiểm ứng viên ML; giữ nguyên punctuation, không bỏ phiên bản/số hoặc gộp sản phẩm.

| Chỉ số duplicate ML | Thực tế |
| --- | --- |
| Nhóm mô tả trùng | 1363 |
| Dòng thuộc nhóm trùng | 5327 |
| Dòng dư so với một dòng/nhóm | 3964 |
| Nhóm có mô tả trùng xuyên split | 199 |
| Dòng thuộc nhóm xuyên split | 1548 |
| Nhóm trùng có nhiều vector nguồn | 440 |
| Nhóm xuyên split có nhiều vector nguồn | 142 |

| Split | Dòng thuộc nhóm trùng xuyên split |
| --- | --- |
| train | 666 |
| validation | 554 |
| test | 328 |

| Cặp split | Số nhóm giao nhau (không cộng để ra tổng nhóm) |
| --- | --- |
| train\|validation | 111 |
| train\|test | 102 |
| validation\|test | 86 |

| SHA-256 mô tả chuẩn hóa | Số dòng | Split | CVE ID ví dụ | Số vector khác nhau |
| --- | --- | --- | --- | --- |
| ed9e9e24a3ea65a0323c453ed38e9eb5014c7e8971f3facef6914c9d86eb7dcd | 101 | test,validation | CVE-2024-20769 (validation): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N; CVE-2024-41842 (test): CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N | 2 |
| d65c240a1b79b602bba0986e3976d3d68ca4e07e7e79de5d9fdd987496b2395a | 98 | train,validation | CVE-2023-47064 (train): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N; CVE-2023-51464 (validation): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 1 |
| f12f6af6aeb798de47efa2e39b05e8d516778e0584787438d85b5ada6173fe94 | 69 | test,train,validation | CVE-2023-21675 (train): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H; CVE-2024-20693 (validation): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H; CVE-2024-37979 (test): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 7 |
| 84a7275951e07ff863d1d5c2cd6fd1b67256f07c31ee2169addb0f373db8f6ce | 45 | test,train,validation | CVE-2023-24932 (train): CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H; CVE-2024-20669 (validation): CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H; CVE-2024-26184 (test): CVSS:3.1/AV:A/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H | 14 |
| d54edbd8981835cde2d15b93fb10ecdceec65255572a954db2109a0d1581c832 | 42 | test,validation | CVE-2024-20760 (validation): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N; CVE-2024-41877 (test): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 1 |
| 454983695ae837054d2a5dad19da66e97acb61273257888640f9480b2ccb1608 | 38 | test,train,validation | CVE-2023-35365 (train): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H; CVE-2024-26179 (validation): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H; CVE-2024-38120 (test): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | 6 |
| 0e9283414b91aa0efc58cf2c66fc01bc5cc897b88ca1cf5c6b5075123539e65d | 34 | test,train,validation | CVE-2023-21681 (train): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H; CVE-2024-21350 (validation): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H; CVE-2024-43519 (test): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | 1 |
| 4959c41420c62caeb818fb55549fa9169136b3776bfa71d50f21da35cee38ec8 | 28 | test,train,validation | CVE-2023-21554 (train): CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H; CVE-2024-21363 (validation): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H; CVE-2024-49118 (test): CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H | 7 |
| 1c29403185bb23155113e2cc0b8072d67773ffc319b3ffa6cba8bae7499a3afb | 27 | test,train,validation | CVE-2023-21570 (train): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N; CVE-2024-21389 (validation): CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N; CVE-2024-38211 (test): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N | 7 |
| 11054659fd35f443b6cc19068367136007ca9124387fc2d5ddfd6e8f2254b3a1 | 26 | test,train,validation | CVE-2022-23264 (train): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N; CVE-2024-21336 (validation): CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N; CVE-2024-38156 (test): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 8 |
| e62f4b0907163710f21eac1327ee34dbf335e74b5d8b922f9da4d6cbc6b86b84 | 26 | test,validation | CVE-2024-28906 (validation): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H; CVE-2024-37334 (test): CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H | 2 |
| 4a9effeccbe6f38ee7878b3def055cdf151d76c37f970003dd186b3039584141 | 25 | test,train,validation | CVE-2022-35750 (train): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H; CVE-2024-20683 (validation): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H; CVE-2024-38059 (test): CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H | 2 |

Các nhóm trên tạo nguy cơ leakage nội dung giữa split thời gian. Findings CSV liệt kê từng CVE trong tất cả nhóm xuyên split bằng hash mô tả, không chép mô tả vào reports. Đề nghị N1/N3 rà nhóm và chốt chính sách có version cho duplicate trước train; nếu tạo cohort đánh giá không trùng, công bố riêng số loại theo split và support lớp. Bản audit không xóa/dời dòng hoặc gán split chính thức.

Mô tả trùng có vector khác nhau không đồng nghĩa nhãn lệch vector: có thể thiếu thông tin trong mô tả hoặc nguồn chấm khác nhau. Không thể tự sửa nhãn dựa trên một chuỗi mô tả chung; cần review source/raw.

Gần trùng/nhóm sản phẩm: **chưa kiểm đầy đủ**. Phương pháp đề xuất: dùng token/shingle và MinHash để sàng lọc, rồi review các cặp cùng sản phẩm/phiên bản; chuẩn hóa CPE vendor/product để đối chiếu nhóm. Không fit TF-IDF trong audit này. Cần N1 cung cấp raw NVD/CPE/references đúng snapshot/checksum; generic template, tên sản phẩm thay đổi và các mô tả khác chữ là giới hạn của exact match.

## 7. Scope, điểm Base và việc cần phối hợp

Scope thực tế: {"status_counts": {"needs_review": 71653}, "in_scope_true": 0, "web_mobile_by_split": {"train": "pending/N/A", "validation": "pending/N/A", "test": "pending/N/A"}}. in_scope=false cùng needs_review là chưa xác nhận, không phải tất cả ngoài phạm vi. Cập nhật Web/mobile theo split sau kết quả N2/N1.

Base Score chỉ kiểm có mặt/range [0,10]; **chưa đối chiếu lại bằng scorer**. Không tự viết công thức điểm khác. Cần scorer dùng chung từ N2 trước khi khóa dataset.

EPSS ngày 2026-09-29; KEV phát hành 2026-09-30T16:59:23.0688Z, tải 2026-10-01T11:29:35.854976+00:00. Không diễn giải là dự báo khai thác lịch sử tại published.

File thiết kế Phase 0 hiện có: {"config/model.yaml": false, "docs/model-plan.md": false}. Nếu thiếu, đề nghị N1 tích hợp PR Phase 0. Các kiến nghị mới ghi ở báo cáo này; chưa có xác nhận N1/N2 đã xử lý.

## 8. Lệnh chạy và artifact

```powershell
.\.venv\Scripts\python.exe -m src.model.audit_data --table data/processed/joined_pilot_20261005T164912_356960Z/cves.parquet --metadata data/processed/joined_pilot_20261005T164912_356960Z/metadata.json --config config/project.yaml --manifest docs/handoffs/phase-1-joined-20261005.json --archive C:/Users/ASUS/Downloads/t08-p1-joined-20261005T164912_356960Z.zip
```

Bảng support nhỏ: `reports\full_ml_label_counts.csv`. Toàn bộ phát hiện theo CVE/cột: `reports\full_ml_findings.csv`. Hai CSV không chứa description. Không commit ZIP, Parquet, CSV nguồn hoặc model weights.

Script chỉ đọc bảng/metadata/config/manifest và kiểm hash trước/sau. Không train, fit TF-IDF, gọi API, sửa bảng nguồn hay khóa split.

## 9. Kiểm chứng triển khai

Lệnh kiểm code thực sự chạy sau khi hoàn thiện script:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_model_data_audit -v
```

Kết quả: **47 tests, OK**, exit code 0. Fixture kiểm nhãn/vector lệch,
description trắng/missing, Rejected, lớp vắng/hiếm, target chỉ một lớp,
ID và mô tả trùng xuyên split, mốc 01/01 và 01/07/2024, end_exclusive,
EPSS missing, input bất biến, checksum/version/config/manifest sai và
CLI dừng trước khi ghi đè nguồn. CLI thực tế trên gói 71.653 dòng cũng exit code 0.

Đối chiếu độc lập bằng phép đếm riêng xác nhận 67.912 ứng viên,
split 28.815/19.921/19.176, support từng lớp, 199 nhóm trùng xuyên split
với 1.548 dòng và 142 nhóm có nhiều bộ nhãn. Điều này xác nhận kết quả audit,
chưa xác nhận scorer, scope hay mức độ leakage của các nhóm gần trùng.

Kiểm whitespace dùng `git -c core.whitespace=cr-at-eol diff --check` đạt.
Tùy chọn theo lệnh này chấp nhận CRLF có sẵn trong working tree Windows;
không đổi cấu hình Git hoặc sửa các file chung để chuẩn hóa line ending.

### Bước 4 — Code kiểm đầu vào dùng chung cho baseline

`src/model/data_validation.py` cung cấp `validate_model_input` và lỗi
`ModelInputError.issues` theo CVE ID/cột. `prepare_baseline_inputs` trong
`src/model/baseline.py` gọi validator trước khi trả bản sao của:

- `features`: Series chỉ chứa description.
- `targets`: DataFrame theo thứ tự AV, AC, PR, UI, S, C, I, A.
- `cve_ids`: metadata tách riêng, giữ index để đối chiếu với feature/target.

Validator kiểm các dòng được caller gửi; không âm thầm lọc, sửa nhãn hoặc
deduplicate. Rejected, description không phải text/trắng, ID trùng/sai,
nhãn/vector/version không hợp lệ và cờ nhãn không hợp lệ bị từ chối
với chẩn đoán đầy đủ. Dataset version có thể được đối chiếu bằng tham số
`dataset_version`. EPSS/KEV, điểm CVSS, source, scope và split không trở thành feature.

Audit cũng dùng helper boolean để báo lỗi giá trị chuỗi/số trong ba trường
boolean thay vì ép truthiness hoặc crash. Description dạng số được báo lỗi
và không được đưa vào ứng viên NLP.

13 test bổ sung gồm 11 test validator/baseline và hai regression audit; cộng với
34 test đã có thành 47 test đạt. Chưa triển khai trainer Phase 2, fit TF-IDF,
class weights hay kết quả đánh giá mô hình.

Đã kiểm thêm trên **67.912 dòng có nhãn** được chọn tường minh từ bảng thật,
không sửa master. Kết quả: features shape (67912,), targets shape (67912, 8),
67.912 CVE ID duy nhất, index thẳng hàng, split nguồn vẫn null và hash Parquet,
metadata/config trước-sau không đổi. Đây là kiểm đầu vào, chưa xác nhận sẵn sàng train;
scope, nhóm trùng và scorer còn cần xử lý theo các mục trên.

Lệnh kiểm trên dữ liệu thật thực sự đã chạy:

```powershell
@'
import hashlib, json
from pathlib import Path
import pandas as pd
from src.model.baseline import prepare_baseline_inputs

folder=Path("data/processed/joined_pilot_20261005T164912_356960Z")
paths=[folder/"cves.parquet",folder/"metadata.json",Path("config/project.yaml")]
before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
metadata=json.loads(paths[1].read_text(encoding="utf-8"))
master=pd.read_parquet(paths[0])
# Explicitly submit the labelled NLP cohort, leaving the master untouched.
candidate=(master.vuln_status.ne("Rejected") &
           master.description.str.strip().fillna("").ne("") &
           master.has_cvss31_label)
submitted=master.loc[candidate]
inputs=prepare_baseline_inputs(submitted,dataset_version=metadata["dataset_version"])
assert inputs.features.name=="description" and len(inputs.features)==67912
assert list(inputs.targets)==["AV","AC","PR","UI","S","C","I","A"]
assert inputs.targets.shape==(67912,8)
assert inputs.features.index.equals(inputs.targets.index)
assert inputs.features.index.equals(inputs.cve_ids.index)
assert master.split.isna().all() and not metadata["training_ready"]
assert before=={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
print(json.dumps({"dataset_version":metadata["dataset_version"],
    "features":list(inputs.features.shape),"feature_name":inputs.features.name,
    "targets":list(inputs.targets.shape),"target_columns":list(inputs.targets),
    "unique_cve_ids":int(inputs.cve_ids.nunique()),"source_split_assigned":int(master.split.notna().sum()),
    "source_hashes_unchanged":True},indent=2))
'@ | .\.venv\Scripts\python.exe -
```

