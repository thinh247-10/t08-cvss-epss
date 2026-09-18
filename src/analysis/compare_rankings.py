#!/usr/bin/env python3
"""
So sanh xep hang uu tien va theo cac thang do khac nhau — RQ2.

TODO:
  - Xep hang theo: CVSS Base (that), CVSS Base (du doan), CVSS Environmental, EPSS
  - Doi chieu top-50 moi thang voi KEV -> tinh recall@50
  - Do trung lap giua cac top-N (Jaccard / Kendall tau)
  - Phan tich 4 o:
      CVSS cao + EPSS thap  -> lang phi cong suc va
      CVSS thap + EPSS cao  -> diem mu nguy hiem
"""
