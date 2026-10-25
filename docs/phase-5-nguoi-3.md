# Phase 5 — Người 3: báo cáo NLP, slide và bảo vệ AI

Giao25/10/2026, dự kiến6giờ. Dummy/TF-IDF/DistilBERT đã chạy ở Phase2;
viết từ kết quả đã khóa, không mở thí nghiệm mới. Phase4 vẫn có mục phối hợp pending.

## 1. Branch, môi trường và đầu vào

```powershell
git status --short
git switch develop
git pull --ff-only origin develop
git switch -c docs/p5-ml-slides
```

Lưu sửa riêng trước, không reset; branch đã có thì switch. Giữ ownvenv và các gói
đã nhận. Không cần train/APIkey/GPU để viết hoặc dựng slide. LiveTF-IDF theo runbook;
Torch chỉ cần nếu chủ động chạy inferenceDistilBERT đã có, không bắt buộc buổi bảo vệ.

Đọc [Phase2 completion](phase-2-completion.md), [model card](model-card.md),
`reports/p2_model_comparison.csv`, `reports/p2_distilbert_run.md`,
`reports/p2_reproduction_n1.md`, `reports/p3_prediction_rank_impact.md`,
`docs/01-research-questions.md`, `docs/phase-4-ui-contract.md`, [runbook](runbook.md).
Artifact trong Phase2 ZIP và receipt là nguồn đối chiếu, không lấy số từ trí nhớ/chat.

## 2. File cần tạo và quyền sửa

| File | Chức năng |
|---|---|
| `reports/sections/ml.md` | Phần NLP hoàn chỉnh cho N1 ghép: phương pháp, split, metric, kết quả/lỗi/giới hạn |
| `reports/slides-outline.md` | N3 tổng hợp9slide, hình/nguồn, lời dẫn, người nói, thời lượng |
| `reports/p5-ml-review.md` | Claim→artifact; kiểm model/demo, lỗi thuật ngữ và giới hạn; bàn giao |
| `reports/slides.pptx` và/hoặc `reports/slides.pdf` | Bản trình bày theo quy cách môn; xuất và mở kiểm thật |

Không sửa final-report củaN1 hoặc securitysection củaN2. N2 gửi
`reports/p5-security-slides.md`; nhận nội dung đó để ghép, không đợi mới viết phần AI.
Định dạng deck phải hỏiN1 theo thông báo; chưa chốt thì làm outline và ghi draft,
không coi tên file ví dụ này là yêu cầu chính thức của thầy.

## 3. Bước A — phương pháp (1,5giờ)

Viết `reports/sections/ml.md` theo thứ tự:

1. Input là mô tả tiếngAnh; target8 thành phầnCVSS3.1, không EPSS/KEV/score trong input.
2. Description→8classifier heads→vector→công thứcBase; phân biệt học nhãn và tính điểm.
3. Temporal split/dedup/product overlap theo protocol thật; không khẳng định chống
   leakage tuyệt đối. Đọc code/config để nêu preprocessing đúng từng model,
   không tự thêm lemmatization chỉ vì sơ đồ ban đầu có.
4. Dummy, TF-IDF classifier, DistilBERT multihead; cấu hình/seed/epochs/hardware thật.
5. Metric mỗi thành phần và cách aggregate, exact-vector, invalidvector, scoreMAE.

ML67242; train28815/val19606/test18821. Scopedval69/test108; mobile không có held-out.
MLtoàn bộ và scopedWeb/mobile phải thành bảng khác hoặc cột cohort rõ.
Baseline model N1reproduction, không gọi là binary model gốcN3 nếu chưa nhận.
DistilBERT1epoch/1seed; baseline test đã biết trước Transformer, không gọi blindbenchmark.

## 4. Bước B — kết quả và lỗi (1giờ)

Lập bảng Dummy/TF-IDF/DistilBERT bằng file metric thật. Ghi đầy đủ split,N,
modelversion, đơn vị và hướng tốt hơn. Không chọn mỗi metric có lợi cho một model.
Đối chiếu permetric/aggregate definition trong code trước đặt tiêu đề “macro-F1”.

Kết quả scopedtest để kiểm: TF-IDF macro-F1~0.6549, exact~0.3519, MAE~1.7509;
DistilBERT~0.6196/~0.2778/~1.5093. Transformer không thắng mọi metric.
Các số làm tròn chỉ để văn bản, nguồn đầy đủ từ release. Không đưa số toànML vào
bảng scoped hoặc so validation của model này với test của model khác.

Chọn lỗi validationCVE-2023-38709: observed7.3, TF-IDF9.1,8metric/vector khác nhau;
đọc prediction thật và mô tả để giải thích, không suy nguyên nhân lỗi như kết luận đã chứng minh.
Predicted rank so với observed dùng cùng commonpopulation (69val/108test), không
đồng nhất với rank toàn396 hay queue theoasset. Không tuning sau xem test.
Nêu giới hạn class imbalance, nhãn nguồn, mô tả thiếu, single-run, mobileheld-out trống.

## 5. Bước C — outline và slide (1giờ)

Tạo9slide theo kế hoạch:1bài toán,2dữ liệu/tín hiệu,3thiết kếranking,
4kết quảranking,5caseWeb/mobile,6context/hành động,7AI,8giới hạn/lỗiAI,9kết luận/tái lập.
Mỗi slide có: người nói, một luận điểm, hình/bảng/nguồn, lời dẫn và thời lượng dự kiến.
NhậnN2 slide3–6 vàN1 dữ liệu/kết luận; draftchờ phải ghi rõ, không tự bịa nội dung thiếu.
9slide/9phút cộng6phútdemo là phương án cũ, chỉ dùng nếu khớp thời lượng chính thức.
Giữ trọng tâm bảo mật; không biến deck thành bài giảngTransformer.

Dùng hình Phase3 đã khóa, không chụp chat hoặc sửa số bằng tay. Khi dựngPPT/PDF,
mở từng trang kiểm chữ Việt, font, crop, legends và bảng; đọc thử trên máy trình bày.
Không cố nhét150dòngtop50 vào một slide, demo/phụlục giữ bảng đầy đủ.
Nếu file lớn hơn giới hạn Git, gửi link/gói riêng cóhash/bytes, không force-add data/model.

## 6. Bước D — demo, kiểm và diễn tập (2giờ)

Một giờ chạy runbook cuối và đối chiếu modelversion/hash/mode; lưu command,
OS/Python, kết quả và lỗi vào `p5-ml-review.md`. Model/receipt không đổi; không train.
Live mặc địnhTF-IDF, DistilBERT đã được train/evaluate nhưng không giả liveDistilBERT.
Output đã lưu phải gọi đúng saved; thêm ô nhập tự do/website không thuộc Phase5.

Một giờ diễn tập AI và trọn bài, kiểm khả năng mở deck/PDF và notebookdựphòng.
Ghi thời gian nói thật, không lấy notebookexecutionseconds. Rà9slide với báo cáo cuối;
nguồn/date/cohort/metric thống nhất. Trả lời được: AIhọc gì, vì sao cần baseline,
labelkhácgroundtruth tuyệt đối thế nào, model nào tốt theo metric nào, CVSSdựđoán
có thay quyết địnhvá không, tại sao chưa chứng minh zero-day/mobilegeneralization.

## 7. Bước E — bàn giao (30phút)

```powershell
git add reports/sections/ml.md reports/slides-outline.md reports/p5-ml-review.md
git diff --cached --check
git diff --cached --stat
git commit -m "docs(phase5): write ML results and presentation outline"
git push -u origin docs/p5-ml-slides
```

Deck/PDF commit riêng sau khi đã dựng/kiểm và đúng quy cách; không add file chưa có.
PRbase develop. GửiN1 commit, section, outline/deck, bảngnguồn, kết quảdemo,
và các mục cònchờ. N2 đọc phần diễn giải bảo mật trên slide; N1 ghép báo cáo.

## 8. Prompt IDE

```text
Tôi là N3. Đọc docs/phase-5-nguoi-3.md, model-card, Phase2 completion,
metricrelease và Phase3 predictionrankimpact. Viết reports/sections/ml.md,
reports/slides-outline.md, reports/p5-ml-review.md. Không train hoặc sửa split/model.
Phân biệt allML/scoped, val/test, observed/predicted, liveTF-IDF/savedDistilBERT.
Mỗi bảng có nguồn/N/version; không tuyên bố Transformer thắng toàn bộ.
Nhận nội dung bảo mật N2 và dữ liệu N1 để ghép9slide. Thiếu định dạng/thời lượng
chính thức thì ghi draft; không giả đã diễn tập hoặc đã xuất/kiểm deck.
```

- [ ] SectionML đủphươngpháp/kếtquả/lỗi/giớihạn, metric truynguyên được.
- [ ] Slide đầyđủbảomật, cónguồn và dùnghìnhđúngversion.
- [ ] Demo/runbook kiểm thật, logmáynhận và modelmode rõ.
- [ ] Deck/PDF mởkiểm thật nếu có, thời lượng người nói đãđo.
- [ ] N1 nhậnfile/commit/pending, không giao mỗi ảnh chụp màn hình.
