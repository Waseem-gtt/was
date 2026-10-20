# واجهة API المحلية — was/1

لفحص الأدلة القابل للاستئناف راجع [واجهات الفحص المتتابع](Integrity-Scans.md). لا توجد واجهات لفريق وكلاء داخل المنتج؛ تبقى المحادثة المحلية الفردية اختيارية.

الخادم `127.0.0.1:8080`. JSON وUTF-8؛ الخطأ `{ "error": "…" }` مع HTTP مناسب. جميع المسارات الخاصة تحتاج cookie `was_session`، وPOST بعد المصادقة يحتاج `X-CSRF-Token`. ترجع عمليات الإعداد والدخول CSRF، ويعيده bootstrap للجلسة الحالية. لا تضع كلمة المرور أو CSRF في URL أو Git.

| العملية | المسار | المدخلات / المخرجات |
|---|---|---|
| GET | `/healthz` | سلامة الخدمة وقراءة SQLite؛ عام محليًا |
| GET | `/api/status` | نسخة التطبيق وهل أنشئ المالك؛ عام محليًا |
| POST | `/api/setup` | `password,setup_token`، مرة واحدة؛ الرمز من ملف خاص على جهاز المالك |
| POST | `/api/login` | `password` |
| POST | `/api/logout` | `{}`؛ إلغاء الجلسة |
| GET | `/api/bootstrap` | الأقسام والأدوات والمشاريع والموارد |
| POST | `/api/projects` | `name,description` |
| GET | `/api/project?id=…` | مشروع وأدلته ومهامه وعلاقاته |
| POST | `/api/upload` | `project_id,name,base64`؛ حد الملف16MiB |
| GET | `/api/evidence?project=…&id=…` | تنزيل بعد تحقق SHA256؛ ترويسة `X-Evidence-SHA256` |
| POST | `/api/run` | `project_id,name,steps` |
| POST | `/api/workflows/resume` | `project_id,source_job_id,steps,name`؛ الاسم اختياري،والمنجز لا يغير |
| POST | `/api/results/compare` | `project_id,left_id,right_id`؛ نتيجتا تحليل من الأداة نفسها في المشروع |
| POST | `/api/learning/attempt` | `project_id,lesson_id,answer_index`؛ مدخل تعليمي اصطناعي مسجل،وأي حقول إضافية مرفوضة |
| GET | `/api/requirements` | `q,status,page,mode`؛ السجل أو كامل نص المصدر،25عنصرًا للصفحة |
| GET | `/api/requirements/block?id=…` | نص مقطع وأرقام أسطره وبصمة الأصل |
| GET | `/api/requirements/source` | تنزيل الأصل مطابقًا بالبايت مع `X-Source-SHA256` |
| GET | `/api/requirements/export` | تصدير السجل والمقاطع والروابط والملفات المشار إليها |
| POST | `/api/requirements/import` | `project_id` فقط؛ مرجع خاص دون تكرار النسخة المطابقة،مع تحقق بصمتها |
| GET | `/api/knowledge?project=…` | المصادر وحالة اللقطة والجدولة |
| GET | `/api/knowledge/search?project=…&q=…` | بحث داخل اللقطة،حتى50نتيجة،وحد السؤال120 حرفًا |
| POST | `/api/knowledge/refresh` | `project_id,source_id`؛ يقبل المصدر المسجل فقط دون URL بديل |
| POST | `/api/knowledge/settings` | `project_id,enabled,interval_seconds`؛ فاصل60–86400ثانية،جدول واحد للمالك |
| POST | `/api/relations` | `project_id,source,target,label`؛ الدليلان من المشروع نفسه |
| GET | `/api/report?project=…` | بيانات وصفية منقحة دون محتوى الأدلة |
| GET | `/api/audit` | آخر200حدث ونتيجة تحقق السلسلة الكاملة |
| POST | `/api/workshop` | `project_id,code`؛ عزل إجباري |
| POST | `/api/chat` | `project_id,question,evidence_ids`؛ موصل AI محلي اختياري |
| POST | `/api/backup` | `password` لكلمة حماية النسخة؛ يعود ملف مشفر |

مثال خطوات:

```json
{
  "project_id": "…",
  "name": "استخراج ثم بصمة",
  "steps": [
    {"tool": "ioc", "evidence_id": "…", "expect": {"ipv4.0": "192.0.2.1"}},
    {"tool": "hashes", "from_step": 0}
  ]
}
```

الخطوة تحتوي دليلًا أو from_step لنتيجة سابقة، دون حقول أو أدوات غير مسجلة. expect يطابق حقول **result** باستخدام مسارات بنقاط، وبمساواة قيمة ونوع JSON؛ لا لغة eval أو تعبيرات برمجية. غيابه يعطي `not_evaluated`؛ فشله يعطي `failed` ويحفظ النتيجة ويوقف السلسلة. روابط المصدر والبصمات وإصدار المحرك وبصمة كوده تحفظ في الأدلة الناتجة. الاستكمال اليدوي المتحقق متاح لهذه الواجهة الخطية؛ تتاح الفروع عبر واجهات خططDAGالموثقة أدناه، ولا تنفيذ متوازٍ.

## واجهات الصيانة والتطوير — 0.5

- `GET /api/maintenance`: آخر10تقارير و100طلب تطوير، بعد تسجيل الدخول.
- `POST /api/maintenance`: `{ "operation": "check" | "repair", "section_id": null | "01" }`. جسم مضبوط الحقول، CSRF، وقفل المهام الثقيلة. تُحفظ نتيجة الفشل أيضًا، ولا تعني استجابةHTTP200اجتياز الفحص: افحص `passed` و`checks`.
- `POST /api/development`: لإنشاء طلب `{ "section_id": "01", "title": "..." }` أو تحديثه `{ "id": "...", "status": "open" | "in_progress" | "done" }`. الحالة يحددها المالك ولا تشغّل كودًا.
- لا توجد واجهة لتثبيت كود أو تنفيذ أوامر تحديث؛ ترقية البرنامج محلية عبر `scripts/release.sh`، وتحديث المعرفة عبر واجهته القائمة فقط.

## تعديل 0.7

ألغى المالك فريق الوكلاء داخل المنتج. أزيلت مسارات `/api/agents` و`/api/agents/roles` و`/api/agents/start`؛ ليست جزءًا من العقد الحالي. تبقى `/api/chat` للمحادثة المحلية الاختيارية دون تفويض تنفيذ.

تقارير الصيانة تتضمن `repair_transaction` لحالة التحقق والتطبيق والرجوع، و`persistence` لتأكيد حفظ التقرير أو تعذره. إذا تعذر إثبات هوية ملفات التخزين يتوقف الإصلاح وحفظ السجل، بدل الكتابة إلى مسار بديل غير موثوق.

## مركز جودة الأدوات — 0.9

جميع المسارات التالية تتطلب جلسة المالك، وعملياتPOSTتتطلبCSRFوتستخدم قفل المهام الثقيلة:

| العملية | المسار | المدخلات / المخرجات |
|---|---|---|
| GET | `/api/quality/catalog` | الحالات المرفقة وبصمات المجموعة والمحرك وحدود التنفيذ |
| GET | `/api/quality/history` | ملخص آخر20تشغيلًا |
| GET | `/api/quality?run=ID` | التقرير المحفوظ والحالات والعدادات |
| POST | `/api/quality/start` | `{}` فقط؛ بدء مجموعة الاختبارات الثابتة |
| POST | `/api/quality/advance` | `{"run_id":"…"}` فقط؛ دفعة محدودة واستكمال التقدم |
| POST | `/api/quality/compare` | `{"left_id":"…","right_id":"…"}`؛ تشغيلان مكتملان للمجموعة نفسها |

استجابةHTTP200لا تعني اجتياز الجودة. افحص`status`و`passed`و`counts`؛ التشغيل المكتمل قد يحتوي حالات فاشلة. مقارنة النتائج لا تعيد تشغيل المحللات. لا تقبل الواجهات مسار ملف أو مدخل اختبار أو توقعات أو كودًا يحدده العميل. راجع[دليل الجودة](Quality-Center.md).

## الأحداث والكشف والتغطية — 0.10

جميع المسارات التالية تتطلب حساب المالك. كلPOSTمضبوط الحقول ويتطلبCSRFوقفل المهام الثقيلة، ويستخدمGETالتغطية القفل نفسه لأنه يعيد التحقق بعامل محدود.

| العملية | المسار | المدخلات / المخرجات |
|---|---|---|
| GET | `/api/events/adapters` | `{adapters:[{id,title,description,example_content}]}`، أمثلة اصطناعية |
| POST | `/api/events/normalize` | `project_id,evidence_id,adapter`؛ دليل أصلي من المشروع، والرد`{evidence,report}` |
| GET | `/api/detection/library?project=ID` | القواعد المدمجة وأحدث مراجعات المالك وأمثلة بتسميات مرجعية وحدود المكتبة |
| POST | `/api/detection/save` | `project_id,rule`؛ قاعدة بستة حقول محددة ومراجعة مستقلة |
| POST | `/api/detection/test` | `project_id,evidence_id,rule_ids`؛ مصدر أحداث وتسميات اختيارية من الملف نفسه، والرد`{evidence,report}` |
| GET | `/api/coverage?project=ID` | الأصول والتقييمات والفجوات والملخص والعقد والعلاقات |
| POST | `/api/coverage/asset` | `project_id,name,kind`؛ نوع الأصل`host/service/data/network` |
| POST | `/api/coverage/assessment` | `project_id,asset_id,threat,control,evidence_id`؛ الحالة مشتقة من تحقق الخادم |
| POST | `/api/coverage/remove` | `project_id,assessment_id`؛ إزالة الارتباط فقط مع إبقاء الأدلة |

محولات الأحداث تدعم الصيغ الموثقة فقط، بحد1MiBو1000سجل، وترفض الدفعة كاملة عند خطأ. `result.failed`هو عدد أحداث ذات`outcome:failure`؛ ليس عدد سجلات معطوبة. يحتفظ تقرير`was.event-evidence/1`بمعرف وبصمة الأصل وبصمة المحول والنتائج، ويُعاد تشغيل المحول للتحقق عند استخدامه في اختبارات الكشف.

غياب التسميات المرجعية في اختبار الكشف يعطي`not_evaluated`، ولا يكفي وجود مطابقات لإعلان النجاح. للتغطية المدعومة يلزم اختبار صحيح بفرص كشف موجبة لكل قاعدة، ومطابقة المصادر والقواعد والمحرك وإعادة التنفيذ. الأمثلة وتسمياتها اصطناعية؛ لا تثبت أن أصلًا حقيقيًا محمي. يعيد عرض التغطية التحقق من أول3تقارير كشف مختلفة ضمن الميزانيات الموثقة، وما يتجاوزها`unverified`؛ لا يوجد استكمال مرحلي لهذا العرض. راجع[المحولات](Event-Adapters.md) و[مكتبة الكشف](Detection-Library.md) و[التغطية](Defense-Coverage.md).

## خطط التحليل والقوالب والتغطية الشاملة وتقارير المشروع — 0.11

جميع المسارات محمية بجلسة المالك. كلPOSTيتطلبCSRFوقفل المهام الثقيلة؛ كذلكGETللحالة التفصيلية للخطة لأنه يعيد قراءة إثباتها. ينشر الخادم الاستجابة بعد تحرير القفل. أجسامPOSTمضبوطة الحقول دون أوامر أو صلاحيات أو مسارات ملفات.

| العملية | المسار | الجسم أو المرشحات |
|---|---|---|
| GET | `/api/plans/templates` | `project`؛ مكتبة القوالب ومراجعات المالك والأمثلة |
| POST | `/api/plans/templates/save` | `project_id,template` |
| POST | `/api/plans/templates/instantiate` | `project_id,template_id,bindings`؛ يحفظ إثبات الربط ولا يبدأ التنفيذ |
| POST | `/api/plans/start` | `project_id,plan` و`instantiation_id` اختياري يطابق الخطة المحفوظة تمامًا |
| POST | `/api/plans/advance` | `project_id,run_id`؛ حتى عقدتين متتابعتين |
| POST | `/api/plans/pause` و`/api/plans/resume` | `project_id,run_id`؛ التحكم بين الدفعات |
| GET | `/api/plans/history` | `project`؛ ملخصات تاريخية مسجلة فقط |
| GET | `/api/plans` | `project,run`؛ تقرير يعيد التحقق من المصادر والنتائج |
| POST | `/api/coverage/scans/start` | `project_id`؛ لقطة لجميع التقييمات الحالية |
| POST | `/api/coverage/scans/advance` | `project_id,scan_id`؛ مرحلة التقييمات ثم مرحلة ملفات الإثبات |
| GET | `/api/coverage/scans/history` | `project` |
| GET | `/api/coverage/scans` | `project,scan`؛ لقطة تاريخية محفوظة وليست إعادة تحقق حي |
| POST | `/api/case-reports/build` | `project_id,title,evidence_ids,plan_run_ids,coverage_scan_id`؛ الأخير معرف أو`null` |
| POST | `/api/case-reports/verify` | `project_id,report_id`؛ مطابقة بايتات المراجع والسجلات |
| GET | `/api/case-reports/history` | `project`؛ آخر التقارير المحفوظة |
| GET | `/api/case-reports` | `project,id,format=json|html`؛ HTMLمرفق تنزيل ثابت بلاJavaScript |

الخطة`was.plan/1`رسم اعتماد بلا دورات حتى20عقدة؛ إدخال عقدة من أخرى هو تقرير النتيجة كاملًا. شروط`when`تختار نجاحًا أو فشلًا صريحًا، ولا توجد تعبيرات برمجية. العقدة المتخطاة ليست نجاحًا، ونجاح تشغيل بلا`expect`لا يعني تقييم جودة مرجعي. الإيقاف لا يقاطع العامل الجاري، والاستكمال لا يعمل في الخلفية. راجع[دليل الخطط](Workflow-Plans.md).

يثبت`plan-instantiation`مصدر القالب ومراجعته وربط الأدلة. تعديل الخطة يلغي انطباق الإثبات القديم؛ يمكن بدء الخطة المعدلة دون نسبة كاذبة إلى القالب. تبقى مراجعات المالك التاريخية صالحة إذا طابقت أدلتها، ولا يعني ذلك استخدام أحدث مراجعة. راجع[القوالب](Plan-Templates.md).

اكتمال فحص التغطية يتطلب انتهاء مرحلتي التقييمات وإعادة قراءة الإثبات. `complete`ليس إعلان حماية، و`all_supported`إن ظهر يخص التقييمات الاصطناعية المحفوظة فقط. `current_validity:snapshot_only`ولا تدعى لقطة ذرية أو حماية حالية. راجع[الفحص الشامل](Coverage-Scans.md).

تقارير المشروع لا تنسخ محتوى الأدلة الأصلية، وتجمع حتى50دليلًا و5خطط ولقطة تغطية مكتملة ضمن الميزانيات. نجاح فحص مراجعها ليس إعادة تنفيذ لجميع التحليلات أو اعتمادًا قضائيًا. راجع[دليل التقارير](Project-Reports.md).

## مسارات التعلم ومراجعة بيانات الإضافات — 0.12

جميع المسارات تتطلب جلسة المالك. عملياتPOSTتتطلبCSRFوحقولًا مطابقة للجدول. قراءة تقدم التعلم وتاريخه وسجل الإضافات تشترك مع الكتابة في قفل المهام الثقيلة؛ يُحرر القفل قبل نشر الرد. فهرس المنهج ثابت ولا يقرأ بيانات مشروع.

| العملية | المسار | الجسم أو المرشحات |
|---|---|---|
| GET | `/api/curriculum` | المنهج والدروس والمسارات الخمسة والحدود |
| GET | `/api/curriculum/progress` | `project`؛ حالات الدروس والتقدم من التقييمات المتحققة |
| GET | `/api/curriculum/history` | `project`؛ تاريخ المحاولات ومعرفات أدلتها وصلاحيتها الحالية |
| POST | `/api/curriculum/attempt` | `project_id,path_id,lesson_id,answer_index`؛ إجابة صحيحة للدروس السابقة شرط للمحاولة |
| GET | `/api/plugins` | `project`؛ عناصر السجل وتاريخها والرسم والملاحظات وبصمة التصدير |
| POST | `/api/plugins/register` | `project_id,evidence_id`؛ بيانJSONأصلي داخل المشروع حتى16KiB |
| POST | `/api/plugins/transition` | `project_id,plugin_id,action,reason`؛ القرار`approve/disable/revoke`وسبب غير فارغ |

يرجع تقييم المسار`{result,evidence,progress}`، ويسجل`was.learning-assessment/1`نسخة الدرس والعينة الاصطناعية والتحليل وبصمات المنهج والمحرك. يتغير التقدم عند تغير صلاحية المحاولات؛ النجاح في هذه التقييمات المحددة ليس شهادة إتقان. الحد200محاولة للمشروع و20لكل درس و32KiBللتقييم، دون حذف تلقائي. لا تقبل الواجهة أهدافًا أو أوامر أو مداخل تمارين حرة. تبقى`/api/learning/attempt`القديمة مستقلة ولا تُحسب تلقائيًا في المسارات. راجع[دليل المسارات](Curriculum.md).

يرجع تسجيل بيان الإضافة أو قرارها`{evidence,item}`. يضم عرض`was.plugin-registry/1`قائمة`items`ورسم`graph`و`digest`؛ لكل عنصر`state/effective_state/issues/history`. الحالة`approved`قرار مراجعة بيانات فقط. قد تصبح الحالة الفعلية`blocked`عند تعطل اعتمادية أو ظهور ملاحظة مانعة، مع بقاء القرار التاريخي. الإصدار الجديد يجب أن يكون أعلى، ويعود إلى`pending`حتى تتم مراجعته. لا تنزيل لرابط المصدر أو تثبيت أو تنفيذ كود أو توقيع ناشر. راجع[دليل سجل الإضافات](Plugin-Registry.md).

## التحليل التقني للملفات — 0.13

تتضمن `GET /api/bootstrap` الأدوات `pcap/certificate/supply-chain/supply-chain-diff` وعيناتها والصيغ وحدود المدخل. تُرفع الملفات عبر `POST /api/upload`، ثم تحلل عبر `POST /api/run` الحالي؛ لا مسار جديد لتشغيل أوامر أو الاتصال بهدف:

```json
{
  "project_id":"…",
  "name":"فحص تسجيل شبكة خاص",
  "steps":[{"tool":"pcap","evidence_id":"…","expect":{"packet_count":1}}]
}
```

تقبل `pcap` بايتاتclassic PCAPأوJSONبحقل`pcap_base64`فقط. تقبل `certificate` بايتاتPEM/DERأوJSONبحقل`certificates_pem`وحقل`validation_time`اختياري ذي إزاحة صريحة. تقبل `supply-chain` مستندSPDX2.3أوCycloneDX1.5/1.6مدعومًا، وتقبل `supply-chain-diff` حقلَي`left/right`فقط، كل منهما مستندSBOMمدعوم. المقارنة للحقول الموحدة الموثقة؛ بصمتا الطرفين لترميزJSONالقياسي للمستندين المضمنين، وبصمة الحزمة للأصل المرفوع كاملًا.

يمكن استخدام هذه المعرّفات في عقد خطط`/api/plans/start`أيضًا. لا تعني حالة تنفيذ`succeeded`تقييم جودة دون توقعات مرجعية، ولا ثقة بشهادة أو خلوSBOMمن الثغرات. تحميل نتيجة تاريخية يتحقق من ملفات الدليل وبصماتها ولا يعيد تشغيل المحلل الحالي. لا توجد واجهة التقاط حي أو تثبيت حزم أو تنزيل شهادات.

يتضمن `GET /api/events/adapters` المحول الرابع`windows-xml`، ويُستخدم عبر`POST /api/events/normalize`القائم بالجسم`{project_id,evidence_id,adapter:"windows-xml"}`. لا يقبل واجهةEVTXأو مسار ملف من المضيف. راجع[الصيغ والحدود التقنية](Technical-Analysis.md) و[عقدXML](Event-Adapters.md) و[تقرير التحقق](Validation-0.13.md).
