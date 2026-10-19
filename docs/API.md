# واجهة API المحلية — was/1

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

الخطوة تحتوي دليلًا أو from_step لنتيجة سابقة، دون حقول أو أدوات غير مسجلة. expect يطابق حقول **result** باستخدام مسارات بنقاط، وبمساواة قيمة ونوع JSON؛ لا لغة eval أو تعبيرات برمجية. غيابه يعطي `not_evaluated`؛ فشله يعطي `failed` ويحفظ النتيجة ويوقف السلسلة. روابط المصدر والبصمات وإصدار المحرك وبصمة كوده تحفظ في الأدلة الناتجة. لا استكمال/تفرع/توازٍ في هذا الإصدار.
# واجهات الصيانة والتطوير — 0.5

- `GET /api/maintenance`: آخر10تقارير و100طلب تطوير، بعد تسجيل الدخول.
- `POST /api/maintenance`: `{ "operation": "check" | "repair", "section_id": null | "01" }`. جسم مضبوط الحقول، CSRF، وقفل المهام الثقيلة. تُحفظ نتيجة الفشل أيضًا، ولا تعني استجابةHTTP200اجتياز الفحص: افحص `passed` و`checks`.
- `POST /api/development`: لإنشاء طلب `{ "section_id": "01", "title": "..." }` أو تحديثه `{ "id": "...", "status": "open" | "in_progress" | "done" }`. الحالة يحددها المالك ولا تشغّل كودًا.
- لا توجد واجهة لتثبيت كود أو تنفيذ أوامر تحديث؛ ترقية البرنامج محلية عبر `scripts/release.sh`، وتحديث المعرفة عبر واجهته القائمة فقط.
