# واجهة API المحلية — was/1

الخادم `127.0.0.1:8080`. JSON وUTF-8؛ الخطأ `{ "error": "…" }` مع HTTP مناسب. جميع المسارات الخاصة تحتاج cookie `was_session`، وPOST بعد المصادقة يحتاج `X-CSRF-Token`. ترجع عمليات الإعداد والدخول CSRF، ويعيده bootstrap للجلسة الحالية. لا تضع كلمة المرور أو CSRF في URL أو Git.

| العملية | المسار | المدخلات / المخرجات |
|---|---|---|
| GET | `/healthz` | سلامة الخدمة وقراءة SQLite؛ عام محليًا |
| GET | `/api/status` | نسخة التطبيق وهل أنشئ المالك؛ عام محليًا |
| POST | `/api/setup` | `password`، مرة واحدة |
| POST | `/api/login` | `password` |
| POST | `/api/logout` | `{}`؛ إلغاء الجلسة |
| GET | `/api/bootstrap` | الأقسام والأدوات والمشاريع والموارد |
| POST | `/api/projects` | `name,description` |
| GET | `/api/project?id=…` | مشروع وأدلته ومهامه وعلاقاته |
| POST | `/api/upload` | `project_id,name,base64`؛ حد الملف16MiB |
| GET | `/api/evidence?project=…&id=…` | تنزيل بعد تحقق SHA256؛ ترويسة `X-Evidence-SHA256` |
| POST | `/api/run` | `project_id,name,steps` |
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
