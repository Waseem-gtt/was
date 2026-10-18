"""Owner-only educational material and deterministic exercises on synthetic data."""
import hashlib
from pathlib import Path
from . import tools
from .store import Problem, encode

# Each topic keeps its own risk model, defensive response and source. Sources are
# reference links, not continuously fetched feeds or claims of certification.
TOPICS = [
    ("المؤشرات والمصادر", "التعامل مع رابط مجهول", "المؤشر قرينة تحتاج سياقًا؛ وجود عنوان IP لا يثبت نشاطًا ضارًا.",
     "ربط المصدر والتوقيت والثقة قبل الحظر", "تحويل كل مؤشر إلى حكم قطعي", "فتح الروابط المجهولة لتنفيذها", "ioc",
     "MITRE ATT&CK", "https://attack.mitre.org/"),
    ("تطبيقات الويب وAPI", "تمييز الملاحظة عن إثبات الثغرة", "غياب رأس حماية يحتاج تقييم سياق، ولا يمنح إذنًا لاختبار موقع آخر.",
     "توثيق الملاحظة وإعادة التحقق ضمن نطاق مصرح", "اعتبار كل رأس مفقود اختراقًا مثبتًا", "تجربة كل موقع دون إذن", "http",
     "OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/"),
    ("الكشف والاستجابة", "تحليل فشل الدخول", "فشل دخول واحد قد يكون خطأ مستخدم؛ تربط الأحداث بزمن وهوية قبل الاستجابة.",
     "مقارنة الأحداث بالسياق وتجربة قاعدة على بيانات مرجعية", "حذف السجل لتقليل الإنذارات", "حظر الجميع بسبب حدث واحد", "events",
     "Sigma", "https://sigmahq.io/docs/"),
    ("التحقيق الرقمي", "التحقق من سلامة الأصل", "العمل على نسخة مع بصمة موثقة يتيح كشف تغير الأصل وإعادة المراجعة.",
     "حفظ الأصل والتحقق من SHA256 قبل استخدام النسخة", "تحرير الأصل ثم حساب بصمته كأنه لم يتغير", "الاكتفاء باسم الملف", "hashes",
     "NIST CFTT", "https://www.nist.gov/itl/ssd/software-quality-group/computer-forensics-tool-testing-program-cftt"),
    ("البرامج والهندسة العكسية", "فحص ملف غير موثوق", "تحليل الرأس والسلاسل ساكنًا لا يتطلب تنفيذ العينة ولا يثبت سلامة سلوكها.",
     "البدء بالتحليل الساكن وحفظ حدود الاستنتاج", "تشغيل العينة على جهاز المالك", "اعتبار السلاسل النصية برهانًا على السلوك", "executable",
     "Ghidra", "https://ghidra-sre.org/"),
    ("الشبكات والاتصالات", "تفسير حجم تدفق", "التدفقات بيانات وصفية؛ الحجم الكبير قد يكون نشاطًا مشروعًا ولا يكشف المحتوى وحده.",
     "مراجعة البروتوكول والوجهة والزمن مع خط أساس", "اعتبار كل اتصال TLS ضارًا", "تخمين المحتوى من العدد فقط", "flows",
     "Wireshark", "https://www.wireshark.org/docs/"),
    ("الأنظمة والهوية", "مراجعة حساب إداري", "تزداد مخاطر الحسابات الإدارية دون MFA، وتطبق أقل صلاحية مع استرداد موثق.",
     "تقليل الامتياز وتفعيل MFA ومراجعة دورة الحساب", "مشاركة كلمة مرور المدير", "إلغاء التدقيق الإداري", "identity",
     "NIST Digital Identity", "https://pages.nist.gov/800-63-4/"),
    ("السحابة والحاويات", "تمييز إعداد حاوية خطر", "privileged وشبكة المضيف يوسّعان سطح الوصول؛ مراجعة JSON لا تثبت عزل التنفيذ.",
     "تقليل الصلاحيات والتحقق من سياسة التنفيذ فعليًا", "اعتبار اسم الحاوية حد عزل", "تفعيل privileged لكل خدمة", "container",
     "Kubernetes Security", "https://kubernetes.io/docs/concepts/security/"),
    ("البرمجيات وسلسلة التوريد", "قراءة جرد مكونات", "SBOM يسجل المكونات؛ يلزم ربط الإصدارات والتنبيهات والسياق قبل تقرير التأثر.",
     "توثيق المكون والإصدار والترخيص ومراجعة التنبيهات", "اعتبار وجود SBOM دليل غياب ثغرات", "تثبيت أي تحديث دون تحقق", "sbom",
     "CycloneDX", "https://cyclonedx.org/specification/overview/"),
    ("المحللات وأبحاث البرمجيات", "اختبار طول سجل ثنائي", "المدخل المبتور يجب أن يفشل بوضوح دون قراءة خارج حدوده؛ التجربة هنا بيانات ثابتة.",
     "التحقق من الطول والحدود قبل قراءة القيمة", "الثقة بالطول المقدم دون فحص", "إخفاء الاستثناء مع إعلان نجاح", "tlv",
     "LLVM libFuzzer", "https://llvm.org/docs/LibFuzzer.html"),
    ("التشفير والبروتوكولات", "فهم حدود جرد التشفير", "اسم خوارزمية في نص ليس اختبارًا للمفاتيح أو تفاوض البروتوكول.",
     "توثيق الخوارزمية ثم اختبار الإعداد والتوافق بأداة مناسبة", "اعتبار اسم AES ضمان أمن كامل", "نشر مفاتيح خاصة للتجربة", "crypto",
     "OpenSSL", "https://docs.openssl.org/"),
    ("العتاد والبرامج الثابتة", "تفسير entropy", "ارتفاع entropy قد يدل على ضغط أو تشفير، ولا يثبت برمجية ضارة بمفرده.",
     "ربط التواقيع والبنية والمصدر والتحقق من سلامة التحديث", "اعتبار كل ملف عالي entropy ضارًا", "تفليش جهاز حقيقي دون استعادة", "firmware",
     "UEFI", "https://uefi.org/specifications"),
    ("الأنظمة الصناعية وIoT", "اختبار نموذج حراري", "نموذج حسابي مبسط يوضح أثر التغذية الراجعة، ولا يثبت سلامة مصنع فعلي.",
     "قياس النموذج وحدوده قبل أي تكامل مادي مصرح", "تطبيق قيم النموذج على مصنع مباشرة", "اعتبار منحنى واحد شهادة سلامة", "twin",
     "NIST OT Security", "https://csrc.nist.gov/pubs/sp/800/82/r3/final"),
    ("الإشارات والاستشعار", "تفسير قمة طيفية", "DFT يصف عينات مقدمة؛ تحديد القمة لا يحدد جهازًا أو نيةً أو تصريح بث.",
     "توثيق العينات ومعدلها وحدود الدقة", "استنتاج هوية جهاز من القمة وحدها", "البث على ترددات فعلية دون تصريح", "spectrum",
     "GNU Radio", "https://wiki.gnuradio.org/index.php/Main_Page"),
    ("الطيران والمسيّرات", "اكتشاف فجوة تسلسل", "فجوة القياسات قد تنتج عن فقد أو إعادة ترتيب؛ تحتاج سياقًا ولا تبرر تحكمًا حيًا.",
     "حفظ تسلسل القياسات ومراجعة الفقد والسياق", "اعتبار كل فجوة هجومًا مثبتًا", "إرسال أوامر إلى طائرة حقيقية", "telemetry",
     "MAVLink", "https://mavlink.io/en/"),
    ("الروبوتات والمركبات", "قراءة CAN من تسجيل", "قراءة candump لا تتطلب إرسال إطارات، ولا تكشف معنى كل إشارة دون مواصفة.",
     "تحليل التسجيل والتحقق من مواصفة الإشارات", "إرسال إطارات إلى مركبة غير مصرح بها", "تخمين وظائف السلامة من المعرف", "can",
     "Linux SocketCAN", "https://docs.kernel.org/networking/can.html"),
    ("الفضاء", "مراجعة رأس حزمة", "CCSDS يحدد بنية رسائل؛ قراءة الرأس ليست اتصالًا بقمر أو تحليلًا لكل حمولة.",
     "التحقق من طول الحزمة والحقول وتوثيق حدود التحليل", "اعتبار الرأس تحققًا من كل الحمولة", "محاولة اتصال فضائي حقيقي", "ccsds",
     "CCSDS", "https://public.ccsds.org/Publications/default.aspx"),
    ("الذكاء الاصطناعي", "مراجعة استنتاج مولد", "مطابقة مقتطف لمصدره لا تثبت أن الاستنتاج صحيح؛ النص غير الموثوق لا يمنح صلاحيات.",
     "التحقق من المصدر والمقتطف والمعنى مستقلًا", "تنفيذ كل أمر يكتبه النموذج", "اعتبار اتفاق نموذجين حقيقة مؤكدة", "ai-audit",
     "OWASP GenAI Security", "https://genai.owasp.org/"),
    ("الحوكمة والخصوصية", "إعداد نسخة للمشاركة", "تنقيح نسخة يترك الأصل سليمًا، لكن الكاشف قد يفوّت أسرارًا فتجب مراجعة بشرية.",
     "مراجعة النسخة المنقحة وتحديد غرض ومتلقي المشاركة", "نشر الأصل لأنه خضع لكاشف أسرار", "تعديل الأصل وإخفاء أثر التغيير", "privacy",
     "NIST Privacy Framework", "https://www.nist.gov/privacy-framework"),
    ("إدارة المنظومة", "تقييم بيان إضافة", "البيان والترخيص والصلاحيات تساعد المراجعة؛ لا تشغّل كود الإضافة قبل التحقق والعزل.",
     "مراجعة المصدر والترخيص والصلاحيات والاختبار قبل التفعيل", "تنفيذ أي إضافة تحمل وصفًا جذابًا", "اعتبار البيان توقيعًا موثوقًا", "manifest",
     "The Update Framework", "https://theupdateframework.io/"),
]


def lessons():
    result = []
    for i, row in enumerate(TOPICS):
        topic, title, concept, defense, wrong1, wrong2, tool, source, url = row
        choices = [defense, wrong1, wrong2]
        shift = i % 3
        choices = choices[shift:] + choices[:shift]
        result.append({"id": f"lesson.{i + 1:02}", "section_id": f"{i + 1:02}", "platform_id": f"platform.22.{i + 1:02}",
                       "topic": topic, "title": title, "concept": concept, "defense": defense,
                       "question": "ما الإجراء الأنسب في هذا السيناريو التعليمي؟", "choices": choices,
                       "tool_id": tool, "source": {"name": source, "url": url},
                       "scope": "بيانات اصطناعية مسجلة؛ لا أهداف أو أوامر أو اتصالات خارجية",
                       "assessment": "فهم مفهوم محدد؛ لا شهادة إتقان أو تصريح اختبار"})
    return result


def attempt(store, project_id, lesson_id, answer):
    store.project(project_id)
    lesson = next((l for l in lessons() if l["id"] == lesson_id), None)
    if lesson is None:
        raise Problem("الدرس غير موجود", 404)
    if type(answer) is not int or not 0 <= answer < len(lesson["choices"]):
        raise Problem("اختر إجابة من الخيارات المسجلة")
    tool = next(t for t in tools.describe() if t["id"] == lesson["tool_id"])
    data = tool["sample"].encode() if tool["sample"] is not None else (
        b"\x01\x02AB" if tool["id"] == "tlv" else b"\x00\x01\x00\x02\x00\x00A")
    # Exercise inputs and analyzer are server-selected. Uploaded commands/targets
    # cannot be substituted for the synthetic input.
    result = tools.analyze(tool["id"], data)
    correct = lesson["choices"][answer] == lesson["defense"]
    output = {"lesson_id": lesson_id, "answer_index": answer, "correct": correct,
              "explanation": lesson["concept"] + " " + lesson["defense"], "tool": tool["id"],
              "synthetic": True, "input_base64": __import__("base64").b64encode(data).decode(),
              "input_sha256": hashlib.sha256(data).hexdigest(),
              "analyzer_sha256": hashlib.sha256(Path(tools.__file__).read_bytes()).hexdigest(),
              "analysis": result, "source": lesson["source"], "assessment": lesson["assessment"]}
    record = store.add_evidence(project_id, lesson_id + "-attempt.json", encode(output).encode(), "learning")
    with store.lock, store.db:
        store.audit("learning.attempt", {"project": project_id, "lesson": lesson_id, "correct": correct, "evidence": record["id"]})
    return {"result": output, "evidence": record}
