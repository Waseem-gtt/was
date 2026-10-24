#!/usr/bin/env python3
"""Preserve and index every source byte; never infer implementation from history."""
import hashlib
import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs/Requirements-Source.md"
OUTPUT = ROOT / "cyber_platform/requirements.json"

# The owner requires completion of every related section, including later owner additions.
CATALOG_SECTIONS = json.loads((ROOT / "cyber_platform/catalog.json").read_text())
OWNER_SECTION_REVIEWS = {"SECTION." + section["id"]: {"id": "SECTION." + section["id"], "title": section["name"], "status": "partial", "origin": "later_owner_request"} for section in CATALOG_SECTIONS[20:]}
COMPLETION_DEPENDENCIES = {
    "BASE.13": tuple("SECTION." + section["id"] for section in CATALOG_SECTIONS),
    "E02": tuple("SECTION." + section["id"] for section in CATALOG_SECTIONS),
    "F01": ("SECTION.20",), "F02": ("SECTION.20",),
    "F03": ("SECTION.03",), "F04": ("SECTION.03",),
    "F05": ("SECTION.20",), "F06": ("SECTION.01",),
}


def apply_completion_policy(records):
    by_id = {**OWNER_SECTION_REVIEWS, **{record["id"]: record for record in records}}
    for record in records:
        dependencies = COMPLETION_DEPENDENCIES.get(record["id"], ())
        if not dependencies:
            continue
        record["completion_dependencies"] = list(dependencies)
        record["functional_status"] = "verified" if record["status"] == "available" else record["status"]
        missing = [key for key in dependencies if key not in by_id or by_id[key]["status"] != "available"]
        record["open_completion_dependencies"] = missing
        if record["status"] == "available" and missing:
            record["status"] = "partial"
            record["scope"] = record["scope"].removeprefix("مكتمل: ") + "؛ الدفعة غير مكتملة حتى إكمال الأقسام المرتبطة: " + "، ".join(missing)
    return records


# Status is a reviewed statement about this checkout, not a source-document claim.
REVIEWS = {
    "F01": ("partial", "سجل بيانات وحزمWasmموقعة بثقة مالك صريحة واختبارات معزولة وتثبيت وتفعيل وإيقاف واستبدال واستعادة إصدار وتشغيل بمدخل مختار وأدلة محفوظة؛ قسم إدارة المنظومة غير مكتمل، وتشغيل أدواتPythonأوShellعامة خارج عقدWasmغير متاح", "cyber_platform/plugin_registry.py", "cyber_platform/plugin_installations.py", "cyber_platform/plugin_wasm.py", "cyber_platform/plugin_package.py", "tests/test_plugin_installations.py", "tests/test_plugin_install_http.py", "tests/test_plugin_wasm.py", "docs/Plugin-Installations.md"),
    "F02": ("partial", "حصة أدلة واحتياطي قرص وعامل تحليل بحدود ذاكرة ومعالج ووقت؛ لا حصة لكل نظام الضيف", "cyber_platform/store.py", "cyber_platform/worker.py", "tests/test_security.py"),
    "F03": ("available", "مكتمل: محولات الأحداث الأربعة مع قاموس حقول ومخططJSONبإصدار وبصمة، وحفظ الأصل وترتيبه ودقة توقيته، وقياس فجوات الجودة والتحقق قبل الحفظ وأثناء الإعادة؛ OCSFمرجع مرشح لا شرط مطابقة كاملة", "cyber_platform/event_adapters.py", "cyber_platform/event_schema.py", "cyber_platform/event_ingest.py", "tests/test_event_schema.py", "docs/Event-Schema.md"),
    "F04": ("available", "مكتمل: مكتبة قواعد بمصدر وترخيص وإصدارات، وعينات موجبة وسالبة مرتبطة بالإصدار، وتغطية لجميع القواعد الحالية وقياساتFP/FNوإعادة اختبار فعلية وتقارير ثابتة؛ Sigmaمرجع مرشح ولا يُدعى جمع حي", "cyber_platform/detection.py", "cyber_platform/detection_acceptance.py", "tests/test_detection_acceptance.py", "docs/Rule-Acceptance.md"),
    "F05": ("partial", "ترقية لينكس متحققة مع بيان Ed25519اختياري وثقة مثبتة وتسلسل مانع للتراجع وانتهاء صلاحية؛ لا TUFأو تحديث آلي أو مفتاح ناشر مهيأ افتراضيًا", "scripts/release.sh", "cyber_platform/signed_release.py", "cyber_platform/release_admin.py", "docs/Signed-Releases.md"),
    "F06": ("available", "مكتمل: أصل وبرنامج وثغرة وحدث ودليل وتجربة مع مراجع ملفات فعلية، ومصدر وبصمة وثقة ووقت ملاحظة وصلاحية وتعارض؛ خريطة وجداول وتفاصيل وبحث وتصدير بعد تفويض المالك والتحقق من السجلات والمصادر، مع حفظ ذري واستعادة مختبرة", "cyber_platform/knowledge_graph.py", "cyber_platform/static/knowledge_graph.js", "tests/test_knowledge_graph.py", "tests/test_graph_http.py", "tests/browser_knowledge_graph.py", "docs/Knowledge-Graph.md"),
    "E01": ("blocked", "الورشة ترفض عند غياب namespaces؛ لا تنفيذ معزول ناجح على هذا المضيف", "cyber_platform/sandbox.py", "docs/Validation.md"),
    "E02": ("available", "مكتمل: هويات ومساحات مستقلة لـ22قسمًا و109منصات، بمعرف ثابت وعنوان ووصف وأيقونة ولون وصفحة وأدوات وخريطة وإعدادات محفوظة ومدققة وخدمات مشتركة؛ اكتمال هوية المساحة لا يعني اكتمال تقنيات التخصص", "cyber_platform/workspaces.py", "cyber_platform/static/workspaces.js", "tests/test_workspaces.py", "tests/browser_workspaces.py", "docs/Workspaces.md"),
    "E03": ("partial", "خريطة افتتاحية بأسهم وبحث وقائمة بديلة من القسم إلى المنصة والأداة ودليلها، وخريطة أدلة وخمسة مسارات تغطي20تمرين فهم ثابتًا بمتطلبات سابقة وتقدم محفوظ متحقق؛ لا إتقان كل التقنيات أو تغطية جميع الأدوات", "cyber_platform/curriculum.py", "tests/test_curriculum.py", "cyber_platform/static/launchpad.js", "tests/browser_launchpad.py", "docs/Requirements-Review-0.15.md", "docs/Curriculum.md"),
    "E04": ("partial", "اكتمل استيراد ملفات KEV وبحثها دون إنترنت مع إثبات مصدر وحفظ آخر فهرس صالح؛ ويتوفر جلب CISA وجدولته؛ تركيب الأدوات وتجديد جميع التقنيات متبقيان", "cyber_platform/knowledge.py", "cyber_platform/knowledge_files.py", "tests/test_knowledge_files.py", "docs/Knowledge-Files.md"),
    "E05": ("partial", "مركز صيانة لجميع الأقسام وفحص بيانات وعينات أدوات وإصلاح صلاحيات وسجل طلبات تطوير وترقية يدوية متحققة؛ لا إصلاح عام مستقل أو ضمان لعقود", "cyber_platform/maintenance.py", "docs/Maintenance.md"),
    "N01": ("partial", "خطط DAG محفوظة حتى20عقدة بفروع نجاح وفشل وإيقاف واستكمال يدوي وبصمات؛ لا توازٍ أو تشغيل خلفي أو إعادة تنفيذ تلقائية", "cyber_platform/plans.py", "docs/Workflow-Plans.md"),
    "N02": ("superseded", "طبقة المختبرات ملغاة؛ أضيفت8قوالب بيانات لخطط التحليل بمراجعات مالك وإثبات ربط، دون مولد منصات أو إضافات كود عامة", "docs/Scope-Update-0.2.md", "cyber_platform/plan_templates.py", "docs/Plan-Templates.md"),
    "N03": ("superseded", "ألغى المالك فريق الوكلاء داخل المنتج؛ مساعدو تطوير المشروع خارج التطبيق ولا يمثلون قدرة تشغيل داخله", "docs/Scope-Update-0.7.md"),
    "N04": ("partial", "حفظ خطط ونتائج وتقارير ومقارنات كاملة للجرد وHARوKubernetesوSARIFبحقولها الموثقة وتكرارها؛ لا مساواة المحتوى المحجوب أو كل بايتات المصدر أو حالة محاكاة أو جودة عامة", "cyber_platform/plans.py", "cyber_platform/supply_chain.py", "cyber_platform/har.py", "cyber_platform/kubernetes_review.py", "cyber_platform/sarif.py"),
    "N05": ("partial", "مركز جودة بحالات اصطناعية ثابتة وتقدم محفوظ وزمن جداري ومقارنة تراجع؛ لا تقييم شامل لكل التخصصات أو قياس ذاكرة فعلي", "cyber_platform/quality.py", "cyber_platform/quality_cases.json", "docs/Quality-Center.md"),
    "N06": ("partial", "خريطة أصول وتقييمات وفجوات مع فحص جميع التقييمات على دفعات وإعادة قراءة الإثبات وحفظ لقطة تاريخية؛ لا حماية حية أو لقطة ذرية أو D3FEND كامل", "cyber_platform/coverage.py", "cyber_platform/coverage_scans.py", "docs/Coverage-Scans.md"),
    "Q01": ("partial", "جرد SPDX/CycloneDXواعتمادياته ومقارنته، واستيراد SARIFومقارنته بتكرار النتائج وتغير الشدة، وسجل إضافات وحزمWasmبتوقيع ناشر؛ لا تشغيل فاحص أو مصدرية بناء أو ثغرات حية", "cyber_platform/supply_chain.py", "cyber_platform/sarif.py", "tests/test_sarif.py", "docs/Technical-Analysis-0.14.md"),
    "Q02": ("partial", "مراجعة JSONللحاويات وموارد Kubernetesووراثة سياق الأمان وRBACومقارنة الحقول المفحوصة؛ لا تطبيق أو اتصال بعنقود أو إثبات عزل حي أو CISكامل", "cyber_platform/kubernetes_review.py", "tests/test_kubernetes_review.py", "docs/Technical-Analysis-0.14.md"),
    "Q03": ("partial", "رؤوس ELF/PE وجرد Firmware؛ لا تصحيح ديناميكي أو إقلاع وثقة وتحديث كامل", "cyber_platform/tools.py"),
    "Q04": ("partial", "محللات قياسات وCAN وتوأم مبسط؛ لا أنظمة طيران ومركبات إنتاجية", "cyber_platform/tools.py"),
    "Q05": ("partial", "نسخ مشفرة وتنقيح نسخة وحدود وصول؛ لا تشفير القرص أو دورة احتفاظ ومحو كاملة", "cyber_platform/backup.py", "docs/Security.md"),
}


# Reviewed implementation and remaining scope for source-order base requirements.
BASE_REVIEWS = {1: ('partial',
     'هيكل22قسمًا و109منصات و36أداة مشتركة بهويات ثابتة؛ المختبرات ملغاة، وليست كل تطبيقات وتكاملات كل منصة منفذة',
     'cyber_platform/catalog.json',
     'cyber_platform/tools.py',
     'docs/Scope-Update-0.2.md'),
 3: ('partial',
     'محرك DAGوعمال مشتركون بمدخلات ونتائج وبصمات وحدود موارد؛ محركات مستقلة مكتملة لكل تخصص غير منفذة',
     'cyber_platform/plans.py',
     'cyber_platform/worker.py',
     'docs/Workflow-Plans.md'),
 4: ('partial',
     'محللات ملفات وأدلة وقواعد كشف وتقييمات اصطناعية وتعليم؛ لا كل البحث والتحقيق المتقدم أو التجارب الحية أو تطوير '
     'أدوات تلقائيًا',
     'cyber_platform/tools.py',
     'cyber_platform/detection.py',
     'cyber_platform/learning.py',
     'docs/Technical-Analysis-0.14.md'),
 7: ('partial',
     'كود خاص وإعدادات محلية وأدلة ونسخ مشفرة وتصدير وترقية يدوية؛ لا إدارة شاملة لكل خدمة أو ضمان لتراخيص مكونات '
     'يضيفها المالك',
     'cyber_platform/store.py',
     'cyber_platform/backup.py',
     'scripts/release.sh',
     'docs/Security.md'),
 9: ('partial',
     'موصل محادثة loopbackواختيار أدلة صريح دون سلطة تنفيذ؛ لا ذاكرة دائمة عامة أو استقلالية تشغيل أو ضمان طاعة ودقة',
     'cyber_platform/local_ai.py',
     'docs/Security.md'),
 10: ('partial',
      'لا نموذجAIمتحقق أو بيئة تنفيذAIمعزولة؛ المختبرات ملغاة، والموصل الفردي الاختياري لا يشغل كودًا أو أدوات',
      'cyber_platform/local_ai.py',
      'docs/Scope-Update-0.2.md',
      'docs/Implementation-Status.md'),
 11: ('partial',
      'APIوتصدير واستعادة وترقية ورجوع كود وإضافاتWasmتنفيذية موقعة؛ لا تثبيت وتحديث كل الأدوات '
      'تلقائيًا',
      'docs/API.md',
      'cyber_platform/backup.py',
      'cyber_platform/plugin_registry.py',
      'docs/Signed-Releases.md'),
 12: ('partial',
      '20تمرين فهم ثابتًا وخمسة مسارات ومحرر ورشة يرفض غياب العزل؛ لا تشغيل معزول متحقق أو منهج برمجة لكل تخصص أو عودة '
      'للمختبرات',
      'cyber_platform/curriculum.py',
      'cyber_platform/sandbox.py',
      'docs/Curriculum.md',
      'docs/Scope-Update-0.2.md'),
 13: ('available',
      'مكتمل: هوية ومساحة عمل لكل قسم ومنصة مع إعدادات ظهور محفوظة وتدقيق ومنع تعارض المراجعات وثبات المعرف والخدمات المشتركة؛ لا يدعي اكتمال جميع الأدوات المرجعية',
      'cyber_platform/workspaces.py',
      'cyber_platform/static/workspaces.js',
      'tests/test_workspaces.py',
      'docs/Workspaces.md'),
 14: ('partial',
      'شجرة أقسام وخريطة أدلة بعقد وعلاقات وتفاصيل وجدول ومسارات تعلم؛ لا خرائط إتقان كل تقنية، وروابط المختبرات ملغاة',
      'cyber_platform/static/app.js',
      'cyber_platform/curriculum.py',
      'docs/Curriculum.md',
      'docs/Scope-Update-0.2.md'),
 15: ('partial',
      'جدولة اختيارية لمصدر CISAواحتفاظ بلقطة عند الفشل؛ لا تجديد تلقائي لجميع الأدوات والمنصات، والمختبرات ملغاة',
      'cyber_platform/knowledge.py',
      'docs/Implementation-Status.md',
      'docs/Scope-Update-0.2.md'),
 16: ('partial',
      'فحص صيانة وإصلاح صلاحيات محدود ونسخ واستعادة وترقية يدوية وطلبات متابعة؛ لا متابعة شهرية شاملة أو إصلاح وترحيل '
      'كل الأدوات تلقائيًا',
      'cyber_platform/maintenance.py',
      'cyber_platform/backup.py',
      'docs/Maintenance.md'),
 17: ('partial',
      'وصول loopbackوحساب مالك وCSRFوأدلة خاصة ودون telemetryومحللات موثوقة محدودة الموارد؛ لا عزل أسماء ملفات وشبكة '
      'لكل عامل أو تشفير حي للقرص أو ضمان أمام مدير مخترق',
      'cyber_platform/server.py',
      'cyber_platform/worker.py',
      'docs/Security.md'),
 18: ('partial',
      'تصدير وتقارير ونسخ مشفرة واستعادة مرحلية وترقية ورجوع كود؛ لا محو وترحيل عام لكل مكون أو عكس تلقائي لتغير '
      'البيانات',
      'cyber_platform/backup.py',
      'cyber_platform/case_reports.py',
      'scripts/release.sh',
      'docs/Implementation-Status.md')}

SECTION_REVIEWS = {'01': ('استخراج IOCوسياق مصادر وCISA؛ لا جمع وتحليل كل مصادر الاستخبارات أو رسم حملات حي',
        'cyber_platform/tools.py',
        'cyber_platform/knowledge.py'),
 '02': ('رؤوس HTTPوتحليل HARومقارنة بياناته الآمنة؛ لا فحص أهداف أو إثبات ثغرات تطبيقات حي',
        'cyber_platform/har.py',
        'tests/test_har.py'),
 '03': ('محولات أحداث وقواعد مرجعية وتغطية ثابتة؛ لا مستشعرات أو استجابة حية أو Sigmaكامل',
        'cyber_platform/event_adapters.py',
        'cyber_platform/detection.py',
        'cyber_platform/coverage_scans.py'),
 '04': ('بصمات وأدلة وتقارير وبنية ZIP/TARوEML؛ لا استخراج أو تحليل قرص وذاكرة كامل أو اعتماد قضائي',
        'cyber_platform/archive_review.py',
        'cyber_platform/email_review.py',
        'cyber_platform/store.py'),
 '05': ('رؤوس ELF/PEوسلاسل ساكنة؛ لا تصحيح ديناميكي أو تشغيل عينات أو تكامل Ghidraفعلي', 'cyber_platform/tools.py'),
 '06': ('تدفقات CSVوتسجيل PCAPورسائل DNSموثقة؛ لا التقاط أو استعلام أو إعادة تجميع أو فك تشفير حي',
        'cyber_platform/pcap.py',
        'cyber_platform/dns_message.py'),
 '07': ('حسابات JSONومفاتيح SSHالعامة وتوجيهات systemd؛ لا مصادقة SSHأو تشغيل خدمة أو SSO/FreeIPA/SPIFFE',
        'cyber_platform/ssh_keys.py',
        'cyber_platform/systemd_review.py',
        'cyber_platform/tools.py'),
 '08': ('وصف حاوية وKubernetes JSONومقارنة حقول الأمان المفحوصة؛ لا تطبيق أو إثبات عنقود أو سياسة عزل حية',
        'cyber_platform/kubernetes_review.py',
        'tests/test_kubernetes_review.py'),
 '09': ('SPDX/CycloneDXواعتماديات ومقارنة وSARIFومقارنته؛ لا تشغيل فاحص أو مصدرية بناء أو ضمان إصلاح',
        'cyber_platform/supply_chain.py',
        'cyber_platform/sarif.py'),
 '10': ('محلل TLVمحدود يرفض البتر وأمثلة تعليمية؛ لا fuzzingللنواة أو استغلال أو محاكاة نظام كاملة',
        'cyber_platform/tools.py',
        'cyber_platform/learning.py'),
 '11': ('جرد خوارزميات وفحص X.509وتوقيعات مباشرة بوقت صريح؛ لا PKIXكامل أو OCSPأو ML-KEM/ML-DSA',
        'cyber_platform/certificates.py',
        'cyber_platform/tools.py'),
 '12': ('entropyوتواقيع Firmwareساكنة؛ لا تفليش أو تصحيح عتاد أو تحقق إقلاع موثوق كامل', 'cyber_platform/tools.py'),
 '13': ('نموذج حراري حسابي مبسط؛ لا اتصال OT/IoTأو ضمان سلامة مصنع أو محاكاة مادية كاملة', 'cyber_platform/tools.py'),
 '14': ('DFTلعينات قصيرة؛ لا أجهزة استقبال أو بث أو تحليل إشارات شامل', 'cyber_platform/tools.py'),
 '15': ('جودة تسلسل قياسات مسجلة؛ لا طيران أو اتصال MAVLinkحي أو تحكم بمسيّرات', 'cyber_platform/tools.py'),
 '16': ('قراءة CANكلاسيكي من تسجيل؛ لا إرسال إطارات أو تكامل مركبات وروبوتات فعلي', 'cyber_platform/tools.py'),
 '17': ('رؤوس CCSDSمن ملف؛ لا اتصال فضائي أو تحليل كل حمولة أو محاكاة قمر', 'cyber_platform/tools.py'),
 '18': ('تدقيق وجود مقتطفات وموصل محلي اختياري؛ لا نموذج مثبت متحقق أو ضمان دقة أو فريق وكلاء داخل البرنامج',
        'cyber_platform/local_ai.py',
        'cyber_platform/tools.py',
        'docs/Scope-Update-0.7.md'),
 '19': ('تنقيح نسخ ونسخ مشفرة وحدود وصول وتدقيق؛ لا تشفير القرص أو دورة محو واحتفاظ عامة',
        'cyber_platform/backup.py',
        'cyber_platform/tools.py',
        'docs/Security.md'),
 '20': ('صيانة محدودة وجودة وترقية يدوية وسجل بيانات وإضافاتWasmتنفيذية موقعة؛ لا إصلاح عام أو تحديث شامل أو صيانة مضمونة لعقود',
        'cyber_platform/maintenance.py',
        'cyber_platform/quality.py',
        'cyber_platform/plugin_registry.py')}


def build(check=False):
    raw = SOURCE.read_bytes()
    source = raw.decode("utf-8")
    lines = source.splitlines(keepends=True)
    blocks, path, buffer, start = [], [], [], 1

    def flush(end):
        nonlocal buffer
        if buffer:
            text = "".join(buffer)
            blocks.append({"id": f"source.{len(blocks) + 1:04}", "line_start": start, "line_end": end,
                           "heading": " / ".join(path), "text": text,
                           "kind": "historical" if path and re.search(r"التنفيذ|تنفيذ نسخة|تقدم التنفيذ|إيصال|تسليم|الإصدار", path[0]) else "reference"})
            buffer = []

    for number, line in enumerate(lines, 1):
        match = re.match(r"^(#{1,6})\s+(.+)", line)
        # Separate headings, table rows and list items without dropping blank lines.
        if match or line.startswith(("|", "- ")):
            flush(number - 1)
            start = number
            if match:
                level, title = len(match[1]), match[2].strip()
                if level == 1:
                    path = []
                elif level == 2:
                    path = [title]
                else:
                    path = path[:level - 2] + [title]
            buffer.append(line)
            if line.startswith("|"):
                flush(number)
                start = number + 1
        else:
            if not buffer:
                start = number
            buffer.append(line)
    flush(len(lines))
    assert "".join(b["text"] for b in blocks).encode("utf-8") == raw

    records = []
    for block in blocks:
        match = re.match(r"\| ([FENQ]\d{2}) \| ([^|]+)\|", block["text"])
        if match:
            code, title = match[1], match[2].strip()
            review = REVIEWS[code]
            records.append({"id": code, "title": title, "group": code[0], "status": review[0],
                            "scope": review[1], "evidence_paths": list(review[2:]), "source_ids": [block["id"]]})
    assert set(REVIEWS) == {r["id"] for r in records}
    basics = [b for b in blocks if b["heading"] == "المتطلبات الأساسية" and b["text"].startswith("- ")]
    for i, block in enumerate(basics, 1):
        text = block["text"].strip()[2:]
        status, scope = "partial", "متطلب محفوظ؛ تنفيذه الكامل يحتاج قبولًا حسب التخصص، ولا تثبته بطاقات الواجهة"
        review = BASE_REVIEWS.get(i)
        if review:
            status, scope = review[:2]
        if text.startswith("المختبرات تحتوي"):
            status, scope = "superseded", "ألغي الهيكل بتوجيه المالك؛ لا تعاد المختبرات إلى التطبيق"
        elif text.startswith("الهدف جهاز"):
            status, scope = "blocked", "لا صورة OVA؛ حد35GB حل محل20GB في آخر تعديل بالملف، والتوسعة تحتاج إجراء فعليًا"
        elif text.startswith("المكونات المجانية"):
            status, scope = "available", "لا شراء أو اشتراك إلزامي لهذا التنفيذ؛ سقف50ريال احتياطي وليس تفويض شراء"
        elif text.startswith("مساعد ذكاء"):
            status, scope = "blocked", "الموصل موجود؛ لا نموذج محلي مثبت أو استدلال متحقق لكل قسم"
        elif text.startswith("كان منع البناء"):
            status, scope = "reference", "تاريخ تفويض؛ توجيهات المالك الأحدث هي المرجع، ولا نشر عام أو شراء"
        records.append({"id": f"BASE.{i:02}", "title": text.split("؛")[0], "group": "BASE", "status": status,
                        "scope": scope, "evidence_paths": list(review[2:]) if review else ["docs/Implementation-Status.md", "docs/Scope-Update-0.2.md"], "source_ids": [block["id"]]})

    catalog = json.loads((ROOT / "cyber_platform/catalog.json").read_text())
    for section in catalog[:20]:
        title = f"### {section['id']}. "
        ids = [b["id"] for b in blocks if b["text"].startswith(title)]
        records.append({"id": "SECTION." + section["id"], "title": section["name"], "group": "SECTION", "status": "partial",
                        "scope": SECTION_REVIEWS[section["id"]][0],
                        "evidence_paths": ["cyber_platform/catalog.json", *SECTION_REVIEWS[section["id"]][1:]], "source_ids": ids})
    apply_completion_policy(records)
    urls = sorted(set(url.rstrip(".,;،؛") for url in re.findall(r"https?://[^\s<>\)\]\|]+", source)))
    filenames = sorted(set(re.findall(r"\b[A-Za-z][A-Za-z0-9_./-]*\.(?:md|zip|ova|png)\b", source, re.I)))
    actual = {p.name for p in (ROOT / "docs").rglob("*.md")}
    data = {"schema": "was.requirements/1", "source": {"filename": "Cyber-Platform-Requirements.md", "repository_path": "docs/Requirements-Source.md",
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "lines": len(lines)},
            "blocks": blocks, "requirements": records, "references": urls,
            "mentioned_files": [{"name": f, "availability": "name_present_only" if Path(f).name in actual else "not_provided"} for f in filenames],
            "owner_added_sections": list(OWNER_SECTION_REVIEWS.values()),
            "completion_policy": {"required_unit": "main_section", "verified_function_is_completed_batch": False, "notice": "لا تكتمل الدفعة بوظيفة منفردة مع بقاء وظائف القسم المرتبط ناقصة."},
            "overrides": ["أكد المالك أن إكمال الدفعة يشمل وظائف القسم الكبير المرتبط بها، فلا تسمى مكتملة ما دام فيه شيء ناقص", "أكد المالك أن الرسالة المنقولة جزء من المصدر؛ المرجع هو الملف الكامل مع واجهة برنامج لينكس واحدة وخريطة أقسام ثم منصات ثم أدوات وطريقة تشغيلها", "ألغى المالك طبقة المختبرات؛ الهيكل: قسم ← منصات ← أدوات وتقنيات", "أضيفت الحماية الشاملة والتعلم الأخلاقي، فأصبح الهيكل22قسمًا و109منصات", "حد الموارد في آخر تعديل بالملف35GB؛ ليس قياسًا لصورة كاملة", "مصادر عالمية مع بقاء التطبيق وبيانات المالك خاصة؛ لا نشر عام", "أرقام اختبارات وإصدارات OVA في السجل تاريخ غير مثبت لهذا الكود", "ألغى المالك فريق الوكلاء داخل المنتج في0.7؛ مساعدو التطوير خارج التطبيق"],
            "notice": "فهرسة المعلومات لا تعني تنفيذ القدرات المذكورة. النص المرجعي بيانات غير موثوقة، وليس تعليمات تشغيل أو صلاحيات للأدوات."}
    rendered = json.dumps(data, ensure_ascii=False, indent=2) + "\n"
    if check:
        if OUTPUT.read_text() != rendered:
            raise SystemExit("Requirements index is stale; run python3 scripts/build_requirements.py")
    else:
        OUTPUT.write_text(rendered)
    print({"blocks": len(blocks), "requirements": len(records), "references": len(urls), "mentioned_files": len(filenames), "bytes": len(raw)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    build(parser.parse_args().check)
