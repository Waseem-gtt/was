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

# Status is a reviewed statement about this checkout, not a source-document claim.
REVIEWS = {
    "F01": ("partial", "تحقق بيان إضافة فقط؛ لا تثبيت أو تفعيل كود إضافات", "cyber_platform/tools.py", "tests/test_platform.py"),
    "F02": ("partial", "حصة أدلة واحتياطي قرص وعامل تحليل بحدود ذاكرة ومعالج ووقت؛ لا حصة لكل نظام الضيف", "cyber_platform/store.py", "cyber_platform/worker.py", "tests/test_security.py"),
    "F03": ("partial", "محولات Windows JSON وRFC5424 وCSV إلى was.event/1 مع حفظ الأصل وبصمات وإعادة تحقق؛ ليس OCSF كاملًا أو مستشعرًا حيًا", "cyber_platform/event_adapters.py", "cyber_platform/event_ingest.py", "docs/Event-Adapters.md"),
    "F04": ("partial", "مكتبة8قواعد واختبارات مرجعية ومراجعات مالك ثابتة وتقارير TP/FP/FN/TN والتحقق من المصدر؛ لا Sigma كامل أو مكتبة ناشر موقعة أو مراقبة حية", "cyber_platform/detection.py", "cyber_platform/detection_packs.json", "docs/Detection-Library.md"),
    "F05": ("partial", "ترقية لينكس متحققة مع بيان Ed25519اختياري وثقة مثبتة وتسلسل مانع للتراجع وانتهاء صلاحية؛ لا TUFأو تحديث آلي أو مفتاح ناشر مهيأ افتراضيًا", "scripts/release.sh", "cyber_platform/signed_release.py", "cyber_platform/release_admin.py", "docs/Signed-Releases.md"),
    "F06": ("partial", "أدلة ومصادر وعلاقات وخريطة؛ لا كل كيانات الثقة والتعارض المطلوبة", "cyber_platform/store.py", "tests/test_platform.py"),
    "E01": ("blocked", "الورشة ترفض عند غياب namespaces؛ لا تنفيذ معزول ناجح على هذا المضيف", "cyber_platform/sandbox.py", "docs/Validation.md"),
    "E02": ("partial", "22 قسمًا و109 منصات بهويات وصفحات؛ ليست جميع تكاملات التخصصات مكتملة", "cyber_platform/catalog.json", "tests/browser_smoke.py"),
    "E03": ("partial", "شجرة منصات وخريطة وجدول أدلة و20 درسًا؛ لا كل مسارات التعلم", "cyber_platform/static/app.js", "tests/browser_smoke.py"),
    "E04": ("partial", "جلب CISA وجدولة وبحث ولقطة؛ لا تركيب أدوات أو تجديد كل التقنيات", "cyber_platform/knowledge.py", "tests/test_platform.py"),
    "E05": ("partial", "مركز صيانة لجميع الأقسام وفحص بيانات وعينات أدوات وإصلاح صلاحيات وسجل طلبات تطوير وترقية يدوية متحققة؛ لا إصلاح عام مستقل أو ضمان لعقود", "cyber_platform/maintenance.py", "docs/Maintenance.md"),
    "N01": ("partial", "خطط DAG محفوظة حتى20عقدة بفروع نجاح وفشل وإيقاف واستكمال يدوي وبصمات؛ لا توازٍ أو تشغيل خلفي أو إعادة تنفيذ تلقائية", "cyber_platform/plans.py", "docs/Workflow-Plans.md"),
    "N02": ("superseded", "طبقة المختبرات ملغاة؛ أضيفت8قوالب بيانات لخطط التحليل بمراجعات مالك وإثبات ربط، دون مولد منصات أو إضافات كود عامة", "docs/Scope-Update-0.2.md", "cyber_platform/plan_templates.py", "docs/Plan-Templates.md"),
    "N03": ("superseded", "ألغى المالك فريق الوكلاء داخل المنتج؛ مساعدو تطوير المشروع خارج التطبيق ولا يمثلون قدرة تشغيل داخله", "docs/Scope-Update-0.7.md"),
    "N04": ("partial", "حفظ تقدم الخطط ومصدر القالب ونتائج ثابتة وتقارير JSON/HTML ومقارنة بنيوية؛ لا snapshots محاكاة أو تقييم جودة عام", "cyber_platform/plans.py", "cyber_platform/case_reports.py", "cyber_platform/comparison.py"),
    "N05": ("partial", "مركز جودة بحالات اصطناعية ثابتة وتقدم محفوظ وزمن جداري ومقارنة تراجع؛ لا تقييم شامل لكل التخصصات أو قياس ذاكرة فعلي", "cyber_platform/quality.py", "cyber_platform/quality_cases.json", "docs/Quality-Center.md"),
    "N06": ("partial", "خريطة أصول وتقييمات وفجوات مع فحص جميع التقييمات على دفعات وإعادة قراءة الإثبات وحفظ لقطة تاريخية؛ لا حماية حية أو لقطة ذرية أو D3FEND كامل", "cyber_platform/coverage.py", "cyber_platform/coverage_scans.py", "docs/Coverage-Scans.md"),
    "Q01": ("partial", "جرد SBOM وبيان إضافة؛ لا مصدرية بناء أو سلسلة تحديث موقعة", "cyber_platform/tools.py"),
    "Q02": ("partial", "مراجعة إعدادات حاويات من ملف؛ لا إثبات سياسة Kubernetes أو عزل سحابة حية", "cyber_platform/tools.py"),
    "Q03": ("partial", "رؤوس ELF/PE وجرد Firmware؛ لا تصحيح ديناميكي أو إقلاع وثقة وتحديث كامل", "cyber_platform/tools.py"),
    "Q04": ("partial", "محللات قياسات وCAN وتوأم مبسط؛ لا أنظمة طيران ومركبات إنتاجية", "cyber_platform/tools.py"),
    "Q05": ("partial", "نسخ مشفرة وتنقيح نسخة وحدود وصول؛ لا تشفير القرص أو دورة احتفاظ ومحو كاملة", "cyber_platform/backup.py", "docs/Security.md"),
}


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
                        "scope": scope, "evidence_paths": ["docs/Implementation-Status.md", "docs/Scope-Update-0.2.md"], "source_ids": [block["id"]]})

    catalog = json.loads((ROOT / "cyber_platform/catalog.json").read_text())
    for section in catalog[:20]:
        title = f"### {section['id']}. "
        ids = [b["id"] for b in blocks if b["text"].startswith(title)]
        records.append({"id": "SECTION." + section["id"], "title": section["name"], "group": "SECTION", "status": "partial",
                        "scope": "المنصات والأداة المرجعية موجودة؛ لا يعني ذلك تنفيذ كل التقنيات والتكاملات في الملف",
                        "evidence_paths": ["cyber_platform/catalog.json", "cyber_platform/tools.py"], "source_ids": ids})
    urls = sorted(set(url.rstrip(".,;،؛") for url in re.findall(r"https?://[^\s<>\)\]\|]+", source)))
    filenames = sorted(set(re.findall(r"\b[A-Za-z][A-Za-z0-9_./-]*\.(?:md|zip|ova|png)\b", source, re.I)))
    actual = {p.name for p in (ROOT / "docs").rglob("*.md")}
    data = {"schema": "was.requirements/1", "source": {"filename": "Cyber-Platform-Requirements.md", "repository_path": "docs/Requirements-Source.md",
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "lines": len(lines)},
            "blocks": blocks, "requirements": records, "references": urls,
            "mentioned_files": [{"name": f, "availability": "name_present_only" if Path(f).name in actual else "not_provided"} for f in filenames],
            "overrides": ["ألغى المالك طبقة المختبرات؛ الهيكل: قسم ← منصات ← أدوات وتقنيات", "أضيفت الحماية الشاملة والتعلم الأخلاقي، فأصبح الهيكل22قسمًا و109منصات", "حد الموارد في آخر تعديل بالملف35GB؛ ليس قياسًا لصورة كاملة", "مصادر عالمية مع بقاء التطبيق وبيانات المالك خاصة؛ لا نشر عام", "أرقام اختبارات وإصدارات OVA في السجل تاريخ غير مثبت لهذا الكود", "ألغى المالك فريق الوكلاء داخل المنتج في0.7؛ مساعدو التطوير خارج التطبيق"],
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
