/* File-only technical analyzers. Uploaded data never grants execution authority. */
function technicalAnalysisPage() {
  const missing = requireProject();
  if (missing) return missing;
  const pid = state.project.project.id;
  const ids = ["pcap", "certificate", "supply-chain", "supply-chain-diff", "har", "har-diff", "email", "kubernetes", "kubernetes-diff", "systemd", "sarif", "sarif-diff", "archive", "ssh-keys", "dns"];
  const names = {pcap:"تسجيلات الشبكة PCAP",certificate:"شهادات X.509","supply-chain":"مكونات البرمجيات واعتمادياتها","supply-chain-diff":"مقارنة جرد مكونات البرمجيات",har:"جلسات الويب HAR","har-diff":"مقارنة جلسات الويب",email:"بيانات رسائل البريد",kubernetes:"إعدادات Kubernetes","kubernetes-diff":"مقارنة مراجعات Kubernetes",systemd:"مراجعة وحدات systemd",sarif:"نتائج فحص الكود SARIF","sarif-diff":"مقارنة نتائج SARIF",archive:"بنية أرشيفات ZIP وTAR","ssh-keys":"مفاتيح SSH العامة",dns:"رسائل DNS المسجلة"};
  const descriptions = {
    har:"HAR1.2: بيانات أصول الطلبات ومؤشرات الرؤوس والكوكيز؛ لا تُصدّر المسارات والاستعلامات أو قيم الرؤوس والأجسام. المؤشرات لا تثبت ثغرة حية.",
    "har-diff":"غلاف left وright لمستندَي HAR. مقارنة كاملة للبيانات الوصفية الآمنة وبترتيب الإدخالات؛ لا تقارن المحتوى والقيم المحجوبة.",
    email:"رسالة EML: بنية MIME ونطاقات العناوين وبصمات المرفقات. لا يُصدّر جسم الرسالة أو يُستخرج مرفق؛ نتائج SPF/DKIM/DMARC تصريحات مصدر غير متحققة تشفيريًا.",
    kubernetes:"موارد Kubernetes بصيغة JSON: مراجعة ثابتة لحقول الأمان الموثقة. لا اتصال بعنقود أو تطبيق إعداد أو ضمان امتثال كامل.",
    "kubernetes-diff":"غلاف left وright لمراجعة الموارد والحقول الموثقة كاملة. اختلاف المراجعة ليس اختبارًا حيًا، والمساواة لا تشمل الأسرار أو الحقول غير المفحوصة.",
    systemd:"ملف وحدة systemd: مراجعة ثابتة لتوجيهات التقوية الموثقة دون تشغيل الخدمة أو الأوامر أو تصدير قيم البيئة والاعتمادات.",
    sarif:"SARIF2.1.0: استيراد نتائج فاحص ضمن الحقول الموثقة. النتائج تصريحات الملف؛ لا يُشغل فاحص أو كود ولا تُعرض مقتطفات الكود.",
    "sarif-diff":"غلاف left وright لمستندَي SARIF. مقارنة كاملة للنتائج المطَبعة مع عدد التكرارات وتغير الشدة؛ اختفاء نتيجة لا يثبت إصلاح ثغرة.",
    archive:"ZIP كلاسيكي أو TAR موثق أو غلاف archive_base64: بيانات الأعضاء والمسارات والروابط والأحجام المعلنة دون استخراج أو فك ضغط أو تحقق CRC.",
    "ssh-keys":"مفاتيح OpenSSH العامة أو authorized_keys الموثق: نوع المفتاح وبصمته وخياراته فقط؛ لا مصادقة أو اتصال أو تنفيذ خيارات أو تصدير قيمها.",
    dns:"رسالة DNS ثنائية أو غلاف dns_base64: الحقول والسجلات الموثقة دون استعلام شبكة أو تحقق DNSSEC. نصوص TXT لا تُصدّر.",
    pcap:"تسجيل PCAP تقليدي أو غلاف JSON موثق؛ تُحلل بيانات الحزم والتدفقات دون تصدير الحمولات. لا التقاط حي أو PCAPNG أو فك تشفير.",
    certificate:"شهادات PEM أو DER أو غلاف JSON مع وقت تحقق صريح. فحص بنية وتوقيعات شهادات مقدمة؛ لا ثقة نظام أو OCSP أو اتصال بخادم.",
    "supply-chain":"قوائم CycloneDX 1.5/1.6 أو SPDX 2.3 بصيغة JSON، مع المكونات والاعتماديات والملاحظات. البيانات والتراخيص والثغرات المعلنة تحتاج تحققًا مستقلًا.",
    "supply-chain-diff":"غلاف JSON يحتوي left وright لقائمتي SPDX أو CycloneDX. يقارن حقول الجرد الموثقة والاعتماديات وتصريحات الثغرات بالكامل؛ لا يساوي جميع بايتات المصدر ولا يثبت غياب الثغرات.",
  };
  const select = el("select", {"aria-label":"القدرة التقنية"}, ...ids.map(id => el("option", {value:id}, names[id])));
  const source = el("select", {"aria-label":"ملف التحليل التقني"});
  const saved = el("select", {"aria-label":"نتيجة تقنية محفوظة"});
  const upload = el("input", {type:"file","aria-label":"رفع ملف للتحليل التقني"});
  const information = el("div"), output = el("div", {"aria-live":"polite"});
  let selectedReport = null, selectionEpoch = 0;
  const safeValue = value => value == null ? "—" : typeof value === "object" ? JSON.stringify(value) : String(value);
  const rows = value => Array.isArray(value) ? value : [];
  function clearOutput() { selectionEpoch += 1; output.replaceChildren(); selectedReport = null; exportReport.disabled = true; }
  const active = () => holder.isConnected && state.project?.project.id === pid;
  const tool = () => state.boot.tools.find(item => item.id === select.value);
  const exportReport = button("تنزيل نتيجة التحليل التقني JSON", () => {
    if (selectedReport) researchJsonDownload(selectedReport, "technical-" + selectedReport.tool + ".json");
  });
  exportReport.disabled = true;
  function updateSources(preferred) {
    if (preferred && preferred !== source.value) {
      clearOutput();
    }
    const chosen = preferred || source.value;
    source.replaceChildren(el("option", {value:""}, "اختر ملفًا…"), ...state.project.evidence.filter(item => item.kind === "original").map(item => el("option", {value:item.id,selected:item.id === chosen}, item.name + " · " + size(item.size))));
  }
  function updateSaved(preferred) {
    const selected = preferred || saved.value;
    const results = state.project.jobs.flatMap(job => job.results || []).filter(item => item.status === "succeeded" && ids.includes(item.tool));
    const unique = new Map(results.map(item => [item.evidence_id,item]));
    saved.replaceChildren(el("option", {value:""}, "اختر نتيجة محفوظة…"), ...Array.from(unique.values()).filter(item => item.tool === select.value).map(item => el("option", {value:item.evidence_id,selected:item.evidence_id === selected}, names[item.tool] + " · " + item.evidence_id.slice(0,12))));
  }
  function describe() {
    information.replaceChildren(el("p", {}, descriptions[select.value]),
      el("p", {class:"notice"}, "قراءة ملفات محلية في عامل محدود الموارد؛ الحد العام 4 MiB، وللشهادات 256 KiB. لا اتصالات خارجية أو تنفيذ ملفات. حدود الصيغة تظهر في التقرير."));
    clearOutput();
    updateSaved();
  }
  select.addEventListener("change", describe);
  source.addEventListener("change", () => {
    clearOutput();
  });
  saved.addEventListener("change", () => {
    clearOutput();
  });
  async function refreshProject() {
    const project = await api("project?id=" + pid);
    if (!active()) return false;
    state.project = project;
    updateSources(); updateSaved();
    return true;
  }
  function renderReport(report, resultId, historical) {
    const value = report.result;
    const sourceMetadata = state.project.evidence.find(item => item.id === report.input_evidence);
    const resultMetadata = state.project.evidence.find(item => item.id === resultId);
    selectedReport = report; exportReport.disabled = false;
    const summary = [];
    if (report.tool === "pcap") {
      summary.push(el("p", {}, "الحزم: " + value.packet_count + " · البايتات الملتقطة: " + value.captured_bytes),
        table(["البروتوكول", "الحزم"], Object.entries(value.protocols || {}).map(([key,count]) => [key,count])),
        table(["المصدر", "الوجهة", "البروتوكول", "منفذ المصدر", "منفذ الوجهة", "الحزم"], (value.flows || []).map(row => [row.source,row.destination,row.protocol,row.source_port ?? "—",row.destination_port ?? "—",row.packets])));
    } else if (report.tool === "certificate") {
      summary.push(el("p", {}, "الشهادات: " + value.certificate_count),
        el("p", {class:"notice"}, "الثقة في ناشر الشهادة غير مقيّمة. صحة توقيع رابط مقدم لا تعني ثقة الجهة أو صلاحية اسم موقع."),
        table(["الشهادة", "الموضوع", "الجهة المصدرة", "بداية الصلاحية", "نهاية الصلاحية", "حالة الوقت"], (value.certificates || []).map((row,index) => [index + 1, typeof row.subject === "string" ? row.subject : JSON.stringify(row.subject),typeof row.issuer === "string" ? row.issuer : JSON.stringify(row.issuer),row.not_before,row.not_after,row.time_status])),
        el("details", {}, el("summary", {}, "روابط التوقيع والقيود والمفاتيح"), pre({chain_links:value.chain_links,certificates:value.certificates})));
    } else if (report.tool === "supply-chain-diff") {
      summary.push(el("p", {}, "المقارنة مكتملة: " + (value.complete ? "نعم":"لا") + " · الجرد المطبع متساوٍ: " + (value.normalized_inventory_equal ? "نعم":"لا")),
        el("p", {class:"notice"}, value.notice),
        table(["المكونات المضافة"], (value.added_components || []).map(id => [id])),
        table(["المكونات المحذوفة"], (value.removed_components || []).map(id => [id])),
        table(["المكون المتغير", "الحقول المتغيرة"], (value.changed_components || []).map(row => [row.id,row.fields.join(" · ")])),
        table(["تغير الاعتمادية", "المصدر", "الهدف"], [...(value.added_dependencies || []).map(row => ["إضافة",row.source,row.target]),...(value.removed_dependencies || []).map(row => ["حذف",row.source,row.target])]),
        el("p", {}, "تغير تصريحات الثغرات: " + (value.vulnerability_claims_changed ? "نعم":"لا")));
    } else if (report.tool === "supply-chain") {
      summary.push(el("p", {}, "المكونات: " + value.component_count + " · الصيغة: " + value.format),
        el("p", {class:"notice"}, "هذه مراجعة للمعلومات المقدمة؛ غياب ملاحظة لا يثبت غياب ثغرات أو صحة الترخيص."),
        table(["المعرف", "المكون", "الإصدار", "الترخيص"], (value.components || []).map(row => [row.id,row.name,row.version || "—",typeof row.license === "string" ? row.license : JSON.stringify(row.licenses || row.license || [])])),
        el("details", {}, el("summary", {}, "الاعتماديات وملاحظات سلسلة التوريد"), pre({dependencies:value.dependencies,graph:value.graph,issues:value.issues,summary:value.summary})));
    }
    if (report.tool === "har") {
      summary.push(el("p", {}, "إدخالات الويب: " + value.entry_count),
        table(["أصل الطلب", "الإدخالات"], rows(value.origins).map(row => [row.origin,row.entries])),
        table(["الإدخال", "الأصل", "الطريقة", "الحالة", "زمن ms"], rows(value.entries).map(row => [row.index,row.origin,row.method,row.status,row.duration_ms])),
        el("p", {class:"notice"}, "التقرير يحجب المسارات والاستعلامات وقيم الرؤوس والكوكيز والأجسام. الأصل الكامل يبقى دليلًا خاصًا."));
    } else if (report.tool === "har-diff") {
      summary.push(el("p", {}, "المقارنة مكتملة: " + (value.complete ? "نعم":"لا") + " · البيانات الوصفية متساوية: " + (value.normalized_metadata_equal ? "نعم":"لا")),
        table(["الإدخال المتغير", "الحقول"], rows(value.changed_entries).map(row => [row.index,safeValue(row.fields)])),
        el("p", {}, "إدخالات مضافة: " + safeValue(value.added_entry_indexes) + " · محذوفة: " + safeValue(value.removed_entry_indexes)),
        el("p", {class:"notice"}, value.notice || "المقارنة للبيانات الآمنة وبترتيب الإدخالات، وليست مساواة المحتوى المحجوب."));
    } else if (report.tool === "email") {
      summary.push(el("p", {}, "أجزاء MIME: " + value.part_count + " · المرفقات: " + value.attachment_count),
        el("p", {}, "نطاقات العناوين: " + safeValue(value.domains)),
        table(["بصمة اسم المرفق", "الامتداد", "النوع", "البايتات", "بصمة المحتوى"], rows(value.attachments).map(row => [row.filename_sha256,row.extension,row.content_type,row.decoded_bytes,row.sha256])),
        el("details", {}, el("summary", {}, "تصريحات مصادقة البريد"), pre(value.auth_claims || [])),
        el("p", {class:"notice"}, "SPF/DKIM/DMARC تصريحات من الملف فقط. لا يُصدّر الجسم أو اسم المرفق الخام ولا يُستخرج محتواه."));
    } else if (report.tool === "kubernetes") {
      summary.push(el("p", {}, "الموارد: " + value.resource_count + " · الحاويات: " + value.container_count),
        table(["المورد", "النوع", "مساحة الاسم", "الحاويات", "نطاق المراجعة"], rows(value.resources).map(row => [row.name,row.kind,row.namespace,row.container_count,row.review_status])),
        el("p", {class:"notice"}, "مراجعة ثابتة فقط؛ مورد not_reviewed لم يُفحص. لا تطبيق للإعدادات أو تحقق من العنقود."));
    } else if (report.tool === "kubernetes-diff") {
      summary.push(el("p", {}, "المقارنة مكتملة: " + (value.complete ? "نعم":"لا") + " · المراجعة المطَبعة متساوية: " + (value.normalized_review_equal ? "نعم":"لا")),
        table(["المورد المتغير", "الحقول"], rows(value.changed_resources).map(row => [row.id,safeValue(row.fields)])),
        el("p", {}, "موارد مضافة: " + safeValue(value.added_resources) + " · محذوفة: " + safeValue(value.removed_resources)),
        el("details", {}, el("summary", {}, "ملاحظات أضيفت أو أزيلت"), pre({added:value.added_findings,removed:value.removed_findings})),
        el("p", {class:"notice"}, value.notice || "المقارنة للحقول المفحوصة فقط؛ لا تشمل الأسرار أو كل إعدادات المصدر."));
    } else if (report.tool === "systemd") {
      summary.push(el("p", {}, "مراجعة توجيهات وحدة الخدمة دون تشغيلها"),
        el("details", {}, el("summary", {}, "ملخص التوجيهات وحضورها"), pre(value.directives || value.review || value.summary || {})),
        el("p", {class:"notice"}, "لا تُنفذ الخدمة أو الأوامر، ولا تعني المراجعة تحققًا من إعدادات خدمة عاملة."));
    } else if (report.tool === "sarif") {
      summary.push(el("p", {}, "النتائج المسجلة: " + value.finding_count + " · مرات التشغيل: " + value.run_count),
        table(["القاعدة", "الشدة", "الرسالة", "المواقع"], rows(value.findings).map(row => [row.rule_id,row.level,row.message,safeValue(row.locations)])),
        el("p", {class:"notice"}, "استيراد تصريحات فاحص فقط، دون تشغيله أو عرض مقتطفات الكود أو فتح المواقع المذكورة."));
    } else if (report.tool === "sarif-diff") {
      summary.push(el("p", {}, "المقارنة مكتملة: " + (value.complete ? "نعم":"لا") + " · النتائج المطَبعة متساوية: " + (value.normalized_findings_equal ? "نعم":"لا")),
        pre(value.counts || {}),
        table(["القاعدة", "الشدة السابقة", "الشدة الجديدة", "التكرارات"], rows(value.severity_changed).map(row => [row.finding?.rule_id,row.from_level,row.to_level,row.count])),
        el("details", {}, el("summary", {}, "النتائج المضافة والغائبة"), pre({added:value.added,resolved:value.resolved})),
        el("p", {class:"notice"}, "اختفاء نتيجة من الملف لا يثبت إصلاح ثغرة. المقارنة تشمل الحقول المطَبعة والتكرارات فقط."));
    } else if (report.tool === "archive") {
      summary.push(el("p", {}, "الصيغة: " + value.format + " · أعضاء الأرشيف: " + value.member_count),
        table(["العضو", "النوع", "الحجم المعلن", "الحجم المخزن", "مشفر"], rows(value.members).map(row => [row.name,row.type,row.size,row.compressed_size,row.encrypted ? "نعم":"لا"])),
        el("p", {class:"notice"}, "لم تُستخرج الملفات أو يُفك ضغطها، ولم يُتحقق من CRC. الأحجام بيانات معلنة في الأرشيف."));
    } else if (report.tool === "ssh-keys") {
      summary.push(el("p", {}, "المفاتيح العامة: " + value.key_count),
        table(["المفتاح", "النوع", "البِتات", "البصمة", "أسماء الخيارات"], rows(value.keys).map(row => [row.index,row.type,row.bits,row.fingerprint || row.sha256,safeValue(row.option_names)])),
        el("p", {class:"notice"}, "هذه مراجعة بنية مفاتيح عامة؛ لا مصادقة أو اتصال SSH أو تنفيذ لقيم الخيارات."));
    } else if (report.tool === "dns") {
      summary.push(el("p", {}, "الأسئلة: " + value.question_count + " · السجلات: " + value.record_count),
        table(["اسم السؤال", "النوع", "الفئة"], rows(value.questions).map(row => [row.name,row.type,row.class])),
        table(["القسم", "الاسم", "النوع", "TTL", "البيانات الموثقة"], rows(value.records).map(row => [row.section,row.name,row.type,row.ttl,safeValue(row.data)])),
        el("p", {class:"notice"}, "رسالة مسجلة دون استعلام شبكة أو تحقق DNSSEC. أعلام الأصالة تصريحات الرسالة وليست ثقة مكتسبة."));
    }
    if (rows(value.findings).length && !["sarif", "sarif-diff"].includes(report.tool)) summary.push(
      table(["الملاحظة", "المورد أو الإدخال", "الحقل", "الوصف"], rows(value.findings).map(row => [row.code,safeValue(row.resource_id ?? row.entry ?? row.member ?? row.key),row.field || "—",row.message])));
    output.replaceChildren(panel("نتيجة التحليل التقني", badge(historical ? "نتيجة تاريخية محفوظة":"اكتمل تحليل الملف", "good"),
      el("p", {class:"muted"}, "نجاح تنفيذ التحليل ليس شهادة سلامة. " + (historical ? "تحققت قراءة الملفات وبصماتها دون إعادة تشغيل المحلل؛ قد تختلف نتائج إصدار أحدث." : "حُفظ الأصل والنتيجة كدليلين منفصلين.")),
      ...summary,
      el("details", {}, el("summary", {}, "الأصل والنتيجة وبصمات المصدر"), pre({input_evidence:report.input_evidence,input_sha256:report.input_sha256,source_sha256:sourceMetadata?.sha256,result_evidence:resultId,result_sha256:resultMetadata?.sha256,engine_version:report.engine_version,engine_sha256:report.engine_sha256,acceptance:report.acceptance})),
      el("details", {}, el("summary", {}, "التقرير التقني الكامل وحدوده"), pre(value))));
  }
  const runButton = button("تشغيل التحليل التقني وحفظ النتيجة", () => action(async () => {
    if (!source.value || !tool()) throw Error("اختر ملفًا وقدرة تقنية متاحة");
    clearOutput();
    const sourceId = source.value, toolId = select.value, epoch = selectionEpoch;
    const job = await api("run", {project_id:pid,name:"تحليل تقني: " + names[toolId],steps:[{tool:toolId,evidence_id:sourceId}]});
    if (!await refreshProject() || selectionEpoch !== epoch || select.value !== toolId || source.value !== sourceId) return;
    const result = job.results[0];
    if (job.status !== "succeeded" || result.status !== "succeeded") {
      output.replaceChildren(panel("تعذر تحليل الملف", el("p", {class:"notice"}, result.error || "رفض المحلل صيغة الملف أو تجاوز حدوده؛ لم تُعلن نتيجة ناجحة.")));
      selectedReport = null; exportReport.disabled = true;
      return;
    }
    saved.value = result.evidence_id;
    renderReport(result.output,result.evidence_id,false);
  }), "primary");
  upload.addEventListener("change", () => action(async () => {
    const file = upload.files[0];
    if (!file) return;
    if (file.size > 4 * 1024 * 1024) throw Error("حد التحليل التقني 4 MiB للملف؛ للشهادات حد أصغر");
    const bytes = new Uint8Array(await file.arrayBuffer());
    let raw = "";
    for (let i = 0; i < bytes.length; i += 32768) raw += String.fromCharCode(...bytes.subarray(i,i + 32768));
    const result = await api("upload", {project_id:pid,name:file.name,base64:btoa(raw)});
    if (await refreshProject()) updateSources(result.id);
    upload.value = "";
  }));
  const holder = el("div", {}, panel("التحليل التقني للملفات",field("القدرة التقنية",select),information,
      field("رفع ملف للتحليل التقني",upload),field("ملف التحليل التقني",source),
      el("div", {class:"actions"},button("إنشاء عينة تقنية اصطناعية", () => action(async () => {
        const item = tool();
        if (!item || item.sample === null) throw Error("لا توجد عينة مسجلة لهذه القدرة");
        const epoch = selectionEpoch;
        const original = await researchUpload(pid,"synthetic-technical-" + item.id + ".json",item.sample);
        if (await refreshProject() && selectionEpoch === epoch && select.value === item.id) updateSources(original.id);
      })),runButton,exportReport)),
    panel("النتائج التقنية المحفوظة",field("نتيجة تقنية محفوظة",saved),button("عرض النتيجة التقنية المحفوظة", () => action(async () => {
      clearOutput();
      const savedId = saved.value, toolId = select.value, epoch = selectionEpoch;
      const metadata = state.project.evidence.find(item => item.id === savedId);
      if (!metadata || metadata.kind !== "result") throw Error("اختر نتيجة محفوظة في المشروع");
      const blob = await api("evidence?project=" + pid + "&id=" + savedId,undefined,true);
      const report = JSON.parse(await blob.text());
      const original = state.project.evidence.find(item => item.id === report.input_evidence);
      if (!report.result || report.tool !== toolId || !original || metadata.parent_id !== original.id || original.sha256 !== report.input_sha256) throw Error("مراجع النتيجة لا تطابق أصلها المحفوظ");
      await api("evidence?project=" + pid + "&id=" + original.id,undefined,true);
      if (active() && selectionEpoch === epoch && select.value === toolId && saved.value === savedId) renderReport(report,metadata.id,true);
    }))),output);
  updateSources(); describe();
  return holder;
}
