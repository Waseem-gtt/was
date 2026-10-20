/* File-only technical analyzers. Uploaded data never grants execution authority. */
function technicalAnalysisPage() {
  const missing = requireProject();
  if (missing) return missing;
  const pid = state.project.project.id;
  const ids = ["pcap", "certificate", "supply-chain", "supply-chain-diff"];
  const names = {pcap:"تسجيلات الشبكة PCAP",certificate:"شهادات X.509","supply-chain":"مكونات البرمجيات واعتمادياتها","supply-chain-diff":"مقارنة جرد مكونات البرمجيات"};
  const descriptions = {
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
  let selectedReport = null;
  const active = () => holder.isConnected && state.project?.project.id === pid;
  const tool = () => state.boot.tools.find(item => item.id === select.value);
  const exportReport = button("تنزيل نتيجة التحليل التقني JSON", () => {
    if (selectedReport) researchJsonDownload(selectedReport, "technical-" + selectedReport.tool + ".json");
  });
  exportReport.disabled = true;
  function updateSources(preferred) {
    if (preferred && preferred !== source.value) {
      output.replaceChildren(); selectedReport = null; exportReport.disabled = true;
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
    output.replaceChildren(); selectedReport = null; exportReport.disabled = true;
    updateSaved();
  }
  select.addEventListener("change", describe);
  source.addEventListener("change", () => {
    output.replaceChildren(); selectedReport = null; exportReport.disabled = true;
  });
  saved.addEventListener("change", () => {
    output.replaceChildren(); selectedReport = null; exportReport.disabled = true;
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
    } else {
      summary.push(el("p", {}, "المكونات: " + value.component_count + " · الصيغة: " + value.format),
        el("p", {class:"notice"}, "هذه مراجعة للمعلومات المقدمة؛ غياب ملاحظة لا يثبت غياب ثغرات أو صحة الترخيص."),
        table(["المعرف", "المكون", "الإصدار", "الترخيص"], (value.components || []).map(row => [row.id,row.name,row.version || "—",typeof row.license === "string" ? row.license : JSON.stringify(row.licenses || row.license || [])])),
        el("details", {}, el("summary", {}, "الاعتماديات وملاحظات سلسلة التوريد"), pre({dependencies:value.dependencies,graph:value.graph,issues:value.issues,summary:value.summary})));
    }
    output.replaceChildren(panel("نتيجة التحليل التقني", badge(historical ? "نتيجة تاريخية محفوظة":"اكتمل تحليل الملف", "good"),
      el("p", {class:"muted"}, "نجاح تنفيذ التحليل ليس شهادة سلامة. " + (historical ? "تحققت قراءة الملفات وبصماتها دون إعادة تشغيل المحلل؛ قد تختلف نتائج إصدار أحدث." : "حُفظ الأصل والنتيجة كدليلين منفصلين.")),
      ...summary,
      el("details", {}, el("summary", {}, "الأصل والنتيجة وبصمات المصدر"), pre({input_evidence:report.input_evidence,input_sha256:report.input_sha256,source_sha256:sourceMetadata?.sha256,result_evidence:resultId,result_sha256:resultMetadata?.sha256,engine_version:report.engine_version,engine_sha256:report.engine_sha256,acceptance:report.acceptance})),
      el("details", {}, el("summary", {}, "التقرير التقني الكامل وحدوده"), pre(value))));
  }
  const runButton = button("تشغيل التحليل التقني وحفظ النتيجة", () => action(async () => {
    if (!source.value || !tool()) throw Error("اختر ملفًا وقدرة تقنية متاحة");
    output.replaceChildren(); selectedReport = null; exportReport.disabled = true;
    const sourceId = source.value;
    const job = await api("run", {project_id:pid,name:"تحليل تقني: " + names[select.value],steps:[{tool:select.value,evidence_id:sourceId}]});
    if (!await refreshProject()) return;
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
        const original = await researchUpload(pid,"synthetic-technical-" + item.id + ".json",item.sample);
        if (await refreshProject()) updateSources(original.id);
      })),runButton,exportReport)),
    panel("النتائج التقنية المحفوظة",field("نتيجة تقنية محفوظة",saved),button("عرض النتيجة التقنية المحفوظة", () => action(async () => {
      output.replaceChildren(); selectedReport = null; exportReport.disabled = true;
      const metadata = state.project.evidence.find(item => item.id === saved.value);
      if (!metadata || metadata.kind !== "result") throw Error("اختر نتيجة محفوظة في المشروع");
      const blob = await api("evidence?project=" + pid + "&id=" + saved.value,undefined,true);
      const report = JSON.parse(await blob.text());
      const original = state.project.evidence.find(item => item.id === report.input_evidence);
      if (!report.result || report.tool !== select.value || !original || metadata.parent_id !== original.id || original.sha256 !== report.input_sha256) throw Error("مراجع النتيجة لا تطابق أصلها المحفوظ");
      await api("evidence?project=" + pid + "&id=" + original.id,undefined,true);
      if (active()) renderReport(report,metadata.id,true);
    }))),output);
  updateSources(); describe();
  return holder;
}
