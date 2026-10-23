/* Immutable private report snapshots; all owner strings remain text nodes. */
function caseReportsPage() {
  const missing = requireProject();
  if (missing) return missing;
  const pid = state.project.project.id;
  const selectedEvidence = new Set(), selectedPlans = new Set();
  const title = el("input", {"aria-label":"عنوان تقرير المشروع", maxlength:120, value:"تقرير نتائج المشروع"});
  const query = el("input", {"aria-label":"بحث أدلة التقرير", placeholder:"ابحث في أسماء الأدلة"});
  const sources = el("div"), planRows = el("div"), output = el("div", {"aria-live":"polite"});
  const scan = el("select", {"aria-label":"لقطة تغطية التقرير"}, el("option", {value:""}, "دون لقطة تغطية"));
  const saved = el("select", {"aria-label":"تقرير مشروع محفوظ"});
  let current = null, reportId = null;
  const jsonButton = button("تنزيل تقرير المشروع JSON", () => {
    if (current) download(new Blob([JSON.stringify(current,null,2)], {type:"application/json"}), "project-report-" + reportId + ".json");
  });
  const htmlButton = button("تنزيل تقرير المشروع HTML", () => action(async () => {
    if (reportId) download(await api("case-reports?project=" + pid + "&id=" + reportId + "&format=html", undefined, true), "project-report-" + reportId + ".html");
  }));
  const verifyButton = button("إعادة فحص مراجع التقرير", () => action(async () => {
    if (!reportId) return;
    const result = await api("case-reports/verify", {project_id:pid, report_id:reportId});
    if (!output.isConnected) return;
    output.append(el("p", {class:"notice"}, result.passed ? "مراجع التقرير مطابقة عند الفحص" : "تغيرت مراجع تحتاج مراجعة"), pre(result));
  }));
  for (const b of [jsonButton,htmlButton,verifyButton]) b.disabled = true;
  function show(id, report) {
    reportId = id; current = report;
    for (const b of [jsonButton,htmlButton,verifyButton]) b.disabled = false;
    output.replaceChildren(el("h3", {}, report.title), el("p", {}, report.notice),
      el("p", {}, "أدلة: " + report.evidence.length + " · خطط: " + report.plans.length + " · لقطة تغطية: " + (report.coverage ? "مرفقة":"غير مرفقة")),
      table(["الدليل", "النوع", "التحقق"], report.evidence.map(item => [item.name,evidenceKindLabel(item.kind),uiLabel(item.verification)])),
      el("details", {}, el("summary", {}, "بصمات التقرير ومراجعه"), pre({digest:report.digest, engine_sha256:report.engine_sha256, created:report.created})),
      el("p", {class:"muted"}, "التقرير لا يضم بايتات الملفات الأصلية. المطابقة تعني سلامة المراجع؛ لا تعني اعتماد التحقيق أو صحة كل نتيجة أو حماية حية."));
  }
  function renderSources() {
    const all = state.project.evidence.filter(item => item.kind !== "project-report" && item.name.toLowerCase().includes(query.value.toLowerCase()));
    sources.replaceChildren(el("p", {class:"muted"}, "يعرض آخر200دليل مطابق. اختر حتى50دليلًا، وبحدود قراءة32MiBتشمل إثبات الخطط."),
      ...all.slice(0,200).map(item => {
        const check = el("input", {type:"checkbox", name:"report-evidence", value:item.id, checked:selectedEvidence.has(item.id), onchange:() => check.checked ? selectedEvidence.add(item.id):selectedEvidence.delete(item.id)});
        return field(item.name + " · " + evidenceKindLabel(item.kind) + " · " + size(item.size), check);
      }));
  }
  query.addEventListener("input", renderSources);
  async function history() {
    const data = await api("case-reports/history?project=" + pid);
    if (!saved.isConnected) return;
    saved.replaceChildren(el("option", {value:""}, "اختر تقريرًا محفوظًا"), ...data.reports.map(item => el("option", {value:item.id, selected:item.id===reportId}, when(item.created) + " · " + item.id)));
  }
  const holder = el("div", {}, panel("تقرير مشروع قابل للتتبع",
    el("p", {class:"notice"}, "لقطة خاصة من الأدلة والخطط ونتائج التغطية المختارة، مع بصمات ومصادر. التصدير يدوي إلى جهازك؛ لا يُرفع التقرير إلى GitHub أو جهة خارجية."),
    field("عنوان تقرير المشروع", title), field("بحث أدلة التقرير", query), sources,
    panel("خطط محفوظة للتقرير", el("p", {class:"muted"}, "اختر حتى5خطط. تُفحص مصادرها ضمن ميزانية القراءة؛ قد يرفض التقرير نطاقًا كبيرًا."), planRows),
    field("لقطة تغطية التقرير", scan),
    button("إنشاء تقرير المشروع وحفظه", () => action(async () => {
      const data = await api("case-reports/build", {project_id:pid, title:title.value, evidence_ids:[...selectedEvidence], plan_run_ids:[...selectedPlans], coverage_scan_id:scan.value || null});
      const fresh = await api("project?id=" + pid);
      if (!output.isConnected || state.project?.project.id !== pid) return;
      state.project = fresh; show(data.evidence.id,data.report); await history();
    }), "primary")),
    panel("تقارير المشروع المحفوظة", field("تقرير مشروع محفوظ", saved), button("عرض تقرير المشروع المحفوظ", () => action(async () => {
      if (!saved.value) throw Error("اختر تقريرًا محفوظًا");
      const data = await api("case-reports?project=" + pid + "&id=" + saved.value);
      if (output.isConnected) show(saved.value,data);
    })), el("div", {class:"actions"}, jsonButton,htmlButton,verifyButton), output));
  renderSources();
  api("plans/history?project=" + pid).then(data => {
    if (!planRows.isConnected) return;
    planRows.replaceChildren(...data.runs.map(item => {
      const check = el("input", {type:"checkbox", name:"report-plan", value:item.id, onchange:() => check.checked ? selectedPlans.add(item.id):selectedPlans.delete(item.id)});
      return field(item.name + " · " + uiLabel(item.status) + " · " + item.id, check);
    }));
  }).catch(e => { if (planRows.isConnected) toast(e.message,true); });
  api("coverage/scans/history?project=" + pid).then(data => {
    if (!scan.isConnected) return;
    scan.append(...data.scans.filter(item => item.status === "completed").map(item => el("option", {value:item.id}, item.id + " · لقطة تاريخية مكتملة")));
  }).catch(e => { if (scan.isConnected) toast(e.message,true); });
  history().catch(e => { if (saved.isConnected) toast(e.message,true); });
  return holder;
}
