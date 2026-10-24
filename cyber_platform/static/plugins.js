/* Offline plugin metadata governance. A manifest never grants code execution. */
function pluginsPage() {
  const missing = requireProject();
  if (missing) return missing;
  const pid = state.project.project.id;
  const evidence = el("select", {"aria-label":"ملف بيان الإضافة"});
  const chosen = el("select", {"aria-label":"الإضافة المسجلة"});
  const reason = el("textarea", {"aria-label":"سبب قرار الإضافة", maxlength:1000, rows:3});
  const content = el("div", {"aria-live":"polite"}, "تحميل سجل الإضافات…");
  const details = el("div", {"aria-live":"polite"});
  const labels = {pending:"بانتظار المراجعة", approved:"معتمد كبيانات وصفية", disabled:"معطل إداريًا", revoked:"مسحوب الاعتماد", blocked:"اعتماد محجوب بتعارض"};
  const actions = {approve:"اعتماد بيانات الإضافة", disable:"تعطيل اعتماد الإضافة", revoke:"سحب اعتماد الإضافة"};
  let snapshot = null;
  const exportButton = button("تنزيل سجل الإضافات JSON", () => {
    if (snapshot) researchJsonDownload(snapshot, "plugin-registry-" + pid + ".json");
  });
  exportButton.disabled = true;
  function selected() { return snapshot?.items.find(item => item.id === chosen.value); }
  function show() {
    const item = selected();
    for (const [action, btn] of Object.entries(decisions)) {
      btn.disabled = !item || item.state === "revoked" ||
        (action === "approve" && (item.state === "approved" || item.issues.length > 0)) ||
        (action === "disable" && item.state === "disabled");
    }
    if (!item) {
      details.replaceChildren(el("p", {}, "اختر إضافة مسجلة لمراجعة بيانها وسجل قراراتها."));
      return;
    }
    details.replaceChildren(
      el("h3", {}, item.id),
      el("p", {}, "الحالة المسجلة: " + (labels[item.state] || item.state) + " · الحالة الحالية: " + (labels[item.effective_state] || item.effective_state)),
      el("p", {}, "المراجعة: " + item.revision + " · الإصدار: " + item.manifest.version + " · الترخيص: " + item.manifest.license),
      el("p", {}, "المصدر المعلن: " + item.manifest.source),
      el("p", {class:"muted"}, "المصدر تصريح داخل البيان؛ لا يجري تنزيله أو التحقق من هوية ناشره. الاعتماد هنا قرار بشأن البيانات الوصفية فقط."),
      table(["الصلاحيات المعلنة"], item.manifest.permissions.map(value => [value])),
      item.issues.length ? table(["ما يحتاج مراجعة", "الوصف"], item.issues.map(issue => [uiLabel(issue.code), issue.message])) : el("p", {}, "لا توجد تعارضات في فحوص البيانات الحالية؛ هذا لا يثبت سلامة كود الإضافة."),
      el("details", {}, el("summary", {}, "البيان وبصمات مصادره"), pre({manifest:item.manifest, source_evidence:item.source_evidence, source_sha256:item.source_sha256, manifest_sha256:item.manifest_sha256, evidence_id:item.evidence_id})),
      table(["المراجعة", "القرار", "الحالة", "السبب", "دليل القرار"], item.history.map(row => [row.revision, actions[row.action] || row.action, labels[row.state] || row.state, row.reason, row.evidence_id])));
  }
  chosen.addEventListener("change", show);
  const decisions = Object.fromEntries(Object.entries(actions).map(([action, label]) => [action, button(label, () => actionDecision(action))]));
  async function actionDecision(decision) {
    await action(async () => {
      const item = selected();
      if (!item) throw Error("اختر إضافة مسجلة");
      if (!reason.value.trim()) throw Error("اكتب سبب القرار أولًا");
      await api("plugins/transition", {project_id:pid, plugin_id:item.id, action:decision, reason:reason.value});
      reason.value = "";
      await load(item.id);
    });
  }
  const holder = el("div", {},
    panel("مراجعة الإضافات دون تشغيلها",
      el("p", {class:"notice"}, "سجل خاص لبيانات الإضافات ومصادرها وتراخيصها وصلاحياتها واعتمادها. لا تُثبت الإضافات ولا يُنفذ كودها؛ الملفات المرفوعة تبقى أدلة. لا يمنح قرار الاعتماد صلاحية تشغيل."),
      el("p", {}, "تُفحص التبعيات والإصدارات والتوافق والدورات والصلاحيات قبل اعتماد البيانات. تغير التبعيات قد يحجب اعتمادًا سابقًا؛ القرارات الأصلية تبقى محفوظة."),
      el("div", {class:"actions"}, button("تحديث سجل الإضافات", () => action(load)), exportButton)),
    panel("تسجيل بيان إضافة",
      field("ملف بيان الإضافة", evidence),
      el("div", {class:"actions"}, button("إنشاء بيان إضافة تجريبي", () => action(async () => {
        const sample = {id:"owner.example", version:"1.0.0", license:"MIT", source:"https://example.test/project", permissions:["selected_evidence.read"], dependencies:[]};
        const file = await researchUpload(pid, "synthetic-plugin-manifest.json", JSON.stringify(sample));
        await load(undefined, file.id);
        toast("حُفظ بيان اصطناعي؛ راجعه ثم سجله");
      })), button("تسجيل بيان الإضافة", () => action(async () => {
        if (!evidence.value) throw Error("اختر ملف بيان JSON أولًا");
        const result = await api("plugins/register", {project_id:pid, evidence_id:evidence.value});
        await load(result.item.id);
      }), "primary")),
      el("p", {class:"muted"}, "اختر ملفًا من أدلة المشروع. لا يُرفع أي شيء إلى جهة خارجية، ولا يُفتح عنوان المصدر المعلن.")),
    content,
    panel("قرار مراجعة البيانات الوصفية", field("الإضافة المسجلة", chosen), details,
      field("سبب قرار الإضافة", reason), el("div", {class:"actions"}, ...Object.values(decisions))));
  async function load(preferredId, preferredEvidence) {
    const [data, project] = await Promise.all([api("plugins?project=" + encodeURIComponent(pid)), api("project?id=" + encodeURIComponent(pid))]);
    if (!holder.isConnected || state.project?.project.id !== pid) return;
    const previous = typeof preferredId === "string" ? preferredId : chosen.value;
    const original = typeof preferredEvidence === "string" ? preferredEvidence : evidence.value;
    snapshot = data;
    state.project = project;
    exportButton.disabled = false;
    evidence.replaceChildren(el("option", {value:""}, "اختر ملف البيان"), ...project.evidence.map(item => el("option", {value:item.id, selected:item.id === original}, item.name + " · " + evidenceKindLabel(item.kind))));
    chosen.replaceChildren(el("option", {value:""}, "اختر إضافة مسجلة"), ...data.items.map(item => el("option", {value:item.id, selected:item.id === previous}, item.id + " · " + item.manifest.version)));
    content.replaceChildren(
      panel("الإضافات المسجلة", el("p", {}, data.notice), data.items.length ? table(["المعرف", "الإصدار", "الترخيص", "الحالة", "المراجعة", "عرض"], data.items.map(item => [item.id, item.manifest.version, item.manifest.license, labels[item.effective_state] || item.effective_state, item.revision, button("مراجعة إضافة " + item.id, () => {chosen.value = item.id; show();})])) : el("p", {}, "لا توجد بيانات إضافات مسجلة.")),
      panel("خريطة تبعيات الإضافات", data.graph.edges.length ? table(["الإضافة", "التبعية", "الإصدار المطلوب"], data.graph.edges.map(edge => [edge.source, edge.target, edge.required_version])) : el("p", {}, "لا توجد تبعيات معلنة."),
        data.graph.issues.length ? table(["الإضافة", "التعارض", "الوصف"], data.graph.issues.map(issue => [issue.plugin_id, uiLabel(issue.code), issue.message])) : el("p", {}, "لا توجد تعارضات تبعية مسجلة ضمن النطاق الحالي."),
        el("details", {}, el("summary", {}, "حدود السجل وبصمته"), pre({limits:data.limits, digest:data.digest}))));
    show();
  }
  for (const btn of Object.values(decisions)) btn.disabled = true;
  load().catch(error => {if (holder.isConnected) toast(error.message, true);}).finally(() => {
    if (holder.isConnected && state.project?.project.id === pid) holder.append(pluginInstallationsPanel());
  });
  return holder;
}
