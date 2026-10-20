/* Persisted, bounded verification of a historical coverage snapshot. */
function coverageScansPanel(projectId) {
  const labels = {pending:"بانتظار الدفعة الأولى", running:"قيد التحقق", completed:"اكتمل فحص اللقطة", failed:"توقف التحقق ويحتاج مراجعة"};
  const phases = {verify:"التحقق من التقييمات", finalize:"التحقق النهائي من ملفات الإثبات", done:"انتهت اللقطة"};
  const statuses = {supported:"مدعوم باختبار محفوظ", gap:"فجوة كشف", unverified:"غير متحقق", stale:"متقادم أو غير سليم", conflict:"اختبارات متعارضة", untested:"لم يُختبر"};
  const reasons = {pending_verification:"لم تصل إليه الدفعات بعد", no_assessment:"لا يوجد تقييم مرتبط", contradictory_current_tests:"اختبارات متعارضة", verification_budget:"لم يُتحقق منه ضمن الميزانية"};
  const saved = el("select", {"aria-label":"فحص تغطية شامل محفوظ"}, el("option", {value:""}, "اختر فحص تغطية محفوظًا"));
  const output = el("div", {"aria-live":"polite"});
  let selected = null;
  const previous = state.coverageScanSelection;
  let selectedId = previous?.projectId === projectId ? previous.scanId : null;
  const exporting = button("تنزيل تقرير فحص التغطية الشامل JSON", () => {
    if (selected) download(new Blob([JSON.stringify(selected, null, 2)], {type:"application/json"}), "coverage-scan-" + selected.id + ".json");
  });
  exporting.disabled = true;
  const advance = button("تشغيل دفعة التغطية الشاملة التالية", () => action(async () => {
    if (!selectedId) throw Error("اختر فحص تغطية أولًا");
    const scan = await api("coverage/scans/advance", {project_id:projectId, scan_id:selectedId});
    if (!active()) return;
    show(scan);
    await history();
  }));
  advance.disabled = true;
  const holder = panel("فحص التغطية الشامل على دفعات",
    el("p", {class:"notice"}, "يفحص جميع تقييمات لقطة محفوظة على دفعات، ويتحقق من ملفات الإثبات قبل اكتمالها. النتيجة تاريخية ومتتابعة، وليست مراقبة حية أو ضمان حماية حالية. اكتمال الفحص لا يعني أن كل التقييمات مدعومة."),
    el("p", {}, "ابدأ فحصًا ثم تابع الدفعات حتى تنتهي مرحلتا التقييمات وملفات الإثبات. يمكنك مغادرة الصفحة واستكمال الفحص المحفوظ؛ لا تعمل الدفعات في الخلفية تلقائيًا."),
    el("div", {class:"actions"}, button("بدء فحص تغطية شامل", () => action(async () => {
      const scan = await api("coverage/scans/start", {project_id:projectId});
      if (!active()) return;
      show(scan);
      await history();
    }), "primary"), advance),
    field("فحص تغطية شامل محفوظ", saved),
    button("عرض فحص التغطية الشامل المحفوظ", () => action(async () => {
      if (!saved.value) throw Error("اختر فحص تغطية محفوظًا أولًا");
      const scan = await api("coverage/scans?project=" + encodeURIComponent(projectId) + "&scan=" + encodeURIComponent(saved.value));
      if (active()) show(scan);
    })), exporting, output);

  function active() {
    return holder.isConnected && state.project?.project.id === projectId;
  }
  function show(scan) {
    selected = scan;
    selectedId = scan.id;
    state.coverageScanSelection = {projectId, scanId:scan.id};
    exporting.disabled = false;
    advance.disabled = !["pending", "running"].includes(scan.status);
    const counts = scan.counts;
    const proof = scan.proof_counts;
    const complete = scan.status === "completed" && scan.complete === true;
    const title = complete ? "اكتمل التحقق من اللقطة المحفوظة" : labels[scan.status] || scan.status;
    const assetName = id => scan.assets.find(item => item.id === id)?.name || id;
    output.replaceChildren(
      el("p", {}, badge(title, complete ? "good":"warn")),
      el("p", {}, "معرّف فحص التغطية الشامل: ", el("span", {class:"code"}, scan.id)),
      el("p", {}, "مرحلة الفحص: " + (phases[scan.phase] || scan.phase)),
      el("progress", {max:Math.max(counts.total, 1), value:counts.processed, "aria-label":"تقدم تقييمات التغطية الشاملة"}),
      el("p", {}, "التقييمات المتحققة: " + counts.processed + " / " + counts.total + " · المتبقي: " + counts.remaining),
      proof ? el("p", {}, "ملفات الإثبات المتحققة: " + proof.checked + " / " + proof.total + " · المتبقي: " + proof.remaining) : null,
      scan.phase === "finalize" ? el("p", {class:"notice"}, "انتهت مراجعة التقييمات، لكن فحص ملفات الإثبات لم يكتمل بعد؛ تابع الدفعات.") : null,
      scan.error_code ? el("p", {class:"notice"}, "توقف الفحص: " + scan.error_code + ". لا تعتمد هذه اللقطة كمكتملة؛ ابدأ فحصًا جديدًا بعد المراجعة.") : null,
      complete ? el("p", {}, scan.all_supported === true ? "كل التقييمات في هذه اللقطة مدعومة باختبار محفوظ؛ هذا لا يثبت حماية الأصول الحقيقية." : "اكتملت مراجعة اللقطة؛ راجع الفجوات والتقييمات غير المتحققة أدناه.") : el("p", {class:"notice"}, "الفحص غير مكتمل؛ الحالات التي لم تُراجع لا تُحسب نجاحًا."),
      scan.summary ? table(["حالة التقييم", "العدد"], Object.entries(statuses).map(([key, label]) => [label, scan.summary[key] ?? 0])) : null,
      scan.results.length ? table(["الأصل", "التهديد", "إجراء الحماية", "الحالة", "سبب المراجعة"], scan.results.map(item => [assetName(item.asset_id), item.threat, item.control, statuses[item.status] || item.status, reasons[item.reason] || statuses[item.reason] || item.reason])) : el("p", {}, "لا توجد تقييمات ضمن هذه اللقطة."),
      el("p", {class:"muted"}, scan.notice),
      el("p", {class:"muted"}, "صلاحية النتيجة: لقطة تاريخية فقط؛ أي تغييرات لاحقة تحتاج فحصًا جديدًا."));
  }
  async function history() {
    const data = await api("coverage/scans/history?project=" + encodeURIComponent(projectId));
    if (!active()) return;
    saved.replaceChildren(el("option", {value:""}, "اختر فحص تغطية محفوظًا"), ...data.scans.map(scan =>
      el("option", {value:scan.id, selected:scan.id === selectedId}, scan.id + " · " + (labels[scan.status] || scan.status))));
  }
  history().catch(error => { if (active()) toast(error.message, true); });
  if (selectedId) {
    const id = selectedId;
    api("coverage/scans?project=" + encodeURIComponent(projectId) + "&scan=" + encodeURIComponent(id)).then(scan => {
      if (active() && selectedId === id) show(scan);
    }).catch(error => { if (active()) toast(error.message, true); });
  }
  return holder;
}
