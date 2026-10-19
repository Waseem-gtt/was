/* Local, evidence-backed coverage. Status is always derived by the server. */
function defenseCoveragePage() {
  const missing = requireProject();
  if (missing) return missing;
  const pid = state.project.project.id;
  const labels = {supported:"مدعوم باختبار محفوظ", gap:"فجوة كشف في الاختبار", unverified:"غير متحقق", stale:"دليل متقادم أو غير سليم", conflict:"اختبارات متعارضة", untested:"لم يُختبر"};
  const kinds = {host:"جهاز", service:"خدمة", data:"بيانات", network:"شبكة"};
  const reasonLabels = {no_assessment:"لا يوجد تقييم مرتبط", verification_budget:"تجاوز حد التحقق في هذه القراءة", contradictory_current_tests:"نتائج اختبارات حالية متعارضة"};
  const content = el("div", {"aria-live":"polite"}, "تحميل خريطة التغطية…");
  const name = el("input", {"aria-label":"اسم أصل التغطية", maxlength:120});
  const kind = el("select", {"aria-label":"نوع أصل التغطية"},
    ...Object.entries(kinds).map(([id, title]) => el("option", {value:id}, title)));
  const asset = el("select", {"aria-label":"أصل تقييم التغطية"});
  const evidence = el("select", {"aria-label":"دليل تقييم التغطية"});
  const threat = el("input", {"aria-label":"تهديد التغطية", maxlength:120});
  const control = el("input", {"aria-label":"إجراء الحماية", maxlength:120});
  let snapshot = null;
  const exportButton = button("تنزيل خريطة التغطية JSON", () => {
    if (snapshot) download(new Blob([JSON.stringify(snapshot, null, 2)], {type:"application/json"}), "coverage-" + pid + ".json");
  });
  exportButton.disabled = true;
  const holder = el("div", {class:"stack"},
    panel("حدود خريطة التغطية",
      el("p", {class:"notice"}, "خريطة ثابتة تربط الأصل والتهديد وإجراء الحماية بدليل محفوظ. نجاح اختبار اصطناعي لا يثبت حماية الأصل الحقيقي، ولا توجد نسبة حماية عامة أو مراقبة حية."),
      el("p", {}, "الحالة يحسبها الخادم من سلامة الدليل ونتائج الاختبار؛ إضافة وصف أو دليل عادي تُسجل كتقييم غير متحقق."),
      el("div", {class:"actions"}, button("تحديث خريطة التغطية", () => action(load)), exportButton)),
    panel("إضافة أصل للتغطية", field("اسم أصل التغطية", name), field("نوع أصل التغطية", kind),
      button("إضافة أصل للتغطية", () => action(async () => {
        if (!name.value.trim()) throw Error("اكتب اسم الأصل أولًا");
        const created = await api("coverage/asset", {project_id:pid, name:name.value, kind:kind.value});
        name.value = "";
        await load(created.id);
      }), "primary")),
    panel("ربط اختبار أو دليل بإجراء حماية",
      field("أصل تقييم التغطية", asset), field("تهديد التغطية", threat), field("إجراء الحماية", control), field("دليل تقييم التغطية", evidence),
      el("p", {class:"muted"}, "اختر تقرير اختبار كشف موثقًا لقياس نتيجته، أو دليلًا عاديًا يبقى غير متحقق. الارتباط وصف يحدده المالك؛ لا يثبت أن الاختبار شُغّل على الأصل الحقيقي."),
      button("إضافة تقييم التغطية", () => action(async () => {
        if (!asset.value || !evidence.value || !threat.value.trim() || !control.value.trim()) throw Error("أكمل الأصل والتهديد وإجراء الحماية والدليل");
        await api("coverage/assessment", {project_id:pid, asset_id:asset.value, threat:threat.value, control:control.value, evidence_id:evidence.value});
        await load();
      }), "primary")), content);
  const status = value => badge(labels[value] || value, value === "supported" ? "good" : "warn");
  async function load(preferredAsset) {
    const [data, project] = await Promise.all([api("coverage?project=" + encodeURIComponent(pid)), api("project?id=" + encodeURIComponent(pid))]);
    if (!holder.isConnected) return;
    snapshot = data;
    exportButton.disabled = false;
    const selectedAsset = typeof preferredAsset === "string" ? preferredAsset : asset.value;
    const selectedEvidence = evidence.value;
    asset.replaceChildren(el("option", {value:""}, "اختر الأصل"), ...data.assets.map(item => el("option", {value:item.id, selected:item.id === selectedAsset}, item.name)));
    evidence.replaceChildren(el("option", {value:""}, "اختر الدليل"), ...project.evidence.map(item => el("option", {value:item.id, selected:item.id === selectedEvidence}, item.name + (item.kind === "detection-test" ? " · تقرير اختبار كشف" : " · دليل غير متحقق"))));
    const assetName = id => data.assets.find(item => item.id === id)?.name || id;
    const evidenceName = id => project.evidence.find(item => item.id === id)?.name || id;
    content.replaceChildren(
      panel("ملخص التغطية المحفوظة", el("p", {}, data.limitation),
        el("p", {}, "الأصول: " + data.summary.assets + " · التقييمات: " + data.summary.assessments + " · أصول لم تُختبر: " + data.summary.untested),
        table(["حالة التقييم", "العدد"], ["supported", "gap", "unverified", "stale", "conflict"].map(key => [labels[key], data.summary[key]]))),
      panel("الأصول وحالة اختبارها", data.assets.length ? table(["الأصل", "النوع", "الحالة", "التقييمات"], data.assets.map(item => [item.name, kinds[item.kind] || item.kind, status(item.status), item.assessment_count])) : el("p", {}, "لا توجد أصول مسجلة بعد")),
      panel("العلاقات بين الأصل والتهديد والحماية والدليل", data.assessments.length ? table(["الأصل", "التهديد", "إجراء الحماية", "الدليل", "الحالة", "إدارة الارتباط"], data.assessments.map(item => [
        assetName(item.asset_id), item.threat, item.control,
        el("details", {}, el("summary", {}, evidenceName(item.evidence_id)), pre(item.snapshot)), status(item.status),
        button("إزالة تقييم " + item.control, () => action(async () => {
          await api("coverage/remove", {project_id:pid, assessment_id:item.id});
          await load();
          toast("أزيل ارتباط التقييم؛ بقي ملف الدليل محفوظًا");
        })),
      ])) : el("p", {}, "لا توجد علاقات تقييم؛ الأصول المسجلة تظهر ضمن الفجوات لغياب الاختبار"),
        el("p", {class:"muted"}, "الإزالة تحذف ارتباط التقييم فقط ولا تحذف الأدلة أو تقارير الاختبار.")),
      panel("الفجوات وما يحتاج مراجعة", data.gaps.length ? table(["الأصل", "الحالة", "سبب المراجعة"], data.gaps.map(item => [assetName(item.asset_id), status(item.status), reasonLabels[item.reason] || labels[item.reason] || item.reason])) : el("p", {}, "لا توجد فجوات مسجلة ضمن العلاقات الحالية؛ هذا لا يثبت اكتمال الحماية.")));
  }
  load().catch(error => { if (holder.isConnected) toast(error.message, true); });
  return holder;
}
