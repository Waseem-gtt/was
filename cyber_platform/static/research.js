/* Project event normalization and exact-match detection; local text nodes only. */
function researchEvidenceSelect(label) {
  return el("select", {"aria-label":label}, el("option", {value:""}, "اختر دليلًا…"),
    state.project.evidence.map(item => el("option", {value:item.id}, item.name + " · " + item.kind)));
}
async function researchUpload(projectId, name, text) {
  const bytes = new TextEncoder().encode(text);
  let raw = "";
  for (let i = 0; i < bytes.length; i += 32768) raw += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return api("upload", {project_id:projectId, name, base64:btoa(raw)});
}
function researchJsonDownload(value, name) {
  download(new Blob([JSON.stringify(value, null, 2)], {type:"application/json"}), name);
}
function eventAdaptersPage() {
  const missing = requireProject();
  if (missing) return missing;
  const projectId = state.project.project.id;
  const source = researchEvidenceSelect("دليل الأحداث الأصلي");
  const adapter = el("select", {"aria-label":"صيغة الأحداث"});
  const information = el("div"), output = el("div", {"aria-live":"polite"});
  let adapters = [], selectedReport = null;
  const exportReport = button("تنزيل تقرير توحيد الأحداث JSON", () => researchJsonDownload(selectedReport, "normalized-events.json"));
  exportReport.disabled = true;
  function updateInfo() {
    const item = adapters.find(row => row.id === adapter.value);
    information.replaceChildren(item ? el("p", {}, item.description) : el("p", {}, "جارٍ تحميل الصيغ…"));
  }
  adapter.addEventListener("change", updateInfo);
  function refreshSources() {
    const chosen = source.value;
    source.replaceChildren(el("option", {value:""}, "اختر دليلًا…"), ...state.project.evidence.map(item => el("option", {value:item.id, selected:item.id === chosen}, item.name + " · " + item.kind)));
  }
  const result = el("div", {}, panel("توحيد الأحداث وحفظ أصلها",
    el("p", {class:"notice"}, "محولات ملفات محددة لصيغة was.event/1؛ ليست دعمًا كاملًا لـOCSF أو استقبالًا حيًا. يحتفظ كل حدث بأصله وبصمة ملف الإدخال. لا يُعرض محتوى الأحداث تلقائيًا؛ التقرير المنزّل قد يحتوي بيانات حساسة."),
    field("دليل الأحداث الأصلي", source), field("صيغة الأحداث", adapter), information,
    el("div", {class:"actions"}, button("استيراد عينة أحداث اصطناعية", () => action(async () => {
      const item = adapters.find(row => row.id === adapter.value);
      if (!item) throw Error("انتظر تحميل الصيغ");
      const evidence = await researchUpload(projectId, "synthetic-" + item.id + ".txt", typeof item.example_content === "string" ? item.example_content : JSON.stringify(item.example_content));
      const fresh = await api("project?id=" + projectId);
      if (state.project?.project.id !== projectId || !source.isConnected) return;
      state.project = fresh;
      refreshSources();
      source.value = evidence.id || evidence.evidence?.id || "";
      toast("حُفظت عينة اصطناعية؛ ليست بيانات نظام حقيقي");
    })), button("توحيد الأحداث وحفظ النتيجة", () => action(async () => {
      if (!source.value || !adapter.value) throw Error("اختر دليلًا وصيغة أولًا");
      const data = await api("events/normalize", {project_id:projectId, evidence_id:source.value, adapter:adapter.value});
      const fresh = await api("project?id=" + projectId);
      if (!output.isConnected || state.project?.project.id !== projectId) return;
      state.project = fresh;
      refreshSources();
      selectedReport = data.report;
      const normalized = data.report.result || data.report;
      exportReport.disabled = false;
      output.replaceChildren(el("p", {}, "أحداث موحدة: " + normalized.count + " · أحداث نتيجتها فشل: " + normalized.failed),
        pre({schema:normalized.schema, adapter:normalized.adapter, input_sha256:data.report.input_sha256 || normalized.input_sha256, adapter_sha256:data.report.adapter_sha256, result_evidence:data.evidence.id}),
        normalized.limitations ? pre(normalized.limitations) : null);
    }), "primary")), exportReport, output));
  api("events/adapters").then(data => {
    if (!adapter.isConnected) return;
    adapters = Array.isArray(data) ? data : data.adapters;
    adapter.replaceChildren(...adapters.map(item => el("option", {value:item.id}, item.title)));
    updateInfo();
  }).catch(error => { if (adapter.isConnected) toast(error.message, true); });
  return result;
}
function detectionLibraryPage() {
  const missing = requireProject();
  if (missing) return missing;
  const projectId = state.project.project.id;
  const source = researchEvidenceSelect("دليل اختبار الكشف");
  const library = el("div"), fixtures = el("div"), output = el("div", {"aria-live":"polite"});
  const history = el("div"), editorOutput = el("div", {"aria-live":"polite"});
  const editor = el("textarea", {rows:12, "aria-label":"قاعدة المالك JSON", spellcheck:"false"});
  editor.value = JSON.stringify({id:"owner-login-failure",title:"فشل تسجيل الدخول — قاعدة المالك",version:"1.0.0",license:"Private",source:"Owner local rule",selection:{action:"login",outcome:"failure"}}, null, 2);
  let selectedReport = null;
  const exportReport = button("تنزيل تقرير اختبار الكشف JSON", () => researchJsonDownload(selectedReport, "detection-test.json"));
  exportReport.disabled = true;
  function show(report) {
    selectedReport = report;
    exportReport.disabled = false;
    const evaluated = report.evaluated_rules ?? report.result.evaluated_rules;
    const label = {passed:"اجتازت التوقعات المرجعية",failed:"أخفقت توقعات مرجعية",not_evaluated:"غير مقيّمة: لا توجد توقعات مرجعية"}[report.evaluation_status] || "راجع تفاصيل التقرير";
    output.replaceChildren(el("p", {}, badge(label, report.evaluation_status === "passed" ? "good":"warn")),
      el("p", {}, "أحداث: " + report.result.event_count + " · قواعد مقيّمة: " + evaluated),
      el("p", {class:"notice"}, "المطابقة وحدها لا تثبت فعالية دفاعية. القواعد بلا تسميات مرجعية تبقى غير مقيّمة، ولا تُحسب نجاحًا."),
      table(["القاعدة", "عدد المطابقات", "التقييم"], report.result.rules.map(rule => [rule.id, rule.matched_event_indexes.length,
        rule.metrics ? el("details", {}, el("summary", {}, rule.metrics.passed ? "اجتازت التوقعات":"تختلف عن التوقعات"), pre(rule.metrics)) : "غير مقيّمة"])),
      el("details", {}, el("summary", {}, "بصمات المصدر والقواعد والمحرك"), pre({input_sha256:report.input_sha256, rules_sha256:report.rules_sha256, engine_sha256:report.engine_sha256, bundle_sha256:report.bundle_sha256})));
  }
  function refreshSources() {
    const chosen = source.value;
    source.replaceChildren(el("option", {value:""}, "اختر دليلًا…"), ...state.project.evidence.map(item => el("option", {value:item.id, selected:item.id === chosen}, item.name + " · " + item.kind)));
    const rows = state.project.evidence.filter(item => item.kind === "detection-test");
    history.replaceChildren(rows.length ? table(["التقرير المحفوظ", "عرض"], rows.map(item => [item.name, button("عرض " + item.name, () => action(async () => {
      const blob = await api("evidence?project=" + projectId + "&id=" + item.id, undefined, true);
      const report = JSON.parse(await blob.text());
      if (output.isConnected) show(report);
    }))])) : el("p", {}, "لا توجد تقارير كشف محفوظة بعد"));
  }
  async function loadLibrary() {
    const data = await api("detection/library?project=" + projectId);
    if (!library.isConnected) return;
    library.replaceChildren(el("p", {}, data.notice), ...data.rules.map(rule => el("article", {class:"card"},
      field(rule.title + " · " + rule.id, el("input", {type:"checkbox", value:rule.id, name:"detection-rule", checked:rule.origin === "builtin"})),
      el("p", {}, (rule.origin === "owner" ? "قاعدة المالك · مراجعة " + rule.revision : "قاعدة مدمجة") + " · الإصدار " + rule.version),
      el("details", {}, el("summary", {}, "المصدر والترخيص والشروط"), pre({source:rule.source,license:rule.license,selection:rule.selection})),
      rule.origin === "owner" ? button("تحرير " + rule.id, () => { editor.value = JSON.stringify(Object.fromEntries(["id","title","version","license","source","selection"].map(key => [key, rule[key]])), null, 2); editor.focus(); }) : null)));
    fixtures.replaceChildren(...data.fixtures.map(fixture => button("استيراد عينة الكشف: " + fixture.title, () => action(async () => {
      const evidence = await researchUpload(projectId, "synthetic-detection-" + fixture.id + ".json", JSON.stringify(fixture.input));
      const fresh = await api("project?id=" + projectId);
      if (state.project?.project.id !== projectId || !source.isConnected) return;
      state.project = fresh;
      refreshSources();
      source.value = evidence.id || evidence.evidence?.id || "";
      toast("حُفظت عينة اصطناعية بتوقعاتها المرجعية؛ ليست قياسًا ميدانيًا");
    }))));
  }
  const result = el("div", {}, panel("مكتبة قواعد الكشف المحلية",
    el("p", {class:"notice"}, "مطابقة حقول وقيم صريحة فقط، دون تنفيذ كود أو صياغة Sigma الكاملة. قواعد المالك محفوظة كمراجعات مع بصمات؛ لا تُثبت إضافات خارجية."), library),
    panel("اختبار الكشف وتوثيق النتائج", el("p", {}, "العينات التالية اصطناعية وتتضمن تسميات متوقعة؛ يمكن اختيار دليل آخر بشرط أن يطابق صيغة الأحداث المدعومة."), fixtures,
      field("دليل اختبار الكشف", source), button("اختبار القواعد المختارة وحفظ التقرير", () => action(async () => {
        const ruleIds = [...library.querySelectorAll('input[name="detection-rule"]:checked')].map(node => node.value);
        if (!source.value || !ruleIds.length) throw Error("اختر دليلًا وقاعدة واحدة على الأقل");
        const data = await api("detection/test", {project_id:projectId, evidence_id:source.value, rule_ids:ruleIds});
        const fresh = await api("project?id=" + projectId);
        if (!output.isConnected || state.project?.project.id !== projectId) return;
        state.project = fresh;
        refreshSources();
        show(data.report);
      }), "primary"), exportReport, output),
    panel("حفظ مراجعة قاعدة المالك", field("قاعدة المالك JSON", editor), button("حفظ مراجعة القاعدة", () => action(async () => {
      const data = await api("detection/save", {project_id:projectId, rule:JSON.parse(editor.value)});
      if (!editorOutput.isConnected) return;
      const fresh = await api("project?id=" + projectId);
      if (state.project?.project.id !== projectId) return;
      state.project = fresh;
      refreshSources();
      await loadLibrary();
      if (editorOutput.isConnected) editorOutput.replaceChildren(el("p", {}, "حُفظت مراجعة القاعدة: " + data.revision));
    })), editorOutput), panel("تقارير الكشف المحفوظة", history));
  refreshSources();
  loadLibrary().catch(error => { if (library.isConnected) toast(error.message, true); });
  return result;
}
