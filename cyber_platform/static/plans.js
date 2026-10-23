/* Saved analysis plans and reusable data templates; no executable expressions. */
function workflowPlansPage() {
  const missing = requireProject();
  if (missing) return missing;
  const projectId = state.project.project.id;
  const active = () => state.project?.project.id === projectId && output.isConnected;
  const statuses = {pending:"بانتظار التنفيذ",running:"قيد التنفيذ",paused:"متوقفة مؤقتًا",completed:"اكتمل التنفيذ",failed:"توقف التحقق"};
  const nodeStatuses = {pending:"لم تُنفّذ",succeeded:"نجحت",failed:"أخفقت",skipped:"تُخطيت بشرط الخطة"};
  const templateSelect = el("select", {"aria-label":"قالب خطة التحليل"});
  const bindings = el("div"), templateInfo = el("div"), fixtureButtons = el("div");
  const editor = el("textarea", {rows:15,"aria-label":"خطة التحليل JSON",spellcheck:"false"});
  editor.value = JSON.stringify({schema:"was.plan/1",name:"خطة تحليل خاصة",nodes:[]},null,2);
  const graph = el("div"), provenance = el("div");
  const output = el("div", {"aria-live":"polite"}), historySelect = el("select", {"aria-label":"خطة تشغيل محفوظة"});
  const templateEditor = el("textarea", {rows:13,"aria-label":"قالب المالك JSON",spellcheck:"false"});
  const templateSaved = el("div", {"aria-live":"polite"});
  let catalog = null, bindingSelectors = new Map(), selectedRun = null, lastInstantiation = null;
  const exportProof = button("تنزيل إثبات إنشاء الخطة JSON", () => {
    if (lastInstantiation) researchJsonDownload(lastInstantiation,"plan-instantiation.json");
  });
  exportProof.disabled = true;
  function matchesInstantiation(plan) {
    return lastInstantiation?.evidence?.id && JSON.stringify(plan) === JSON.stringify(lastInstantiation.plan);
  }
  function showInstantiation() {
    if (!lastInstantiation) { provenance.replaceChildren(); return; }
    let matching = false;
    try { matching = matchesInstantiation(JSON.parse(editor.value)); } catch {}
    provenance.replaceChildren(el("p",{},matching ? "أُنشئت الخطة للمراجعة؛ لم يبدأ التنفيذ" : "الخطة معدلة يدويًا؛ لن تُنسب إلى إثبات القالب السابق عند التشغيل"),
      pre({template_id:lastInstantiation.template_id,template_sha256:lastInstantiation.template_sha256,revision:lastInstantiation.revision,bindings:lastInstantiation.bindings,instantiation_id:lastInstantiation.evidence?.id || null}));
  }
  const advance = button("تنفيذ دفعة الخطة التالية", () => mutateRun("advance"), "primary");
  const pause = button("إيقاف الخطة مؤقتًا", () => mutateRun("pause"));
  const resume = button("استكمال الخطة المتوقفة", () => mutateRun("resume"));
  const exportRun = button("تنزيل تقرير خطة التحليل JSON", () => {
    if (selectedRun) researchJsonDownload(selectedRun,"analysis-plan-" + selectedRun.id + ".json");
  });
  for (const control of [advance,pause,resume,exportRun]) control.disabled = true;
  function preview() {
    try {
      const plan = JSON.parse(editor.value);
      if (!Array.isArray(plan.nodes)) throw Error();
      graph.replaceChildren(table(["العقدة","الأداة","المدخل","التبعيات","الشرط"],plan.nodes.map(node => [
        node.id ?? "", node.tool ?? "", JSON.stringify(node.input ?? {}),
        JSON.stringify(node.depends_on ?? []), JSON.stringify(node.when ?? null),
      ])), el("p",{class:"muted"},"هذا عرض للخطة فقط؛ يتحقق الخادم من الأدوات والتبعيات والدورات ومصادر الأدلة قبل التشغيل."));
    } catch {
      graph.replaceChildren(el("p",{class:"notice"},"أدخل خطة JSON تحتوي قائمة nodes لعرض العلاقات."));
    }
  }
  editor.addEventListener("input", () => { showInstantiation(); preview(); });
  function show(run) {
    selectedRun = run;
    state.planRun = {projectId,id:run.id};
    const completed = run.status === "completed";
    const counts = run.counts || {total:run.plan.nodes.length,completed:run.results.length,succeeded:0,failed:0,skipped:0};
    advance.disabled = !["pending","running"].includes(run.status);
    pause.disabled = !["pending","running"].includes(run.status);
    resume.disabled = run.status !== "paused";
    exportRun.disabled = false;
    const results = new Map(run.results.map(item => [item.node_id,item]));
    output.replaceChildren(
      el("p",{},badge(completed && run.passed === true ? "اجتازت الخطة خطواتها المنفذة" : statuses[run.status] || run.status,completed && run.passed === true ? "good":"warn")),
      el("p",{},"معرّف تشغيل الخطة: ",el("span",{class:"code"},run.id)),
      el("progress",{max:Math.max(counts.total,1),value:counts.completed,"aria-label":"تقدم عقد الخطة"}),
      el("p",{},"منتهية: " + counts.completed + " / " + counts.total + " · نجحت: " + counts.succeeded + " · أخفقت: " + counts.failed + " · تُخطيت: " + counts.skipped),
      completed && !run.passed ? el("p",{class:"notice"},"اكتمل تنفيذ الخطة مع إخفاقات أو دون نجاح كافٍ؛ لا تُعد العقد المتخطاة نجاحًا.") : null,
      run.error_code ? el("p",{class:"notice"},"توقف التحقق: " + run.error_code + ". راجع المصدر قبل بدء تشغيل جديد.") : null,
      table(["العقدة","الأداة","الحالة","الدليل والتوقيت"],run.plan.nodes.map(node => {
        const item = results.get(node.id);
        return [node.id,toolDisplayName(node.tool),item ? nodeStatuses[item.status] || item.status : nodeStatuses.pending,
          item ? el("details",{},el("summary",{},String(item.elapsed_ms ?? 0) + " ms"),pre({evidence_id:item.evidence_id || null,input_evidence:item.input_evidence || null,input_sha256:item.input_sha256 || null,output_sha256:item.output_sha256 || null,error_code:item.error_code || null,checks:item.checks || []})) : "—"];
      })),
      el("details",{},el("summary",{},"بصمات الخطة والمحرك"),pre({version:run.version,plan_sha256:run.plan_sha256,engine_sha256:run.engine_sha256})),
      run.template_origin ? el("details",{},el("summary",{},"مصدر قالب التشغيل"),pre(run.template_origin)) : el("p",{class:"muted"},"هذا التشغيل بلا إثبات قالب مرتبط؛ تُحفظ خطة التنفيذ نفسها."),
      el("p",{class:"muted"},"التنفيذ متتابع وعلى دفعات يطلبها المالك. الإيقاف بين الدفعات؛ لا يقطع عاملًا جاريًا ولا ينشئ مهام خلفية."));
  }
  async function loadHistory() {
    const data = await api("plans/history?project=" + projectId);
    if (!historySelect.isConnected || state.project?.project.id !== projectId) return;
    const chosen = selectedRun?.id || historySelect.value;
    historySelect.replaceChildren(el("option",{value:""},"اختر تشغيل خطة محفوظًا"),...data.runs.map(run =>
      el("option",{value:run.id,selected:run.id === chosen},(run.plan?.name || run.name || run.id) + " · " + (statuses[run.status] || run.status))));
  }
  function mutateRun(operation) {
    return action(async () => {
      if (!selectedRun) throw Error("اختر تشغيلًا محفوظًا أولًا");
      const run = await api("plans/" + operation,{project_id:projectId,run_id:selectedRun.id});
      if (!active()) return;
      show(run);
      await loadHistory();
      const fresh = await api("project?id=" + projectId);
      if (active()) state.project = fresh;
    });
  }
  function currentTemplate() {
    return catalog?.templates.find(item => item.id === templateSelect.value);
  }
  function setupBindings() {
    const template = currentTemplate();
    const previous = new Map([...bindingSelectors].map(([slot,select]) => [slot,select.value]));
    bindingSelectors = new Map();
    if (!template) { bindings.replaceChildren(); fixtureButtons.replaceChildren(); return; }
    const slots = [...new Set(template.plan.nodes.map(node => node.input?.slot).filter(slot => typeof slot === "string"))];
    bindings.replaceChildren(...slots.map(slot => {
      const select = el("select",{"aria-label":"دليل مدخل الخطة: " + slot},el("option",{value:""},"اختر دليلًا للمدخل " + slot),
        state.project.evidence.map(item => el("option",{value:item.id,selected:previous.get(slot) === item.id},item.name + " · " + evidenceKindLabel(item.kind))));
      bindingSelectors.set(slot,select);
      return field("دليل مدخل الخطة: " + slot,select);
    }));
    templateInfo.replaceChildren(el("p",{},template.description),el("p",{},"الإصدار " + template.version + " · المراجعة " + template.revision + " · " + (template.origin === "builtin" ? "قالب مدمج":"قالب المالك")),
      el("details",{},el("summary",{},"تعريف القالب وبصمته"),pre({template_sha256:template.template_sha256,plan:template.plan})));
    fixtureButtons.replaceChildren(...(catalog.fixtures || []).filter(fixture => fixture.template_id === template.id).map(fixture =>
      button("استيراد عينة القالب: " + fixture.title,() => action(async () => {
        const uploaded = new Map();
        for (const [slot,content] of Object.entries(fixture.inputs)) {
          const item = await researchUpload(projectId,"synthetic-plan-" + fixture.id + "-" + slot + ".txt",content);
          uploaded.set(slot,item.id || item.evidence?.id);
        }
        const fresh = await api("project?id=" + projectId);
        if (!active()) return;
        state.project = fresh;
        setupBindings();
        for (const [slot,evidenceId] of uploaded) if (bindingSelectors.has(slot)) bindingSelectors.get(slot).value = evidenceId;
        toast("حُفظت مدخلات اصطناعية للقالب؛ لم يبدأ تنفيذ الخطة");
      }))));
  }
  async function loadTemplates() {
    const data = await api("plans/templates?project=" + projectId);
    if (!templateSelect.isConnected || state.project?.project.id !== projectId) return;
    const chosen = templateSelect.value;
    catalog = data;
    templateSelect.replaceChildren(...data.templates.map(template => el("option",{value:template.id,selected:template.id === chosen},template.title + " · " + template.id)));
    setupBindings();
    if (!templateEditor.value && data.templates.length) {
      const item = data.templates[0];
      templateEditor.value = JSON.stringify({id:"owner-analysis-template",title:"قالب تحليل المالك",version:"1.0.0",description:"قالب بيانات خاص قابل لإعادة الاستخدام",plan:item.plan},null,2);
    }
  }
  templateSelect.addEventListener("change",setupBindings);
  const result = el("div",{},
    panel("قوالب تحليل قابلة لإعادة الاستخدام",el("p",{class:"notice"},"القوالب بيانات وخطوات لأدوات مسجلة فقط. ربط المدخلات يولد خطة قابلة للمراجعة؛ لا ينفذها ولا يثبت نجاحها."),
      field("قالب خطة التحليل",templateSelect),templateInfo,bindings,fixtureButtons,
      button("نسخ القالب المحدد لمراجعة المالك",() => {
        const item = currentTemplate();
        if (!item) return;
        templateEditor.value = JSON.stringify({id:item.origin === "owner" ? item.id : "owner-analysis-template",title:item.title,version:item.version,description:item.description,plan:item.plan},null,2);
        templateEditor.focus();
        templateSaved.replaceChildren(el("p",{},"نُسخ تعريف القالب فقط؛ غيّر المعرف أو رقم الإصدار قبل حفظ مراجعة جديدة."));
      }),
      button("إنشاء خطة من القالب دون تشغيل",() => action(async () => {
        const inputBindings = Object.fromEntries([...bindingSelectors].map(([slot,select]) => [slot,select.value]));
        if (Object.values(inputBindings).some(value => !value)) throw Error("اربط جميع مداخل القالب بأدلة المشروع");
        const data = await api("plans/templates/instantiate",{project_id:projectId,template_id:templateSelect.value,bindings:inputBindings});
        if (!active()) return;
        lastInstantiation = data;
        exportProof.disabled = false;
        editor.value = JSON.stringify(data.plan,null,2);
        showInstantiation();preview();
      })),exportProof),
    panel("تحرير خطة التحليل وتبعياتها",field("خطة التحليل JSON",editor),provenance,graph,
      button("بدء تشغيل خطة التحليل",() => action(async () => {
        const plan = JSON.parse(editor.value);
        const body = {project_id:projectId,plan};
        if (matchesInstantiation(plan)) body.instantiation_id = lastInstantiation.evidence.id;
        const run = await api("plans/start",body);
        if (!active()) return;
        show(run);await loadHistory();
      }),"primary")),
    panel("تنفيذ الخطة وحفظ التقدم",el("div",{class:"actions"},advance,pause,resume,exportRun),
      field("خطة تشغيل محفوظة",historySelect),button("عرض تشغيل الخطة المحفوظ",() => action(async () => {
        if (!historySelect.value) throw Error("اختر تشغيل خطة محفوظًا");
        const run = await api("plans?project=" + projectId + "&run=" + encodeURIComponent(historySelect.value));
        if (!active()) return;
        editor.value = JSON.stringify(run.plan,null,2);preview();show(run);
      })),output),
    panel("حفظ قالب المالك ومراجعاته",field("قالب المالك JSON",templateEditor),
      button("حفظ مراجعة قالب المالك",() => action(async () => {
        const data = await api("plans/templates/save",{project_id:projectId,template:JSON.parse(templateEditor.value)});
        if (!active()) return;
        const fresh = await api("project?id=" + projectId);
        if (!active()) return;
        state.project = fresh;await loadTemplates();
        if (active()) templateSaved.replaceChildren(el("p",{},"حُفظت مراجعة قالب المالك: " + data.revision));
      })),templateSaved));
  preview();
  loadTemplates().catch(error => { if (active()) toast(error.message,true); });
  loadHistory().catch(error => { if (active()) toast(error.message,true); });
  if (state.planRun?.projectId === projectId) {
    const runId = state.planRun.id;
    api("plans?project=" + projectId + "&run=" + encodeURIComponent(runId)).then(run => {
      if (active() && state.planRun?.id === runId) show(run);
    }).catch(error => { if (active()) toast(error.message,true); });
  }
  return result;
}
