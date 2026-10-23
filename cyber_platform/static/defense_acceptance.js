/* Defensive acceptance UI: owner labels are dataset claims, never execution authority. */
function eventQualityView(quality) {
  if (!quality) return el("p", {}, "هذا التقرير لا يتضمن قياس جودة التحويل بهذا الإصدار.");
  const flagLabels = {unknown_time:"التوقيت غير معلوم",unknown_actor:"الفاعل غير معلوم",unknown_action:"الإجراء غير معلوم",unknown_outcome:"النتيجة غير معلومة",offset_unspecified:"إزاحة التوقيت غير معلومة"};
  return panel("جودة تحويل الأحداث والتوقيت",
    el("p", {}, "السجلات: " + quality.records + " · سجلات بها حقول غير معلومة: " + quality.records_with_gaps),
    el("p", {}, "ترتيب السجلات محفوظ: " + (quality.order_preserved ? "نعم":"لا") + " · بايتات المصدر محفوظة: " + (quality.source_bytes_preserved ? "نعم":"لا")),
    table(["الحقل", "عدد القيم غير المعلومة"], Object.entries(quality.unknown_counts || {}).map(([key,value]) => [({time:"التوقيت",actor:"الفاعل",action:"الإجراء",outcome:"النتيجة"})[key] || key,value])),
    el("details", {}, el("summary", {}, "فجوات السجلات ودقة التوقيت"),
      table(["ترتيب السجل", "ملاحظات الجودة"], (quality.flags || []).map(item => [item.index,item.codes.map(code => flagLabels[code] || code).join(" · ")])),
      table(["ترتيب السجل", "التوقيت الأصلي", "فرق التوقيت", "خانات كسر الثانية"], (quality.timestamps || []).map(item => [item.index,item.original,item.offset_known ? item.offset : "غير معلوم",item.fraction_digits])))
  );
}

function eventSchemaPanel() {
  const holder = panel("قاموس الأحداث وإصدار المخطط", el("p", {}, "تحميل عقد الأحداث…"));
  api("events/schema").then(data => {
    if (!holder.isConnected) return;
    const types = {string:"نص",integer:"عدد صحيح",number:"عدد",object:"كائن حقول",array:"قائمة",boolean:"قيمة منطقية",enum:"قيمة من قائمة", "object|string":"كائن حقول أو نص", "ip-address":"عنوان شبكة"};
    holder.replaceChildren(el("div", {class:"panel-head"},el("h2", {}, "قاموس الأحداث وإصدار المخطط")),
      el("p", {}, "معرف المخطط: " + data.id + " · الإصدار: " + data.version),
      el("p", {class:"notice info"}, data.notice),
      table(["الحقل", "النوع", "مطلوب", "المعنى"], data.fields.map(item => [item.name,types[item.type] || item.type,item.required ? "نعم":"لا",item.description])),
      table(["ملاحظة الجودة", "المعنى"], (data.quality_flags || []).map(item => [item.code,item.description])),
      el("details", {}, el("summary", {}, "بصمة القاموس وعقد JSON القابل للتحقق"),
        pre({dictionary_sha256:data.dictionary_sha256,limits:data.limits,json_schema:data.json_schema})),
      el("small", {}, "القاموس يوثق التحويلات المدعومة؛ الحقول غير المعلومة تبقى معلنة، ولا تتحول أرقام الأحداث وحدها إلى نتائج نجاح أو فشل."));
  }).catch(error => {if (holder.isConnected) holder.append(el("p", {class:"notice"},error.message));});
  return holder;
}

function ruleAcceptancePanel() {
  const pid = state.project.project.id;
  const holder = panel("عينات القواعد وتغطيتها وإعادة اختبارها",
    el("p", {}, "اربط قاعدة المالك بملف أحداث وتوقعات مرجعية، ثم أعد اختبار المكتبة. التوقعات تصريحات مجموعة البيانات، وليست إثبات حماية حية."));
  const active = () => holder.isConnected && state.project?.project.id === pid;
  const statuses = {current:"عينة مرتبطة بالإصدار الحالي",builtin:"عينة مرجعية مدمجة",missing:"لا توجد عينة",stale:"تحتاج إعادة ربط",passed:"اجتازت التوقعات",failed:"أخفقت التوقعات",missing_fixture:"لا توجد عينة",stale_fixture:"عينة غير مطابقة للإصدار"};
  const library = el("div"), output = el("div", {"aria-live":"polite"});
  const rules = el("select", {"aria-label":"قاعدة العينة المرجعية"});
  const source = el("select", {"aria-label":"ملف أحداث العينة المرجعية"});
  const file = el("input", {type:"file",accept:".json,application/json","aria-label":"رفع ملف أحداث للعينة المرجعية"});
  const expected = el("textarea", {rows:3,spellcheck:"false","aria-label":"فهارس الأحداث المطابقة المتوقعة"}, "[0]");
  const history = el("select", {"aria-label":"تقرير تغطية قواعد محفوظ"});
  let report = null, selectionEpoch = 0, loadEpoch = 0;
  const exportReport = button("تنزيل تقرير تغطية القواعد JSON", () => {
    if (report && active()) researchJsonDownload(report,"detection-library-acceptance.json");
  });
  exportReport.disabled = true;
  function clearReport() {selectionEpoch+=1; report=null; exportReport.disabled=true; output.replaceChildren();}
  for (const control of [rules,source,file,expected]) control.addEventListener("change",clearReport);
  expected.addEventListener("input",clearReport);
  function refreshSources(preferred) {
    const chosen = preferred || source.value;
    source.replaceChildren(el("option", {value:""},"اختر ملفًا أصليًا…"), ...state.project.evidence.filter(item => item.kind === "original").map(item => el("option", {value:item.id,selected:item.id === chosen},item.name)));
  }
  refreshSources();
  async function load() {
    const epoch=++loadEpoch;
    const data=await api("detection/acceptance?project="+pid);
    if (!active() || epoch!==loadEpoch) return;
    const selected=rules.value;
    rules.replaceChildren(el("option", {value:""},"اختر قاعدة المالك…"), ...data.library.filter(item=>item.origin === "owner").map(item=>el("option",{value:item.id,selected:item.id===selected},item.title+" · "+item.version)));
    library.replaceChildren(el("p", {class:"notice info"},data.notice),
      table(["القاعدة", "الإصدار", "المصدر", "الترخيص", "العينة"],data.library.map(item=>[item.title,item.version,item.source,item.license,statuses[item.fixture_status] || item.fixture_status])));
    history.replaceChildren(el("option",{value:""},"اختر تقريرًا محفوظًا…"),...data.runs.map(item=>el("option",{value:item.evidence_id},when(item.created)+" · "+item.covered_rules+" / "+item.total_rules+" · "+(item.passed ? "اجتاز":"يحتاج مراجعة"))));
  }
  function show(value) {
    report=value; exportReport.disabled=false;
    output.replaceChildren(panel("نتيجة تغطية واختبار مكتبة القواعد",
      badge(value.passed && value.complete ? "اجتازت جميع القواعد المغطاة بالتوقعات المرجعية":"توجد قواعد تحتاج عينة أو مراجعة",value.passed && value.complete ? "good":"warn"),
      el("p",{},"القواعد ذات العينات: "+value.covered_rules+" / "+value.total_rules),
      el("p",{class:"notice"},value.notice),
      table(["القاعدة", "الإصدار", "الحالة", "الصحيح", "الإنذارات الكاذبة", "الفائت"],value.rows.map(item=>{
        const m=item.metrics || {};
        return [item.title || item.id,item.version,statuses[item.status] || item.status,m.true_positive ?? "—",m.false_positive ?? "—",m.false_negative ?? "—"];
      })),
      el("small",{},"نتائج مرجعية محفوظة بإصداراتها؛ ليست مراقبة حية أو شهادة تغطية لجميع التهديدات.")));
  }
  const register=button("ربط العينة بقاعدة المالك",()=>action(async()=>{
    if (!rules.value) throw Error("اختر قاعدة المالك أولًا");
    let indexes;
    try {indexes=JSON.parse(expected.value);} catch {throw Error("فهارس المطابقات تحتاج قائمة JSON، مثل [0]");}
    if (!Array.isArray(indexes) || !indexes.length || indexes.some(value=>!Number.isInteger(value) || value<0)) throw Error("حدد قائمة فهارس صحيحة تبدأ من الصفر");
    const selectedRule=rules.value, epoch=selectionEpoch;
    const controls=[rules,source,file,expected];controls.forEach(control=>{control.disabled=true;});
    try {
      let eid=source.value;
      if (file.files[0]) {
        const chosen=file.files[0];
        if (chosen.size>1024*1024) throw Error("حد ملف العينة1ميبيبايت");
        const bytes=new Uint8Array(await chosen.arrayBuffer());let raw="";
        for(let i=0;i<bytes.length;i+=32768) raw+=String.fromCharCode(...bytes.subarray(i,i+32768));
        if (!active()) return;
        const uploaded=await api("upload",{project_id:pid,name:chosen.name,base64:btoa(raw)});eid=uploaded.id;
      }
      if (!eid) throw Error("اختر ملف أحداث أصليًا للعينة");
      if (!active()) return;
      await api("detection/fixtures/register",{project_id:pid,rule_id:selectedRule,evidence_id:eid,expected_indexes:indexes});
      if (!active() || epoch!==selectionEpoch) return;
      const project=await api("project?id="+pid);if(!active()) return;
      state.project=project;refreshSources(eid);file.value="";
      clearReport();await load();toast("حُفظت العينة والتوقعات مع إصدار القاعدة");
    } finally {controls.forEach(control=>{control.disabled=false;});}
  },register),"primary");
  const run=button("إعادة اختبار جميع القواعد وقياس التغطية",()=>action(async()=>{
    clearReport();const epoch=selectionEpoch;
    output.append(el("p",{},"تجري إعادة اختبار القواعد والتحقق من العينات…"));
    const data=await api("detection/acceptance/run",{project_id:pid});
    if(!active() || epoch!==selectionEpoch) return;
    show(data.report || data);await load();
  },run),"primary");
  const view=button("عرض تقرير تغطية القواعد المحفوظ",()=>action(async()=>{
    if(!history.value) throw Error("اختر تقريرًا محفوظًا");
    clearReport();const chosen=history.value,epoch=selectionEpoch;
    const value=await api("detection/acceptance/report?project="+pid+"&id="+encodeURIComponent(chosen));
    if(active() && epoch===selectionEpoch && history.value===chosen) show(value.report || value);
  },view));
  history.addEventListener("change",clearReport);
  holder.append(library,
    el("details",{},el("summary",{},"عينة مرجعية لقاعدة المالك"),
      field("القاعدة وإصدارها الحالي",rules),field("ملف محفوظ أو ملف جديد",source),file,
      field("فهارس المطابقات المتوقعة، بدءًا من الصفر",expected),
      el("small",{},"تحتاج العينة حدثًا واحدًا متوقع المطابقة على الأقل وآخر غير مطابق. اختيارك تسمية مرجعية للبيانات، وليس حكمًا مستقلًا على وجود هجوم."),register),
    el("div",{class:"actions"},run,button("تحديث عينات واختبارات المكتبة",()=>action(load))),
    field("تقارير التغطية والقبول المحفوظة",history),view,exportReport,output);
  load().catch(error=>{if(active()) toast(error.message,true);});
  return holder;
}
