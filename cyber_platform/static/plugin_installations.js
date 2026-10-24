/* Explicit owner installation of signed isolated modules; metadata review stays separate. */
function pluginInstallationsPanel() {
  const pid=state.project.project.id;
  const holder=panel("تثبيت الإضافات الموقعة وتشغيلها",el("p",{},"تحميل سجل الحزم والتحقق منه…"));
  holder.classList.add("plugin-installations");
  const active=()=>holder.isConnected && state.project?.project.id===pid;
  const labels={active:"مفعّلة للتشغيل",disabled:"متوقفة",blocked:"محجوبة بسبب تعارض",installed:"مثبتة وغير مفعّلة",trusted:"ناشر موثوق بقرار المالك",revoked:"ثقة مسحوبة"};
  const issueLabels={publisher_revoked:"ثقة الناشر مسحوبة",stale_runtime:"تغير المنفذ ويحتاج إعادة اختبار"};
  const permissionLabels={"selected_evidence.read":"قراءة الملف المحدد فقط","derived_evidence.write":"حفظ نتيجة مشتقة"};
  const message=el("div",{"aria-live":"polite"}),inventory=el("div"),details=el("div"),history=el("div"),output=el("div",{"aria-live":"polite"});
  const publicKey=el("textarea",{rows:3,maxlength:100,"aria-label":"المفتاح العام لناشر الإضافة","placeholder":"مفتاح Ed25519 عام بصيغة Base64؛ لا تضع مفتاحًا خاصًا"});
  const trusted=el("select",{"aria-label":"ناشر الإضافات لسحب الثقة"});
  const packageSource=el("select",{"aria-label":"ملف حزمة الإضافة الموقعة"});
  const packageFile=el("input",{type:"file",accept:".json,application/json","aria-label":"رفع حزمة إضافة موقعة"});
  const chosen=el("select",{"aria-label":"الإضافة التنفيذية المثبتة"});
  const version=el("select",{"aria-label":"إصدار الإضافة للتفعيل أو الاستعادة"});
  const input=el("select",{"aria-label":"ملف الإدخال الأصلي للإضافة"});
  let snapshot=null,loadEpoch=0,selectionEpoch=0,runResult=null;
  const exportInventory=button("تنزيل سجل الحزم الموقعة JSON",()=>{if(snapshot && active())researchJsonDownload(snapshot,"signed-plugin-inventory.json");});
  const exportRun=button("تنزيل نتيجة تشغيل الإضافة JSON",()=>{if(runResult && active())researchJsonDownload(runResult,"isolated-plugin-result.json");});
  exportInventory.disabled=true;exportRun.disabled=true;
  function selected(){return snapshot?.plugins.find(item=>item.id===chosen.value);}
  function clearRun(){selectionEpoch+=1;runResult=null;exportRun.disabled=true;output.replaceChildren();}
  function controls() {
    const item=selected(),selectedVersion=version.value,known=Boolean(snapshot && item && selectedVersion);
    activate.disabled=!known || item.effective_state==="active" && item.current_version===selectedVersion;
    disable.disabled=!item || item.state!=="active";
    rollback.disabled=!known || item.current_version===selectedVersion;
    run.disabled=!item || item.effective_state!=="active" || !input.value;
    revoke.disabled=!snapshot?.trust.some(item=>item.key_id===trusted.value && item.state==="trusted");
  }
  function showPlugin(preserveVersion=true) {
    clearRun();const item=selected(),previous=preserveVersion?version.value:"";
    version.replaceChildren(el("option",{value:""},"اختر إصدارًا مثبتًا…"),...(item?.versions || []).map(value=>el("option",{value:value.version,selected:value.version===(previous || item.current_version)},value.version)));
    if(item && !version.value && item.versions.length)version.value=item.versions[item.versions.length-1].version;
    if(!item){details.replaceChildren(el("p",{},"اختر إضافة مثبتة لعرض إصداراتها وصلاحياتها."));controls();return;}
    const current=item.versions.find(value=>value.version===version.value);
    details.replaceChildren(el("h3",{},"الحزمة التنفيذية: "+item.id),
      el("p",{},"الحالة المسجلة: "+(labels[item.state] || item.state)+" · الحالة الفعلية: "+(labels[item.effective_state] || item.effective_state)),
      el("p",{},"الإصدار الحالي: "+(item.current_version || "لم يُفعّل إصدار")),
      item.issues.length?table(["سبب الحجب","التفصيل"],item.issues.map(issue=>[issueLabels[issue.code] || uiLabel(issue.code),issue.message])):el("p",{},"لا توجد موانع مسجلة في التحقق الحالي."),
      current?el("div",{},el("p",{},"الإصدار المختار: "+current.version+" · الترخيص: "+current.manifest.license),el("p",{},"المصدر المعلن: "+current.manifest.source),
        table(["الصلاحية التنفيذية"],current.manifest.permissions.map(value=>[permissionLabels[value] || value])),
        table(["الاعتمادية","الإصدار المطلوب"],(current.manifest.dependencies || []).map(value=>[value.id,value.version])),
        el("p",{},"العينات التي اجتازت الاختبار عند التثبيت: "+current.fixture_count),
        el("details",{},el("summary",{},"بيانات الإصدار والتوقيع والبصمات"),pre(current))):null,
      table(["الإجراء المحفوظ","الإصدار","دليل الإجراء"],item.history.map(value=>[({install:"تثبيت بعد الاختبار",activate:"تفعيل",disable:"إيقاف",rollback:"استعادة إصدار سابق"})[value.action] || value.action,value.version || "—",value.evidence_id])));
    controls();
  }
  function fill(control,items,prompt,preferred){const old=preferred || control.value;control.replaceChildren(el("option",{value:""},prompt),...items.map(item=>el("option",{value:item.id,selected:item.id===old},item.name || item.id)));}
  function renderHistory(runs) {
    history.replaceChildren(el("h3",{},"تشغيلات الإضافات المحفوظة"),el("p",{},"هذه نتائج محفوظة بتاريخها؛ عرض السجل أو تنزيله لا يعيد تنفيذ الإضافة."),runs.length?table(["الإضافة","الإصدار","وقت التشغيل","حالة المنفذ","عرض النتيجة"],runs.map(item=>[item.plugin_id,item.version,when(item.created),item.current_runtime===false?"تغير المنفذ؛ نتيجة تاريخية":"سجل محفوظ؛ ليس إعادة تنفيذ",button("عرض تشغيل "+item.evidence_id,()=>{if(!active())return;clearRun();runResult=item;exportRun.disabled=false;output.replaceChildren(pre(item));})])):el("p",{},"لا توجد تشغيلات محفوظة."));
  }
  async function load(preferredPlugin,preferredPackage) {
    const epoch=++loadEpoch,oldPlugin=preferredPlugin || chosen.value;snapshot=null;exportInventory.disabled=true;clearRun();inventory.replaceChildren();details.replaceChildren();history.replaceChildren();controls();
    message.replaceChildren(el("p",{},"التحقق من الحزم والثقة والمصادر…"));
    const [data,files]=await Promise.all([api("plugins/installations?project="+pid),api("project?id="+pid)]);
    if(!active() || epoch!==loadEpoch)return;
    snapshot=data;exportInventory.disabled=false;
    fill(packageSource,files.evidence.filter(value=>value.kind==="original"),"اختر ملف الحزمة الأصلي…",preferredPackage);
    fill(input,files.evidence.filter(value=>value.kind==="original" && value.size<=65536),"اختر ملف الإدخال الأصلي حتى64كيبيبايت…");
    chosen.replaceChildren(el("option",{value:""},"اختر إضافة مثبتة…"),...data.plugins.map(item=>el("option",{value:item.id,selected:item.id===oldPlugin},item.id)));
    trusted.replaceChildren(el("option",{value:""},"اختر ناشرًا موثوقًا…"),...data.trust.map(item=>el("option",{value:item.key_id,disabled:item.state!=="trusted"},item.key_id+" · "+(labels[item.state] || item.state))));
    inventory.replaceChildren(el("p",{class:"notice"},data.notice),
      el("h3",{},"الحزم المثبتة وحالتها الفعلية"),data.plugins.length?table(["الإضافة","الإصدار الحالي","الحالة","الإصدارات المحفوظة"],data.plugins.map(item=>[button(item.id,()=>{chosen.value=item.id;showPlugin(false);}),item.current_version || "—",labels[item.effective_state] || item.effective_state,item.versions.map(value=>value.version).join(" · ")])):el("p",{},"لم تُثبّت حزم تنفيذية في هذا المشروع."),
      el("h3",{},"مفاتيح الناشرين وقرارات الثقة"),data.trust.length?table(["معرف المفتاح العام","قرار المالك"],data.trust.map(item=>[item.key_id,labels[item.state] || item.state])):el("p",{},"لا يوجد ناشر موثوق؛ تثبيت الحزمة يرفض حتى اعتماد مفتاحه العام صراحة."),
      el("details",{},el("summary",{},"حدود التنفيذ والحفظ"),pre(data.limits)));
    renderHistory(data.runs);
    message.replaceChildren();showPlugin();
  }
  const trust=button("اعتماد المفتاح العام لناشر الإضافة",()=>action(async()=>{
    const key=publicKey.value.trim();if(!key)throw Error("أدخل المفتاح العام للناشر؛ لا تدخل مفتاحًا خاصًا");
    if(!active())return;await api("plugins/trust",{project_id:pid,public_key:key});
    if(!active())return;publicKey.value="";await load();toast("حُفظ قرار الثقة بالمفتاح العام داخل هذا المشروع");
  },trust));
  const revoke=button("سحب الثقة من ناشر الإضافات",()=>action(async()=>{
    const key=trusted.value;if(!key)throw Error("اختر ناشرًا موثوقًا أولًا");
    if(!active())return;await api("plugins/trust/revoke",{project_id:pid,key_id:key});
    if(!active())return;await load();toast("سُحبت الثقة؛ الحزم المرتبطة بالمفتاح لا تحصل على إذن تشغيل");
  },revoke).finally(controls));
  const install=button("التحقق من الحزمة واختبارها وتثبيتها",()=>action(async()=>{
    const source=packageSource.value,selectedFile=packageFile.files[0];
    const inputs=[packageSource,packageFile];inputs.forEach(value=>{value.disabled=true;});
    try{
      let eid=source;
      if(selectedFile){
        if(selectedFile.size>2*1024*1024)throw Error("حد حزمة الإضافة2ميبيبايت");
        const bytes=new Uint8Array(await selectedFile.arrayBuffer());let binary="";
        for(let i=0;i<bytes.length;i+=32768)binary+=String.fromCharCode(...bytes.subarray(i,i+32768));
        if(!active())return;const uploaded=await api("upload",{project_id:pid,name:selectedFile.name,base64:btoa(binary)});eid=uploaded.id;
      }
      if(!eid)throw Error("اختر حزمة موقعة أو ارفع ملفها الأصلي أولًا");
      if(!active())return;await api("plugins/install",{project_id:pid,evidence_id:eid});
      if(!active())return;packageFile.value="";await load(undefined,eid);toast("اختُبرت الحزمة وثُبتت؛ التفعيل إجراء مستقل للمالك");
    }finally{inputs.forEach(value=>{value.disabled=false;});}
  },install),"primary");
  async function transition(actionName,control){
    await action(async()=>{
      const id=chosen.value,target=actionName==="disable"?null:version.value;if(!id || actionName!=="disable" && !target)throw Error("اختر إضافة وإصدارًا مثبتًا");
      if(!active())return;await api("plugins/runtime/transition",{project_id:pid,plugin_id:id,action:actionName,version:target});
      if(!active())return;await load(id);toast("حُفظ قرار تشغيل الإضافة بعد التحقق");
    },control);
    controls();
  }
  const activate=button("تفعيل إصدار الإضافة المختار",()=>transition("activate",activate));
  const disable=button("إيقاف الإضافة التنفيذية",()=>transition("disable",disable));
  const rollback=button("استعادة إصدار إضافة سابق",()=>transition("rollback",rollback));
  const run=button("تشغيل الإضافة المعزولة على الملف المحدد",()=>action(async()=>{
    const id=chosen.value,eid=input.value;clearRun();const expectedEpoch=selectionEpoch;
    if(!id || !eid)throw Error("اختر إضافة مفعلة وملف إدخال أصليًا");
    const result=await api("plugins/runtime/run",{project_id:pid,plugin_id:id,evidence_id:eid});
    if(!active() || expectedEpoch!==selectionEpoch || chosen.value!==id || input.value!==eid)return;
    runResult=result;exportRun.disabled=false;output.replaceChildren(panel("نتيجة تشغيل الإضافة المحفوظة",pre(result.record.result),el("details",{},el("summary",{},"المصدر والإصدار وإثبات التشغيل"),pre(result))));
    // Refresh the history separately without replacing the user's current execution result.
    const saved=await api("plugins/installations?project="+pid);
    if(active() && expectedEpoch===selectionEpoch){snapshot=saved;renderHistory(saved.runs);}
  },run).finally(controls),"primary");
  for(const control of [chosen,version,input])control.addEventListener("change",()=>{if(control===chosen)showPlugin(false);else if(control===version)showPlugin();else{clearRun();controls();}});
  trusted.addEventListener("change",controls);
  packageFile.addEventListener("change",clearRun);packageSource.addEventListener("change",clearRun);
  holder.replaceChildren(el("div",{class:"panel-head"},el("h2",{},"تثبيت الإضافات الموقعة وتشغيلها")),
    el("p",{},"لا يكفي اعتماد بيان الإضافة لتشغيلها. هنا تثبّت حزمة موقعة من ناشر تعتمد مفتاحه العام، بعد نجاح عيناتها، ثم تختار تفعيلها صراحة."),
    el("p",{class:"notice"},"الإضافة المعزولة تستلم بايتات الملف الذي تحدده فقط، وتعيد نتيجةJSON. لا تملك وصولًا إلى ملفات الجهاز أو الشبكة أو مفاتيحك. سحب الثقة يوقف أهلية التشغيل."),
    message,el("div",{class:"actions"},button("تحديث الحزم الموقعة والتحقق",()=>action(load)),exportInventory),
    el("details",{},el("summary",{},"ثقة ناشر الإضافة ومفتاحه العام"),field("المفتاح العام للناشر؛ ليس مفتاحًا خاصًا",publicKey),trust,field("ناشر لسحب الثقة",trusted),revoke),
    el("details",{},el("summary",{},"تثبيت حزمة أو إصدار بديل"),field("حزمة موقعة محفوظة",packageSource),field("أو رفع حزمة موقعة",packageFile),install),
    inventory,field("الإضافة التنفيذية",chosen),field("الإصدار المثبت",version),el("small",{},"قائمة الإصدار للتفعيل أو الاستعادة؛ التشغيل يستخدم الإصدار الحالي المفعّل فقط."),details,
    el("div",{class:"actions"},activate,disable,rollback),field("ملف الإدخال الأصلي؛ حتى64كيبيبايت",input),run,output,exportRun,history,
    el("small",{},"إيقاف الإضافة يحفظ إصداراتها ونتائجها. لاستعادة إصدار أقدم سبق تفعيله، اختره ثم اضغط زر الاستعادة."));
  controls();load().catch(error=>{if(active())message.replaceChildren(el("p",{class:"notice"},error.message));});
  return holder;
}
