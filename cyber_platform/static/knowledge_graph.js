/* F06: project-scoped claims, their evidence and conflicts; never inferred truth. */
function knowledgeGraphPanel() {
  const pid=state.project.project.id;
  const holder=panel("خريطة الكيانات والمصادر والثقة",el("p",{},"تحميل خريطة المشروع والتحقق من مصادرها…"));
  holder.classList.add("knowledge-graph");
  const active=()=>holder.isConnected && state.project?.project.id===pid;
  const entityLabels={asset:"أصل",software:"برنامج",vulnerability:"ثغرة",event:"حدث",evidence:"دليل",experiment:"تجربة"};
  const relationLabels={related_to:"مرتبط بـ",runs:"يشغّل",affects:"يؤثر في",observed_on:"لوحظ على",derived_from:"مشتق من",supports:"يدعم",contradicts:"يتعارض مع",tested_by:"اختُبر بواسطة",tests:"يختبر",contains:"يحتوي",mitigates:"يعالج",produces:"ينتج",depends_on:"يعتمد على"};
  const validityLabels={current:"صالح في وقت العرض",active:"صالح في وقت العرض",expired:"انتهت الصلاحية",future:"لم تبدأ الصلاحية",not_yet_valid:"لم تبدأ الصلاحية",unbounded:"دون حد زمني مسجل"};
  let graph=null,epoch=0,selected=null;
  const view=el("div"),detail=el("div",{"aria-live":"polite"}),messages=el("div",{"aria-live":"polite"});
  const filter=el("input",{type:"search","aria-label":"بحث كيانات خريطة الأدلة",placeholder:"ابحث عن كيان أو نوع…"});
  const choose=(items,labels,title)=>el("select",{"aria-label":title},el("option",{value:""},"اختر…"),...items.map(item=>el("option",{value:typeof item==="string"?item:item.id},labels[typeof item==="string"?item:item.id] || item.label || item.name || item.id || item)));
  const entityType=choose(Object.keys(entityLabels),entityLabels,"نوع كيان الخريطة");
  const title=el("input",{maxlength:160,"aria-label":"اسم كيان الخريطة"});
  const description=el("textarea",{rows:3,maxlength:2000,"aria-label":"وصف كيان الخريطة"});
  const source=el("select",{"aria-label":"المصدر الأصلي لكيان الخريطة"});
  const reference=el("select",{"aria-label":"الدليل أو نتيجة التجربة المرتبطة بكيان الخريطة"});
  const confidence=el("input",{type:"number",min:0,max:100,value:50,"aria-label":"ثقة كيان الخريطة"});
  const observed=el("input",{placeholder:"2026-10-23T12:00:00+03:00","aria-label":"وقت ملاحظة كيان الخريطة"});
  const from=el("input",{placeholder:"2026-10-23T12:00:00+03:00","aria-label":"بداية صلاحية كيان الخريطة"});
  const until=el("input",{placeholder:"اختياري؛ توقيت مع إزاحة","aria-label":"نهاية صلاحية كيان الخريطة"});
  const relationSource=el("select",{"aria-label":"كيان بداية العلاقة"});
  const relationTarget=el("select",{"aria-label":"كيان نهاية العلاقة"});
  const relationType=choose([],relationLabels,"نوع علاقة الخريطة");
  const relationDescription=el("textarea",{rows:3,maxlength:2000,"aria-label":"شرح علاقة الخريطة"});
  const relationEvidence=el("select",{"aria-label":"المصدر الأصلي لعلاقة الخريطة"});
  const relationConfidence=el("input",{type:"number",min:0,max:100,value:50,"aria-label":"ثقة علاقة الخريطة"});
  const relationObserved=el("input",{placeholder:"2026-10-23T12:00:00+03:00","aria-label":"وقت ملاحظة علاقة الخريطة"});
  const relationFrom=el("input",{placeholder:"اختياري؛ توقيت مع إزاحة","aria-label":"بداية صلاحية علاقة الخريطة"});
  const relationUntil=el("input",{placeholder:"اختياري؛ توقيت مع إزاحة","aria-label":"نهاية صلاحية علاقة الخريطة"});
  const conflicts=el("select",{"aria-label":"العلاقة المتعارضة مع الادعاء الجديد"});
  const at=el("input",{"aria-label":"وقت تقييم صلاحية خريطة الأدلة",placeholder:"اتركه فارغًا لوقت العرض؛ أو RFC3339 مع إزاحة"});
  function sourceText(item) {
    const id=typeof item.source_evidence==="object"?item.source_evidence.id:item.source_evidence;
    return state.project.evidence.find(value=>value.id===id)?.name || id || "غير معلوم";
  }
  function validity(item) {return validityLabels[item.validity] || validityLabels[item.validity_status] || item.validity || item.validity_status || "وفق الفترة المسجلة";}
  function isConflicting(id) {return (graph?.conflicts || []).some(item=>(item.relations || []).includes(id));}
  function show(item,kind) {
    selected=item.id;
    detail.replaceChildren(el("h3",{},kind==="entity"?"تفاصيل الكيان ومصدره":"معنى العلاقة ودليلها"),
      el("p",{},kind==="entity"?(entityLabels[item.type] || item.type)+" · "+item.label:(relationLabels[item.type] || item.type)),
      el("p",{},item.description),el("p",{},"المصدر: "+sourceText(item)),
      el("p",{},"الثقة المعلنة: "+item.confidence+" / 100 · "+validity(item)),
      el("p",{},"وقت الملاحظة: "+item.observed_at),
      el("p",{},"بداية الصلاحية: "+(item.valid_from || "غير محددة")+" · النهاية: "+(item.valid_until || "غير محددة")),
      el("small",{},"الثقة ادعاء المالك المرتبط بالمصدر؛ وجود العلاقة لا يثبت صحتها تلقائيًا."));
    if(kind==="relation") detail.append(el("p",{},"من: "+(graph.entities.find(value=>value.id===item.source)?.label || item.source)+" ← إلى: "+(graph.entities.find(value=>value.id===item.target)?.label || item.target)));
    if(item.reference_evidence) detail.append(el("p",{},"الملف المرتبط: "+(state.project.evidence.find(value=>value.id===item.reference_evidence)?.name || item.reference_evidence)),el("small",{},"بصمة الملف المرتبط: "+item.reference_sha256));
    if(kind==="relation" && isConflicting(item.id)) detail.append(el("p",{class:"notice"},"لهذا الادعاء تعارض محفوظ؛ راجع سجل التعارضات والمصدرين دون دمج حكمهما."));
    if(item.conflicts_with) detail.append(el("p",{class:"notice"},"تعارض معلن مع العلاقة: "+item.conflicts_with));
    detail.append(el("details",{},el("summary",{},"المعرفات والبصمات المحفوظة"),pre(item)));
  }
  function draw() {
    if(!graph) return;
    const q=filter.value.trim().toLocaleLowerCase();
    const filtered=graph.entities.filter(item=>[item.label,item.description,entityLabels[item.type] || item.type].join(" ").toLocaleLowerCase().includes(q));
    const shown=filtered.slice(0,30),positions=new Map();
    const canvas=svg("svg",{viewBox:"0 0 800 420",class:"knowledge-graph-canvas",role:"group","aria-label":"خريطة الكيانات والعلاقات الموثقة"});
    shown.forEach((item,index)=>positions.set(item.id,[85+(index%5)*155,45+Math.floor(index/5)*65]));
    const keyboard=(node,fn)=>{node.addEventListener("click",fn);node.addEventListener("keydown",event=>{if(event.key==="Enter" || event.key===" "){event.preventDefault();fn();}});};
    graph.relations.forEach((item,index)=>{
      const a=positions.get(item.source),b=positions.get(item.target);if(!a || !b) return;
      const edge=svg("path",{d:"M "+a[0]+" "+a[1]+" Q "+((a[0]+b[0])/2)+" "+(Math.min(a[1],b[1])-22-(index%3)*12)+" "+b[0]+" "+b[1],tabindex:0,role:"button","aria-label":"تفاصيل العلاقة: "+(relationLabels[item.type] || item.type),class:isConflicting(item.id)?"conflicting":""});
      keyboard(edge,()=>show(item,"relation"));canvas.append(edge);
    });
    shown.forEach(item=>{
      const [x,y]=positions.get(item.id);
      const node=svg("circle",{cx:x,cy:y,r:15,tabindex:0,role:"button","aria-label":"تفاصيل الكيان: "+item.label});
      keyboard(node,()=>show(item,"entity"));
      const label=svg("text",{x,y:y+30,"text-anchor":"middle"});label.textContent=item.label.slice(0,18);canvas.append(node,label);
    });
    const name=id=>graph.entities.find(item=>item.id===id)?.label || id;
    view.replaceChildren(el("p",{},"الكيانات: "+graph.entities.length+" · العلاقات: "+graph.relations.length+" · التعارضات المعلنة: "+graph.conflicts.length),
      shown.length?canvas:el("p",{},"لا توجد كيانات مطابقة. أضف كيانًا مع مصدره الأصلي أولًا."),
      el("small",{},"الرسم يعرض أول30كيانًا مطابقًا. الجداول التالية تشمل جميع الكيانات والعلاقات؛ اختيار عنصر يشرح معناه ومصدره."),
      el("h3",{},"جدول الكيانات المكافئ"),table(["الكيان", "النوع", "المصدر", "الثقة", "الصلاحية"],filtered.map(item=>[button(item.label,()=>show(item,"entity"),"small"),entityLabels[item.type] || item.type,sourceText(item),item.confidence+" / 100",validity(item)])),
      el("h3",{},"جدول العلاقات ومعانيها"),table(["من", "المعنى", "إلى", "المصدر", "الثقة", "الصلاحية", "التعارض"],graph.relations.map(item=>[name(item.source),button(relationLabels[item.type] || item.type,()=>show(item,"relation"),"small"),name(item.target),sourceText(item),item.confidence+" / 100",validity(item),isConflicting(item.id)?"تعارض معلن":"لا تعارض مسجل"])),
      el("h3",{},"سجل التعارضات دون دمج الادعاءات"),graph.conflicts.length?table(["الادعاء", "الادعاء المقابل", "التفصيل"],graph.conflicts.map(item=>[item.relations?.[0] || "—",item.relations?.[1] || "—",item.kind==="opposed_assertions"?"ادعاء داعم وآخر معارض للكيانين نفسيهما":"تعارض صريح مسجل"] )):el("p",{},"لم تسجل تعارضات في هذا المشروع."));
  }
  function fillSelect(control,items,placeholder) {
    const chosen=control.value;control.replaceChildren(el("option",{value:""},placeholder),...items.map(item=>el("option",{value:item.id,selected:item.id===chosen},item.label || item.name || item.id)));
  }
  async function load() {
    const generation=++epoch;graph=null;selected=null;view.replaceChildren();detail.replaceChildren();exportGraph.disabled=true;
    messages.replaceChildren(el("p",{},"جارٍ التحقق من أصول الخريطة ومراجعها…"));
    const suffix=at.value.trim()?"&at="+encodeURIComponent(at.value.trim()):"";
    const result=await api("graph?project="+pid+suffix);
    if(!active() || generation!==epoch) return;
    graph=result;exportGraph.disabled=false;selected=null;detail.replaceChildren();
    const originals=state.project.evidence.filter(item=>item.kind==="original");
    fillSelect(source,originals,"اختر ملف المصدر الأصلي…");fillSelect(reference,state.project.evidence,"لا ارتباط مباشر؛ مطلوب للدليل والتجربة…");fillSelect(relationEvidence,originals,"اختر ملف المصدر الأصلي…");
    fillSelect(relationSource,result.entities,"اختر كيان البداية…");fillSelect(relationTarget,result.entities,"اختر كيان النهاية…");
    fillSelect(conflicts,result.relations.map(item=>({...item,label:(relationLabels[item.type] || item.type)+" · "+item.id.slice(0,8)})),"لا تعارض معلن");
    const kinds=result.catalog?.relation_types || Object.keys(relationLabels);
    const entries=Array.isArray(kinds)?kinds.map(item=>typeof item==="string"?{id:item}:item):Object.entries(kinds).map(([id,label])=>({id,label}));
    const old=relationType.value;relationType.replaceChildren(el("option",{value:""},"اختر نوع العلاقة…"),...entries.map(item=>el("option",{value:item.id,selected:item.id===old},relationLabels[item.id] || item.label || item.id)));
    messages.replaceChildren(el("p",{class:"notice info"},result.notice || "هذه ادعاءات موثقة بمصادر المشروع؛ لا تُدمج الثقة المتعارضة تلقائيًا."));draw();
  }
  const values=(c,f,u,s)=>({source_evidence:s.value,confidence:Number(c.value),valid_from:f.value.trim() || null,valid_until:u.value.trim() || null});
  const saveEntity=button("حفظ كيان موثق",()=>action(async()=>{
    const entity={type:entityType.value,label:title.value.trim(),description:description.value.trim(),reference_evidence:reference.value || null,observed_at:observed.value.trim(),...values(confidence,from,until,source)};
    if(!active()) return;
    await api("graph/entities",{project_id:pid,entity});
    if(!active()) return;
    await load();toast("حُفظ الكيان مع مصدره وثقته وصلاحيته");
  },saveEntity),"primary");
  const saveRelation=button("حفظ علاقة موثقة وتعارضها",()=>action(async()=>{
    const relation={source:relationSource.value,target:relationTarget.value,type:relationType.value,description:relationDescription.value.trim(),observed_at:relationObserved.value.trim(),...values(relationConfidence,relationFrom,relationUntil,relationEvidence),conflicts_with:conflicts.value || null};
    if(!active()) return;
    await api("graph/relations",{project_id:pid,relation});
    if(!active()) return;
    await load();toast("حُفظت العلاقة ومصدرها دون إلغاء الادعاء المقابل");
  },saveRelation),"primary");
  filter.addEventListener("input",draw);
  at.addEventListener("input",()=>{epoch+=1;graph=null;exportGraph.disabled=true;view.replaceChildren();detail.replaceChildren();});
  const exportGraph=button("تنزيل خريطة الكيانات ومصادرها JSON",()=>{if(graph && active())researchJsonDownload(graph,"project-evidence-graph.json");});
  exportGraph.disabled=true;
  holder.replaceChildren(el("div",{class:"panel-head"},el("h2",{},"خريطة الكيانات والمصادر والثقة")),
    el("p",{},"الأصل والبرنامج والثغرة والحدث والدليل والتجربة، بعلاقات تحافظ على المصدر والثقة والصلاحية والتعارض."),messages,
    field("وقت تقييم الصلاحية؛ اختياري",at),el("div",{class:"actions"},button("تحديث خريطة الكيانات والتحقق",()=>action(load)),exportGraph),filter,view,detail,
    el("details",{},el("summary",{},"إضافة كيان ومصدره وثقته"),el("div",{class:"form-grid"},field("النوع",entityType),field("الاسم",title),field("الوصف",description),field("المصدر الأصلي",source),field("ملف الدليل أو نتيجة التجربة؛ مطلوب لهذين النوعين",reference),field("الثقة من0إلى100",confidence),field("وقت الملاحظة؛ مطلوب مع إزاحة",observed),field("بداية الصلاحية؛ اختيارية",from),field("نهاية الصلاحية؛ اختيارية",until)),saveEntity),
    el("details",{},el("summary",{},"إضافة علاقة ومعناها وتعارضها"),el("div",{class:"form-grid"},field("من كيان",relationSource),field("إلى كيان",relationTarget),field("نوع العلاقة",relationType),field("شرح الدليل على العلاقة",relationDescription),field("المصدر الأصلي",relationEvidence),field("الثقة من0إلى100",relationConfidence),field("وقت الملاحظة؛ مطلوب مع إزاحة",relationObserved),field("بداية الصلاحية؛ اختيارية",relationFrom),field("نهاية الصلاحية؛ اختيارية",relationUntil),field("تعارض مع علاقة محفوظة؛ اختياري",conflicts)),saveRelation),
    el("small",{},"تحتاج إضافة ملف المصدر من صفحة الأدلة أولًا. لا تُقرأ ملفات خارج المشروع ولا يرسل هذا العرض بيانات إلى خدمة خارجية."));
  load().catch(error=>{if(active()) messages.replaceChildren(el("p",{class:"notice"},error.message));});
  return holder;
}
