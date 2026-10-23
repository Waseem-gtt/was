/* Completed file import/search flow, separate from public network snapshots. */
function offlineKnowledgePanel() {
  const pid = state.project.project.id;
  const holder = panel("فهرس الثغرات من ملف — استيراد وبحث جاهزان",
    el("p", {}, "استورد ملفًا بصيغة CISA KEV من جهازك، ثم ابحث فيه دون إنترنت. تُحفظ البصمة والأصل وإثبات الاستيراد. يبقى آخر فهرس صالح عند رفض ملف جديد."));
  holder.classList.add("offline-knowledge");
  const active = () => holder.isConnected && state.project?.project.id === pid;
  const file = el("input", {type:"file", accept:".json,application/json", "aria-label":"ملف فهرس الثغرات دون إنترنت"});
  const sources = el("select", {"aria-label":"فهرس ثغرات محفوظ للاستيراد"});
  const current = el("div", {"aria-live":"polite"});
  const output = el("div", {"aria-live":"polite"});
  const query = el("input", {type:"search", maxlength:120, "aria-label":"بحث فهرس الثغرات المستورد"});
  let receiptId = null, statusRequest = 0;
  function updateSources() {
    sources.replaceChildren(el("option", {value:""}, "اختر ملفًا أصليًا محفوظًا…"),
      ...state.project.evidence.filter(item => item.kind === "original").map(item => el("option", {value:item.id}, item.name)));
  }
  updateSources();
  async function load() {
    const request = ++statusRequest;
    const value = await api("knowledge/offline?project=" + pid);
    if (!active() || request !== statusRequest) return;
    receiptId = value.receipt_id || null;
    exportReceipt.disabled = !receiptId;
    current.replaceChildren(el("p", {class:"notice info"}, value.notice));
    if (value.current) current.append(badge("جاهز للبحث دون إنترنت", "good"),
      row("إصدار الملف", value.current.version), row("عدد السجلات", value.current.count),
      row("وقت الاستيراد", when(value.current.imported_at)), row("بصمة الأصل", el("span", {class:"code"}, value.current.input_sha256)),
      el("p", {}, "التحقق من هوية الناشر: غير متحقق. الاستيراد منفصل عن اللقطة التي تُجلب من المصدر العام."));
    else current.append(el("p", {}, "لم تستورد فهرسًا في هذا المشروع بعد."));
  }
  const submit = button("استيراد فهرس الثغرات والتحقق منه", () => action(async () => {
    if (!active()) return;
    file.disabled = sources.disabled = true;
    try {
    let eid = sources.value;
    if (file.files[0]) {
      const selected = file.files[0];
      if (selected.size > 4 * 1024 * 1024) throw Error("حد الفهرس4ميبيبايت");
      const bytes = new Uint8Array(await selected.arrayBuffer());
      let raw = "";
      for (let i=0; i<bytes.length; i+=32768) raw += String.fromCharCode(...bytes.subarray(i,i+32768));
      if (!active()) return;
      const uploaded = await api("upload", {project_id:pid,name:selected.name,base64:btoa(raw)});
      eid = uploaded.id;
    }
    if (!eid) throw Error("اختر ملفًا من جهازك أو ملفًا أصليًا محفوظًا");
    await api("knowledge/offline/import", {project_id:pid,evidence_id:eid});
    if (!active()) return;
    const project = await api("project?id=" + pid);
    if (!active()) return;
    state.project = project; file.value=""; output.replaceChildren(); updateSources();
    await load(); toast("اكتمل الاستيراد؛ الفهرس جاهز للبحث دون إنترنت");
    } finally { file.disabled = sources.disabled = false; }
  }, submit), "primary");
  const search = button("بحث في الفهرس المستورد", () => action(async () => {
    const requested = query.value;
    const result = await api("knowledge/offline/search?project=" + pid + "&q=" + encodeURIComponent(requested));
    if (!active() || query.value !== requested) return;
    output.replaceChildren(el("p", {}, result.total_matches + " نتيجة مطابقة؛ العرض حتى50سجلًا"),
      table(["معرف الثغرة", "المنتج", "الوصف", "الإجراء المعلن", "تاريخ المعالجة المعلن"], result.items.map(item =>
        [item.cveID,item.vendorProject + " / " + item.product,item.vulnerabilityName,item.requiredAction || "غير مذكور",item.dueDate || "غير مذكور"])));
  }, search));
  query.addEventListener("input", () => output.replaceChildren());
  const exportReceipt = button("تنزيل إثبات استيراد الفهرس", () => action(async () => {
    const chosen = receiptId;
    if (!chosen) return;
    const blob = await api("evidence?project=" + pid + "&id=" + chosen, undefined, true);
    if (active() && chosen === receiptId) download(blob, "knowledge-import-receipt.json");
  }, exportReceipt));
  exportReceipt.disabled = true;
  holder.append(field("اختر فهرس الثغرات من جهازك", file), field("أو اختر ملفًا محفوظًا", sources), submit,
    current, exportReceipt, field("البحث بالمعرف أو المنتج أو الوصف", query), search, output);
  load().catch(error => {if (active()) toast(error.message,true);});
  return holder;
}
