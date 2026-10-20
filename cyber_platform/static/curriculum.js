/* Fixed synthetic learning paths; progress remains private to each project. */
function curriculumPage() {
  const missing = requireProject();
  if (missing) return missing;
  const pid = state.project.project.id;
  const pathSelect = el("select", {"aria-label":"مسار التعلم"});
  const lessonSelect = el("select", {"aria-label":"درس المسار"});
  const overview = el("div"), pathInfo = el("div"), lessonInfo = el("div");
  const output = el("div", {"aria-live":"polite"});
  let catalog = null, progress = null, selectedAnswer = null, loading = true;
  const labels = {passed:"اجتاز هذا التقييم",attempted:"تحتاج الإجابة مراجعة",available:"متاح للتقييم",locked:"بانتظار الدرس السابق",stale:"تحتاج المحاولة إعادة تحقق"};
  const active = () => rootNode.isConnected && state.project?.project.id === pid;
  const submit = button("تقييم درس المسار وحفظ المحاولة", () => action(async () => {
    if (selectedAnswer === null) throw Error("اختر إجابة من الخيارات المسجلة");
    const response = await api("curriculum/attempt", {project_id:pid,path_id:pathSelect.value,lesson_id:lessonSelect.value,answer_index:selectedAnswer});
    if (!active()) return;
    progress = response.progress;
    drawProgress(); drawPath();
    const result = response.result, exercise = result.exercise || result;
    output.replaceChildren(badge(result.correct ? "إجابة المسار صحيحة":"إجابة المسار تحتاج مراجعة",result.correct ? "good":"warn"),
      el("p",{},exercise.explanation),el("p",{class:"muted"},"حُفظت محاولة التقييم في أدلة هذا المشروع؛ لا تمثل شهادة إتقان."),
      el("p",{},"معرّف دليل المحاولة: ",el("span",{class:"code"},response.evidence.id)),
      el("details",{},el("summary",{},"تحليل المثال الاصطناعي وبصماته"),pre(exercise)));
    const fresh = await api("project?id=" + pid);
    if (active()) state.project = fresh;
  }),"primary");
  submit.disabled = true;
  const exportProgress = button("تنزيل تقدم التعلم JSON", () => {
    if (progress) download(new Blob([JSON.stringify(progress,null,2)],{type:"application/json"}),"learning-progress.json");
  });
  exportProgress.disabled = true;
  function selectedPath() { return catalog?.paths.find(path => path.id === pathSelect.value); }
  function pathProgress() { return progress?.paths.find(path => path.id === pathSelect.value); }
  function drawProgress() {
    const counts = progress.counts;
    overview.replaceChildren(el("p",{},"تقييمات مجتازة: " + counts.passed + " / " + counts.total),
      el("progress",{max:Math.max(counts.total,1),value:counts.passed,"aria-label":"تقدم تقييمات التعلم"}),
      el("p",{class:"muted"},"تحتاج مراجعة: " + counts.attempted + " · متاحة: " + counts.available + " · بانتظار متطلب سابق: " + counts.locked + " · قديمة: " + counts.stale),
      el("p",{class:"notice"},progress.notice || catalog.notice),
      el("p",{class:"muted"},"حد الحفظ: " + catalog.limits.attempts_per_lesson + " محاولة لكل درس، و" + catalog.limits.attempts + " محاولة لكل مشروع. لا تُحذف المحاولات تلقائيًا ولا يُعاد تعيينها لإخفاء نتائج سابقة."));
    exportProgress.disabled = false;
  }
  function drawLesson() {
    selectedAnswer = null;
    const lesson = catalog?.lessons.find(item => item.id === lessonSelect.value);
    const item = pathProgress()?.lessons.find(item => item.lesson_id === lessonSelect.value);
    if (!lesson || !item) { lessonInfo.replaceChildren(); submit.disabled = true; return; }
    const locked = item.status === "locked";
    const answers = el("fieldset",{class:"checklist"},el("legend",{},lesson.question));
    lesson.choices.forEach((choice,index) => answers.append(field(choice,el("input",{
      type:"radio",name:"curriculum-answer",value:index,disabled:locked,
      onchange:() => { selectedAnswer=index; },
    }))));
    lessonInfo.replaceChildren(el("h3",{},lesson.title),badge(labels[item.status] || item.status,item.status === "passed" ? "good":"warn"),
      el("p",{},lesson.concept),el("p",{class:"notice info"},lesson.scope),
      locked ? el("p",{class:"notice"},"اجتز تقييم الدرس السابق في هذا المسار أولًا."):null,
      answers,el("p",{class:"muted"},"الأداة: " + lesson.tool_id + " · المصدر المرجعي: " + lesson.source.name),
      el("p",{class:"muted"},lesson.assessment));
    submit.disabled = loading || locked;
  }
  function drawPath() {
    const path = selectedPath(), pathState = pathProgress();
    if (!path || !pathState) return;
    const chosen = lessonSelect.value;
    lessonSelect.replaceChildren(...path.lesson_ids.map(id => {
      const lesson = catalog.lessons.find(item => item.id === id);
      const item = pathState.lessons.find(item => item.lesson_id === id);
      return el("option",{value:id,selected:id === chosen},lesson.title + " · " + (labels[item.status] || item.status));
    }));
    pathInfo.replaceChildren(el("p",{},path.description),table(["الدرس","حالة التقييم","المحاولات","الإجابات الصحيحة"],pathState.lessons.map(item => [
      item.title,labels[item.status] || item.status,item.attempts,item.correct_attempts,
    ])));
    drawLesson();
  }
  pathSelect.addEventListener("change",() => { output.replaceChildren(); drawPath(); });
  lessonSelect.addEventListener("change",() => { output.replaceChildren(); drawLesson(); });
  async function load() {
    const [data,saved] = await Promise.all([api("curriculum"),api("curriculum/progress?project=" + pid)]);
    if (!active()) return;
    const chosen = pathSelect.value;
    catalog=data; progress=saved; loading=false;
    pathSelect.replaceChildren(...catalog.paths.map(path => el("option",{value:path.id,selected:path.id === chosen},path.title)));
    drawProgress(); drawPath();
  }
  const rootNode = el("div",{},panel("تقدم التعلم في المشروع",overview,
      button("إعادة التحقق من تقدم التعلم",() => action(load)),exportProgress),
    panel("مسارات مفاهيم وتقييمات اصطناعية",el("p",{class:"notice"},"تسلسل دروس بمتطلبات سابقة. لا تُجرى اختبارات على أجهزة أو مواقع حقيقية، ولا يُمنح تصريح اختبار أو اعتماد مهني."),
      field("مسار التعلم",pathSelect),pathInfo,field("درس المسار",lessonSelect),lessonInfo,submit,output));
  load().catch(error => { if (active()) toast(error.message,true); });
  return rootNode;
}
