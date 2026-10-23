/* Stable section/platform identities; shared services remain owner-authenticated. */
function workspacePage() {
  const requestedId = state.workspaceId;
  const holder = el("div", {class:"workspace-page stack"}, el("p", {}, "تحميل مساحة العمل…"));
  const active = () => holder.isConnected && state.view === "workspace" && state.workspaceId === requestedId;
  let current = null, selectedTab = "overview", generation = 0;
  const tabNames = {overview:"نظرة المساحة",tools:"أدوات المساحة",map:"خريطة المساحة",settings:"إعدادات الهوية"};
  const colors = {teal:"فيروزي",blue:"أزرق",violet:"بنفسجي",amber:"كهرماني",rose:"وردي"};

  function toolsView(workspace) {
    if (!workspace.tools.length) return empty("لم تُربط أدوات تشغيل بهذه المساحة بعد", "هوية المساحة وخريطتها وإعداداتها جاهزة؛ تقنيات هذا التخصص تحتاج تنفيذًا منفصلًا.");
    return el("div", {class:"grid"}, workspace.tools.map(tool => el("article", {class:"card"},
      badge("أداة ملفات متاحة", "good"), el("h3", {}, tool.name), el("p", {}, tool.input),
      el("p", {}, "حد الملف: " + size(tool.max_bytes || 4*1024*1024)),
      button("طريقة التشغيل: " + tool.name, () => openTool(tool), "primary"))));
  }
  function childCard(child) {
    return el("article", {class:"card workspace-child workspace-color-" + child.color},
      el("span", {class:"workspace-icon","aria-hidden":"true"}, child.icon),
      el("h3", {}, child.title),
      el("small", {class:"code"}, child.id),
      button("فتح مساحة: " + child.title, () => goWorkspace(child.id), "primary"));
  }
  function overview(workspace) {
    return el("div", {class:"stack"},
      panel("مساحة العمل والخدمات المشتركة", el("p", {}, workspace.description),
        el("div", {class:"workspace-services actions"},
          button("المشاريع والأدلة", () => go("projects")),
          button("المعرفة المشتركة", () => go("knowledge")),
          button("المساعد المحلي", () => go("assistant")),
          button("الصيانة", () => go("maintenance", workspace.type === "section" ? workspace.id : workspace.parent_id))),
        el("small", {}, "تظل صلاحيات المالك وسياق المشروع وحدود التشغيل مشتركة. اختلاف هوية الصفحة لا ينشئ عزلًا أو أداة جديدة.")),
      workspace.children.length ? panel("المنصات التابعة", el("div", {class:"grid"}, workspace.children.map(childCard))) : null,
      workspace.topics.length ? panel("موضوعات المساحة", el("ul", {}, workspace.topics.map(topic => el("li", {}, topic)))) : null,
      panel("الأدوات المرتبطة فعليًا", toolsView(workspace)),
      workspace.references.length ? panel("مراجع المساحة", references(workspace.references)) : null);
  }
  function mapView(workspace) {
    const children = workspace.children;
    const targets = children.length ? children : workspace.tools.map(tool => ({id:tool.id,title:tool.name,tool}));
    const meaning = children.length ? "الأسهم تعني أن المنصة تقع ضمن هذا القسم؛ لا تعني اكتمال تقنياتها." : "الأسهم تعني أن الأداة مرتبطة بهذه المنصة وقابلة للاستخدام ضمن عقد مدخلاتها.";
    return panel("العلاقات داخل المساحة", el("p", {}, meaning),
      el("div", {class:"workspace-map"},
        el("div", {class:"workspace-map-parent"}, el("span", {"aria-hidden":"true"}, workspace.icon), el("strong", {}, workspace.title)),
        targets.length ? el("div", {class:"workspace-map-targets"}, targets.map(target => el("div", {class:"workspace-map-branch"},
          el("span", {class:"workspace-map-arrow","aria-hidden":"true"}, "↓"),
          button(target.title, () => target.tool ? openTool(target.tool) : goWorkspace(target.id), "workspace-map-node")))) :
          el("p", {}, "لا توجد أداة مرتبطة لهذه المنصة بعد؛ لا تُعرض عقد تشغيل افتراضية.")),
      el("details", {}, el("summary", {}, "جدول العلاقات المكافئ"),
        table(["المصدر","العلاقة","الوجهة","فتح"], targets.map(target => [workspace.title,
          target.tool ? "تستخدم أداة ملفات" : "تحتوي منصة فرعية",target.title,
          button("فتح " + target.title, () => target.tool ? openTool(target.tool) : goWorkspace(target.id), "small")]))),
      workspace.references.length ? references(workspace.references) : null);
  }
  function settingsView(data) {
    const workspace = data.workspace;
    const title = el("input", {value:workspace.title,required:true,minlength:1,maxlength:120,"aria-label":"عنوان مساحة العمل"});
    const description = el("textarea", {required:true,minlength:1,maxlength:2000,rows:4,"aria-label":"وصف مساحة العمل"}, workspace.description);
    const icon = el("select", {"aria-label":"أيقونة مساحة العمل"}, data.icons.map(value => el("option", {value,selected:value === workspace.icon}, value)));
    const color = el("select", {"aria-label":"لون مساحة العمل"}, data.colors.map(value => el("option", {value,selected:value === workspace.color}, colors[value] || value)));
    const landing = el("select", {"aria-label":"صفحة افتتاح المساحة"}, data.landings.map(value => el("option", {value,selected:value === workspace.landing}, tabNames[value] || value)));
    const feedback = el("div", {"aria-live":"polite"});
    const save = el("button", {type:"submit",class:"primary"}, "حفظ هوية مساحة العمل");
    const form = el("form", {class:"stack",onsubmit:event => {
      event.preventDefault();
      action(async () => {
        if (!active()) return;
        const requestedGeneration = generation;
        const controls = [title,description,icon,color,landing,save];
        controls.forEach(control => {control.disabled=true;});
        try {
          const updated = await api("workspaces/settings", {id:workspace.id,revision:workspace.revision,
            title:title.value,description:description.value,icon:icon.value,color:color.value,landing:landing.value});
          if (!active()) return;
          current = updated;
          // Refresh navigation labels without changing fixed workspace identifiers.
          try { await refresh(); } catch { toast("حُفظت الهوية؛ حدّث بيانات التنقل عند توفر الخدمة", true); }
          if (!active()) return;
          if (requestedGeneration === generation) selectedTab = "settings";
          draw(); toast("حُفظت هوية المساحة مع بقاء معرفها ثابتًا");
        } catch (error) {
          if (active() && requestedGeneration === generation) feedback.replaceChildren(
            el("p", {class:"notice"}, error.message),
            button("إعادة تحميل الهوية الحالية", () => action(async () => { await load(false); selectedTab="settings"; draw(); }), "small"),
            el("small", {}, "تبقى تعديلاتك في النموذج الحالي حتى تختار إعادة التحميل. لا تُستبدل مراجعة أحدث بصمت."));
        } finally { controls.forEach(control => {control.disabled=false;}); }
      });
    }},
    el("p", {}, "هذه الإعدادات تخص عرض المساحة في هذا التثبيت الخاص، ولا تغير المعرف أو عضوية الأدوات أو صلاحيات التنفيذ."),
    row("المعرف الثابت", el("span", {class:"code"}, workspace.id)), row("مراجعة الإعدادات", workspace.revision),
    field("العنوان", title),field("الوصف", description),field("الأيقونة", icon),field("اللون", color),field("صفحة الافتتاح", landing),save,feedback);
    return panel("تخصيص الهوية وصفحة الافتتاح", form);
  }
  function draw() {
    if (!current || !active()) return;
    generation += 1;
    const workspace = current.workspace;
    holder.className = "workspace-page stack workspace-color-" + workspace.color;
    const panelId = "workspace-panel-" + requestedId;
    const content = el("div", {id:panelId,class:"workspace-tab-content",role:"tabpanel","aria-labelledby":"workspace-tab-" + requestedId + "-" + selectedTab});
    const tabs = el("div", {class:"workspace-tabs",role:"tablist","aria-label":"أقسام مساحة العمل"});
    for (const [key,label] of Object.entries(tabNames)) {
      const tab = button(label, () => {selectedTab=key; draw(); holder.querySelector('[role=tab][aria-selected=true]')?.focus();}, key === selectedTab ? "primary" : "ghost");
      tab.setAttribute("role","tab");tab.setAttribute("aria-selected",String(key === selectedTab));
      tab.setAttribute("id","workspace-tab-" + requestedId + "-" + key);
      tab.setAttribute("aria-controls",panelId);tab.setAttribute("tabindex",key === selectedTab ? "0" : "-1");
      tab.addEventListener("keydown", event => {
        if (!["ArrowLeft","ArrowRight","Home","End"].includes(event.key)) return;
        event.preventDefault();
        const keys = Object.keys(tabNames), position = keys.indexOf(key);
        selectedTab = event.key === "Home" ? keys[0] : event.key === "End" ? keys.at(-1) : keys[(position + (event.key === "ArrowLeft" ? 1 : -1) + keys.length) % keys.length];
        draw();holder.querySelector('[role=tab][aria-selected=true]')?.focus();
      });
      tabs.append(tab);
    }
    if (selectedTab === "settings") content.append(settingsView(current));
    else if (selectedTab === "map") content.append(mapView(workspace));
    else if (selectedTab === "tools") content.append(panel("أدوات مساحة العمل", toolsView(workspace)));
    else content.append(overview(workspace));
    holder.replaceChildren(
      el("div", {class:"workspace-breadcrumb actions","aria-label":"مسار مساحة العمل"},
        button("المنصة الأم", () => go("launchpad"), "ghost small"),
        workspace.parent_id ? button(workspace.parent_title || "القسم الأب", () => goWorkspace(workspace.parent_id), "ghost small") : null,
        el("span", {}, "← " + workspace.title)),
      el("header", {class:"workspace-identity"}, el("span", {class:"workspace-icon","aria-hidden":"true"}, workspace.icon),
        el("div", {}, badge(workspace.type === "section" ? "مساحة قسم رئيسي" : "مساحة منصة فرعية"),
          el("h2", {}, workspace.title),el("p", {}, workspace.description),el("small", {class:"code"}, workspace.id))),
      el("p", {class:"notice info"}, current.notice), tabs, content);
  }
  async function load(useLanding=true) {
    const data = await api("workspaces?id=" + encodeURIComponent(requestedId));
    if (!active()) return;
    current = data;
    if (useLanding) selectedTab = data.workspace.landing;
    draw();
  }
  load().catch(error => {if (active()) holder.replaceChildren(empty("تعذر تحميل مساحة العمل", error.message));});
  return holder;
}
