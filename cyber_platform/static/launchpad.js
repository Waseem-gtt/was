/* The opening map navigates the real catalog; scope is never readiness. */
function launchpadPage() {
  const available = new Map(state.boot.tools.map(tool => [tool.id, tool]));
  const branches = el("div", {class:"launch-branches", "aria-label":"الأقسام الرئيسية"});
  const detail = el("div", {class:"launch-detail", "aria-live":"polite"});
  const search = el("input", {type:"search", "aria-label":"بحث خريطة المنظومة", placeholder:"ابحث باسم قسم أو منصة أو أداة…"});
  let selected = null;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "launch-lines");
  svg.setAttribute("aria-hidden", "true");
  const parent = el("div", {class:"launch-root"}, el("strong", {}, "واس"), el("span", {}, "المنصة الأم"));
  const map = el("div", {class:"launch-map"}, svg, parent, branches);
  function drawEdges() {
    if (!map.isConnected) return;
    const rect = map.getBoundingClientRect(), rootRect = parent.getBoundingClientRect();
    svg.setAttribute("viewBox", "0 0 " + rect.width + " " + rect.height);
    svg.replaceChildren();
    const x = rootRect.x - rect.x + rootRect.width / 2, y = rootRect.bottom - rect.y;
    for (const node of branches.querySelectorAll(".launch-node")) {
      const target = node.getBoundingClientRect();
      const tx = target.x - rect.x + target.width / 2, ty = target.y - rect.y - 5;
      const channel = target.y - rect.y - 22;
      const path = document.createElementNS(svg.namespaceURI, "path");
      path.setAttribute("d", `M ${x} ${y} V ${y + 8} H 3 V ${channel} H ${tx} V ${ty} m -4 -5 l 4 5 4 -5`);
      svg.append(path);
    }
  }
  const observer = new ResizeObserver(() => {
    if (!map.isConnected) { observer.disconnect(); return; }
    drawEdges();
  });
  requestAnimationFrame(() => { if (map.isConnected) { observer.observe(map); drawEdges(); } });
  function toolIds(section) {
    return new Set(section.platforms.flatMap(platform => platform.tool_ids).filter(id => available.has(id)));
  }
  function showPlatform(section, platform) {
    const tools = platform.tool_ids.map(id => available.get(id)).filter(Boolean);
    detail.replaceChildren(
      el("p", {class:"eyebrow"}, "واس ← " + section.name + " ← " + platform.name),
      el("h3", {}, platform.name), el("p", {}, platform.description),
      el("p", {class:"notice info"}, tools.length ? tools.length + " أداة ملفات متاحة هنا. اختر الأداة لقراءة طريقة التشغيل والمدخلات ثم تشغيلها على ملفك." : "هذه منصة ضمن نطاق المشروع؛ لم تُربط بها أداة تشغيل بعد."),
      el("ul", {}, platform.topics.map(topic => el("li", {}, topic))),
      el("div", {class:"grid"}, tools.map(tool => el("article", {class:"card"},
        badge("تحليل ملف محلي", "good"), el("h4", {}, tool.name), el("p", {}, tool.input),
        button("طريقة التشغيل: " + tool.name, () => openTool(tool), "primary")))),
      el("div", {class:"actions"}, button("→ منصات " + section.name, () => showSection(section)), button("مساحة القسم الكاملة", () => go("sections", section.id))),
      references(platform.references || [])
    );
  }
  function showSection(section) {
    selected = section.id;
    draw();
    detail.replaceChildren(
      el("p", {class:"eyebrow"}, "واس ← " + section.name),
      el("h3", {}, section.name), el("p", {}, section.description),
      el("p", {}, "اختر منصة للوصول إلى أدواتها وطريقة تشغيلها. عدد المنصات يصف النطاق، ولا يثبت اكتماله."),
      el("div", {class:"grid"}, section.platforms.map(platform => {
        const count = platform.tool_ids.filter(id => available.has(id)).length;
        return el("article", {class:"card"}, el("h4", {}, platform.name),
          badge(count ? count + " أداة متاحة" : "نطاق يحتاج تنفيذًا", count ? "good" : ""),
          button("فتح منصة: " + platform.name, () => showPlatform(section, platform), "small"));
      })),
      button("مساحة القسم الكاملة", () => go("sections", section.id), "ghost")
    );
  }
  function draw() {
    const query = search.value.trim().toLocaleLowerCase();
    const sections = state.boot.catalog.filter(section => [section.name, section.description,
      ...section.platforms.flatMap(platform => [platform.name, ...platform.tool_ids.map(id => available.get(id)?.name || "")])]
      .join(" ").toLocaleLowerCase().includes(query));
    branches.replaceChildren(...sections.map(section => el("div", {class:"launch-branch"},
      el("span", {class:"launch-arrow", "aria-hidden":"true"}, "↓"),
      el("button", {type:"button", class:"launch-node", "aria-pressed":section.id === selected,
        onclick:() => showSection(section)},
        el("span", {class:"section-number"}, section.id), el("strong", {}, section.name),
        el("small", {}, section.platforms.length + " منصة · " + toolIds(section).size + " أداة مرتبطة"))
    )));
    if (!sections.length) branches.append(el("p", {}, "لا توجد نتائج مطابقة."));
    requestAnimationFrame(drawEdges);
  }
  search.addEventListener("input", draw);
  draw();
  detail.append(el("p", {}, "اختر قسمًا من الخريطة، ثم منصة، ثم أداة. يمكن فتح دليل الأداة قبل إنشاء مشروع."));
  return panel("خريطة المنظومة",
    el("p", {}, "برنامج واحد على لينكس: المنصة الأم ← القسم الرئيسي ← المنصة الفرعية ← الأداة وطريقة تشغيلها."),
    search,
    map,
    detail,
    el("details", {}, el("summary", {}, "عرض قائمة مكافئة للخريطة"),
      el("ul", {}, state.boot.catalog.map(section => el("li", {},
        button(section.id + " · " + section.name, () => showSection(section), "ghost small"),
        el("span", {}, " — " + section.platforms.map(platform => platform.name).join("، "))))))
  );
}
