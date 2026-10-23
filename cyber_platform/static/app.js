/* Offline UI: text nodes for all owner-controlled content; no external assets. */
const root = document.querySelector("#app");
const state = {
  boot: null,
  project: null,
  view: "dashboard",
  section: null,
  csrf: "",
  busy: false,
  integrityScan: null,
  qualityRun: null,
};
const nav = [
  ["dashboard", "◈", "نظرة عامة"],
  ["launchpad", "⌗", "خريطة المنظومة"],
  ["sections", "▦", "الأقسام والتخصصات"],
  ["projects", "▱", "المشاريع"],
  ["evidence", "◇", "الأدلة والملفات"],
  ["tools", "⌘", "أدوات التحليل"],
  ["knowledge", "◎", "المعرفة العالمية"],
  ["requirements", "☷", "ملف المشروع ومتطلباته"],
  ["workflows", "⇄", "سير العمل"],
  ["map", "⌗", "خريطة الأدلة"],
  ["workshop", "⌨", "ورشة البرمجة"],
  ["assistant", "✧", "المساعد المحلي"],
  ["audit", "≡", "سجل التدقيق"],
  ["settings", "⚙", "إدارة المنظومة"],
  ["maintenance", "⟳", "التحديث والصيانة"],
  ["quality", "✓", "جودة الأدوات"],
  ["events", "⇥", "توحيد الأحداث"],
  ["detection", "⌕", "مكتبة الكشف"],
  ["coverage", "◉", "التغطية الدفاعية"],
  ["plans", "⤴", "خطط التحليل"],
  ["reports", "▤", "تقارير المشروع"],
  ["curriculum", "◈", "مسارات التعلم"],
  ["plugins", "◇", "إدارة الإضافات"],
  ["technical", "⌘", "التحليل التقني"],
];
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (value !== false && value != null)
      node.setAttribute(key, value === true ? "" : value);
  }
  for (const c of children.flat(Infinity))
    if (c != null)
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}
const button = (text, fn, cls = "") =>
  el("button", { type: "button", class: cls, onclick: fn }, text);
const badge = (text, kind = "") => el("span", { class: "badge " + kind }, text);
const field = (title, node) => el("label", {}, title, node);
const pre = (value) =>
  el(
    "pre",
    { class: "code" },
    typeof value === "string" ? value : JSON.stringify(value, null, 2),
  );
const panel = (title, ...children) =>
  el(
    "section",
    { class: "panel" },
    el("div", { class: "panel-head" }, el("h2", {}, title)),
    ...children,
  );
const size = (n) =>
  n >= 1e6
    ? (n / 1e6).toFixed(2) + " ميجابايت"
    : n >= 1024
      ? (n / 1024).toFixed(1) + " كيلوبايت"
      : n + " بايت";
const when = (n) =>
  new Intl.DateTimeFormat("ar-SA", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Riyadh",
  }).format(new Date(n * 1000));
const statusText = {
  succeeded: "نجحت",
  failed: "فشلت",
  running: "قيد التنفيذ",
  interrupted: "توقفت عند إعادة التشغيل",
};
function toast(text, error = false) {
  const n = el("div", { class: "toast" + (error ? " error" : "") }, text);
  document.querySelector("#notifications").append(n);
  setTimeout(() => n.remove(), 6500);
}
async function api(path, body, raw = false) {
  const response = await fetch("/api/" + path, {
    method: body === undefined ? "GET" : "POST",
    headers:
      body === undefined
        ? {}
        : { "Content-Type": "application/json", "X-CSRF-Token": state.csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!response.ok) {
    let msg = "تعذر إكمال الطلب";
    try {
      msg = (await response.json()).error || msg;
    } catch {}
    if (response.status === 401 && state.boot) {
      state.boot = null;
      await start();
    }
    throw Error(msg);
  }
  return raw ? response.blob() : response.json();
}
async function action(fn, btn) {
  if (state.busy) {
    toast("انتظر اكتمال المهمة الحالية", true);
    return;
  }
  state.busy = true;
  if (btn) btn.disabled = true;
  try {
    await fn();
  } catch (e) {
    toast(e.message, true);
  } finally {
    state.busy = false;
    if (btn) btn.disabled = false;
  }
}
function download(blob, name) {
  const a = el("a", { href: URL.createObjectURL(blob), download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
async function refresh() {
  state.boot = await api("bootstrap");
  state.csrf = state.boot.csrf;
  if (state.project)
    state.project = await api("project?id=" + state.project.project.id);
}
function go(view, section = null) {
  state.view = view;
  state.section = section;
  const hash = section && view === "sections" ? "section-" + section : view;
  if (location.hash !== "#" + hash) history.pushState(null, "", "#" + hash);
  render();
  window.scrollTo(0, 0);
}
function modal(title, ...children) {
  const previous = document.activeElement;
  const box = el("div", { class: "modal-backdrop" });
  const dialog = el("div", {
    class: "modal",
    role: "dialog",
    "aria-modal": "true",
    "aria-label": title,
    tabindex: "-1",
  });
  function close() {
    box.remove();
    previous?.focus();
  }
  dialog.append(
    button("إغلاق ×", close, "small close"),
    el("h2", {}, title),
    el("div", { class: "divider" }),
    ...children.filter((c) => c != null),
  );
  box.append(dialog);
  box.addEventListener("click", (e) => {
    if (e.target === box) close();
  });
  box.addEventListener("keydown", (e) => {
    if (e.key === "Escape") close();
    if (e.key === "Tab") {
      const nodes = [
        ...dialog.querySelectorAll("button,input,select,textarea,a"),
      ];
      if (e.shiftKey && document.activeElement === nodes[0]) {
        e.preventDefault();
        nodes.at(-1).focus();
      } else if (!e.shiftKey && document.activeElement === nodes.at(-1)) {
        e.preventDefault();
        nodes[0].focus();
      }
    }
  });
  document.body.append(box);
  dialog.focus();
  return close;
}
function empty(title, body, cta) {
  return el(
    "div",
    { class: "empty" },
    el("div", { class: "symbol" }, "◇"),
    el("strong", {}, title),
    el("p", {}, body),
    cta ? el("div", { class: "actions" }, cta) : null,
  );
}
function requireProject() {
  return state.project
    ? null
    : panel(
        "اختر مشروعًا أولًا",
        empty(
          "لكل مشروع أدلته ونتائجه",
          "أنشئ مشروعًا أو اختره من القائمة في أعلى الصفحة.",
          button("إنشاء مشروع", newProject, "primary"),
        ),
      );
}
function newProject() {
  const name = el("input", {
      required: true,
      maxlength: 120,
      placeholder: "مثل: تحليل سجلات مشروع",
    }),
    description = el("textarea", {
      maxlength: 4000,
      placeholder: "هدف المشروع ونطاق البيانات",
    });
  const form = el(
    "form",
    { class: "stack" },
    field("اسم المشروع", name),
    field("الوصف", description),
  );
  const submit = el(
    "button",
    { class: "primary", type: "submit" },
    "إنشاء المشروع",
  );
  form.append(submit);
  const close = modal("مشروع جديد", form);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    action(async () => {
      const p = await api("projects", {
        name: name.value,
        description: description.value,
      });
      await refresh();
      state.project = await api("project?id=" + p.id);
      close();
      go("evidence");
      toast("تم إنشاء المشروع");
    }, submit);
  });
}
function brand() {
  return el(
    "div",
    { class: "brand" },
    el("div", { class: "brand-mark" }, "و"),
    el(
      "div",
      {},
      el("b", {}, "واس"),
      el("small", {}, "منصة البحث السيبراني"),
    ),
  );
}
async function start() {
  try {
    const status = await api("status");
    try {
      await refresh();
      const hash = location.hash.slice(1);
      if (hash.startsWith("section-")) {
        state.section = hash.slice(8);
        state.view = "sections";
      } else if (nav.some((n) => n[0] === hash)) state.view = hash;
      if (state.boot.projects.length)
        state.project = await api("project?id=" + state.boot.projects[0].id);
      render();
      return;
    } catch {}
    auth(status.initialized);
  } catch (e) {
    root.replaceChildren(empty("الخدمة غير متاحة", e.message));
  }
}
function auth(initialized) {
  state.boot = null;
  const password = el("input", {
    type: "password",
    autocomplete: initialized ? "current-password" : "new-password",
    required: true,
    minlength: 12,
    maxlength: 256,
    "aria-label": "كلمة المرور",
  });
  const error = el("p", { class: "login-error", role: "alert" });
  const setupToken = el("input", {
    type: "password",
    autocomplete: "off",
    required: true,
    maxlength: 128,
    "aria-label": "رمز التهيئة",
  });
  const submit = el(
    "button",
    { type: "submit", class: "primary" },
    initialized ? "دخول مساحة العمل" : "إنشاء حساب المالك",
  );
  const form = el(
    "form",
    { class: "stack" },
    !initialized ? field("رمز التهيئة", setupToken) : null,
    !initialized
      ? el(
          "small",
          {},
          "اقرأ الرمز من ملف setup-token في مجلد بيانات التطبيق على جهازك. لا ترسله في المحادثة أو ترفعه إلى GitHub.",
        )
      : null,
    field("كلمة المرور", password),
    el(
      "small",
      {},
      "12 حرفًا على الأقل. لا تُرسل كلمة المرور إلى أي خدمة خارجية.",
    ),
    error,
    submit,
  );
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      const login = await api(initialized ? "login" : "setup", {
        password: password.value,
        ...(!initialized ? { setup_token: setupToken.value } : {}),
      });
      state.csrf = login.csrf;
      await refresh();
      if (state.boot.projects.length)
        state.project = await api("project?id=" + state.boot.projects[0].id);
      render();
    } catch (e) {
      error.textContent = e.message;
    } finally {
      submit.disabled = false;
    }
  });
  root.replaceChildren(
    el(
      "main",
      { class: "auth" },
      el(
        "section",
        { class: "auth-intro" },
        brand(),
        el("div", { class: "eyebrow" }, "بياناتك هنا. أدواتك تحت إدارتك."),
        el("h1", {}, "مساحة واحدة،", el("br"), "لبحثٍ مترابط."),
        el(
          "p",
          {},
          "نظّم مشاريعك، حلّل ملفاتك، واربط النتائج بأدلتها. منصة عربية تعمل محليًا على لينكس.",
        ),
        el(
          "div",
          { class: "actions" },
          badge("22 قسمًا"),
          badge("تحليل دون اتصال"),
          badge("لا اشتراك إلزامي"),
        ),
      ),
      el(
        "section",
        { class: "auth-form" },
        el(
          "div",
          { class: "panel" },
          el("h2", {}, initialized ? "أهلًا بعودتك" : "مرحبًا في مساحة عملك"),
          el(
            "p",
            {},
            initialized
              ? "سجّل الدخول إلى حساب المالك المحلي."
              : "ابدأ بتهيئة حسابك لحماية الأدلة والمشاريع.",
          ),
          form,
        ),
      ),
    ),
  );
}
function render() {
  if (!state.boot) return;
  const side = el(
    "aside",
    { class: "sidebar" },
    brand(),
    el(
      "div",
      {},
      el("div", { class: "nav-title" }, "مساحة العمل"),
      el(
        "nav",
        { class: "nav", "aria-label": "القائمة الرئيسية" },
        nav.map(([id, icon, label]) =>
          el(
            "a",
            {
              href: "#" + id,
              class: state.view === id ? "active" : "",
              onclick: (e) => {
                e.preventDefault();
                go(id);
              },
            },
            el("span", { class: "nav-icon", "aria-hidden": "true" }, icon),
            label,
          ),
        ),
      ),
    ),
    el(
      "div",
      { class: "side-bottom" },
      el("small", {}, el("span", { class: "status-dot" }), "تشغيل محلي"),
      el("p", { class: "muted" }, "المحللات بلا اتصال خارجي"),
      el("small", {}, "نسخة البناء 0.11.0"),
    ),
  );
  const select = el(
    "select",
    { "aria-label": "المشروع الحالي" },
    el("option", { value: "" }, "اختر مشروعًا"),
    state.boot.projects.map((p) =>
      el(
        "option",
        { value: p.id, selected: state.project?.project.id === p.id },
        p.name,
      ),
    ),
  );
  select.addEventListener("change", () =>
    action(async () => {
      state.project = select.value
        ? await api("project?id=" + select.value)
        : null;
      render();
    }),
  );
  const content = el("div", { class: "content" });
  const current = nav.find((n) => n[0] === state.view);
  content.append(el("div", {class:"maintenance-toolbar"},
    el("details", {}, el("summary", {}, "إدارة البرنامج ▾"),
      el("div", {class:"actions"},
        button("فحص وصيانة جميع الأقسام", () => go("maintenance")),
        button("تحديث المعرفة", () => go("knowledge")),
        button("التطوير وترقية البرنامج", () => go("maintenance"))))));
  content.append(
    el(
      "header",
      { class: "page-head" },
      el(
        "div",
        {},
        el("div", { class: "eyebrow" }, "واس / مساحة العمل"),
        el(
          "h1",
          {},
          state.section && state.view === "sections"
            ? state.boot.catalog.find((s) => s.id === state.section)?.name
            : current?.[2],
        ),
        el("p", {}, subtitle()),
      ),
      state.view === "dashboard" || state.view === "projects"
        ? button("＋ مشروع جديد", newProject, "primary")
        : button(
            "تحديث البيانات",
            () =>
              action(async () => {
                await refresh();
                render();
              }),
            "ghost small",
          ),
    ),
  );
  const views = {
    launchpad: launchpadPage,
    dashboard,
    sections,
    projects,
    evidence,
    tools: toolPage,
    knowledge: knowledgePage,
    requirements: requirementsPage,
    workflows,
    map: mapPage,
    workshop,
    assistant,
    audit: auditPage,
    settings,
    maintenance: maintenancePage,
    quality: qualityPage,
    events: eventAdaptersPage,
    detection: detectionLibraryPage,
    coverage: defenseCoveragePage,
    plans: workflowPlansPage,
    reports: caseReportsPage,
    curriculum: curriculumPage,
    plugins: pluginsPage,
    technical: technicalAnalysisPage,
  };
  content.append(
    views[state.view]?.() || dashboard(),
    el(
      "div",
      { class: "footer-note" },
      "واس · منصة بحث محلية · حالة كل قدرة موضحة حسب تحققها الفعلي",
    ),
  );
  root.replaceChildren(
    el(
      "div",
      { class: "shell" },
      side,
      el(
        "main",
        { class: "main" },
        el(
          "div",
          { class: "topbar" },
          el(
            "div",
            { class: "context" },
            button(
              "☰",
              () => side.classList.toggle("open"),
              "mobile-menu small",
            ),
            el("span", { class: "muted" }, "المشروع الحالي"),
            select,
          ),
          el(
            "div",
            { class: "user" },
            el("span", { class: "status-dot" }),
            el("small", {}, "محلي • خاص"),
            el("div", { class: "avatar" }, "م"),
            button(
              "خروج",
              () =>
                action(async () => {
                  await api("logout", {});
                  state.project = null;
                  await start();
                }),
              "ghost small",
            ),
          ),
        ),
        content,
      ),
    ),
  );
}
function subtitle() {
  return {
    dashboard: "من الأدلة إلى النتائج، في مساحة عمل تملكها.",
    sections: "الخريطة التنظيمية من ملف المتطلبات، مع فصل المخطط عن المتاح.",
    projects: "سياق مستقل لكل بحث، ومرجع واضح لكل نتيجة.",
    evidence: "احفظ الأصل، تحقّق من البصمة، وتتبع ما اشتُق منه.",
    tools: "محللات محلية محددة النطاق. الملفات المرفوعة لا تُشغّل.",
    knowledge: "مصادر عامة عالمية ولقطات خاصة داخل مشروعك.",
    requirements:
      "الملف الأصلي كاملًا، ومعلوماته مفهرسة، وحالة تنفيذ متطلباته.",
    workflows: "خطوات قابلة للتتبع ومعايير قبول توقف السلسلة عند الفشل.",
    map: "كل علاقة تبدأ بدليل؛ اضغط عقدة لعرض سجلها.",
    workshop: "تعلّم وجرّب Python داخل عزل Linux، عند توفره.",
    assistant: "محرك محلي مشترك، مع أدلة تختارها أنت.",
    audit: "سجل إجراءات بسلسلة بصمات محلية قابلة للتحقق.",
    settings: "الموارد والنسخ الاحتياطية وحدود التشغيل.",
    quality: "عينات اصطناعية ثابتة ونتائج محفوظة؛ نجاحها لا يقيس الفعالية في العالم الحقيقي.",
  }[state.view];
}
function dashboard() {
  const b = state.boot,
    p = state.project;
  return el(
    "div",
    {},
    launchpadPage(),
    el(
      "section",
      { class: "hero" },
      el(
        "div",
        {},
        badge("معرفة عالمية · مساحة خاصة", "good"),
        el("h2", {}, "ابدأ من دليل. وابنِ عليه."),
        el(
          "p",
          {},
          "ارفع ملفًا إلى مشروعك، اختر أداة تحليل، ثم احفظ النتيجة واربطها بالأصل. كل تشغيل يسجّل مصدره وحالة قبوله.",
        ),
        el(
          "div",
          { class: "actions" },
          button("استعراض الأدوات", () => go("tools"), "primary"),
          button("خريطة التخصصات ←", () => go("sections"), "ghost"),
        ),
      ),
      el(
        "div",
        { class: "orbit" },
        el("b", {}, b.catalog.length),
        el("span", {}, "مجال بحث مترابط"),
      ),
    ),
    el(
      "div",
      { class: "stats" },
      stat("الأقسام الرئيسية", b.catalog.length, "أقسام ومنصات وأدوات"),
      stat("أدوات محلية", b.tools.length, "محللات محددة النطاق"),
      stat("المشاريع", b.projects.length, "محفوظة في هذا التثبيت"),
      stat(
        "أدلة المشروع",
        p?.evidence.length || 0,
        "أصول ونتائج ببصمات SHA-256",
      ),
    ),
    el(
      "div",
      { class: "grid two" },
      panel(
        "حالة مساحة العمل",
        row(
          "سجل التدقيق",
          badge(
            b.audit.valid ? "سليم" : "فشل التحقق",
            b.audit.valid ? "good" : "bad",
          ),
        ),
        row("مساحة الأدلة", size(b.resources.evidence_bytes)),
        row("المشروع المختار", p?.project.name || "لم يُحدد"),
        row("الاتصال الخارجي للمحللات", badge("معطّل", "good")),
      ),
      panel(
        "التشغيل والتحقق",
        el(
          "p",
          {},
          "22 قسمًا و109 منصات، تشمل الحماية الشاملة والتعلم الأخلاقي عبر 20 تخصصًا. مراجع تقنية عالمية مع فهرس CISA قابل للجلب والبحث والجدولة.",
        ),
        el("div", { class: "divider" }),
        row("الذكاء الاصطناعي", badge("يتطلب نموذجًا محليًا", "warn")),
        row("الجهاز الافتراضي", badge("صورة OVA غير مبنية", "warn")),
        row("الأجهزة والجوال", badge("غير مربوط")),
      ),
    ),
    panel(
      "مسارات التخصص",
      el("div", { class: "grid" }, b.catalog.slice(0, 6).map(sectionCard)),
    ),
  );
}
function stat(label, value, note) {
  return el(
    "div",
    { class: "stat" },
    el("small", {}, label),
    el("b", { class: "number" }, value),
    el("small", {}, note),
  );
}
function row(label, value) {
  return el(
    "div",
    { class: "row" },
    el("span", {}, label),
    value instanceof Node ? value : el("span", { class: "muted" }, value),
  );
}
function sectionCard(s) {
  const count = new Set(s.platforms.flatMap((p) => p.tool_ids)).size;
  return el(
    "article",
    { class: "card" },
    el(
      "div",
      { class: "card-top" },
      el("span", { class: "section-number" }, s.id),
      badge(s.platforms.length + " منصات"),
    ),
    el("h3", {}, s.name),
    el("p", {}, s.description || s.platforms.map((p) => p.name).join(" · ")),
    el(
      "footer",
      {},
      el("small", {}, count + " أداة مرتبطة"),
      button("فتح القسم ←", () => go("sections", s.id), "small ghost"),
    ),
  );
}
function references(items) {
  return el(
    "div",
    { class: "stack" },
    el(
      "small",
      {},
      "مراجع تقنية عالمية؛ روابط توثيق لا تعني تثبيت الأدوات أو متابعة إصداراتها تلقائيًا.",
    ),
    items.map((r) =>
      el(
        "a",
        { href: r.url, target: "_blank", rel: "noopener noreferrer" },
        r.name + " ↗",
      ),
    ),
  );
}
function platformCard(p) {
  const linked = state.boot.tools.filter((t) => p.tool_ids.includes(t.id));
  const lessons = (p.lesson_ids || []).map((id) =>
    state.boot.lessons.find((l) => l.id === id),
  );
  return el(
    "details",
    { class: "platform" },
    el(
      "summary",
      {},
      p.name,
      " · ",
      badge(linked.length + " أداة مرتبطة", linked.length ? "good" : ""),
    ),
    el(
      "div",
      { class: "platform-content stack" },
      el("p", {}, p.description),
      el(
        "ul",
        {},
        p.topics.map((t) => el("li", {}, t)),
      ),
      el(
        "div",
        { class: "actions" },
        linked.map((t) => button(t.name, () => openTool(t), "small")),
        lessons.map((l) =>
          button(
            "درس وتقييم: " + l.title,
            () => openLesson(l),
            "small primary",
          ),
        ),
      ),
      !linked.length
        ? el("small", {}, "نطاق موثق؛ لم تُربط أداة تنفيذ لهذا الجزء بعد.")
        : null,
      el("small", {}, p.scope),
      references(p.references),
      p.related_section_id
        ? button(
            "فتح قسم التخصص",
            () => go("sections", p.related_section_id),
            "ghost small",
          )
        : null,
    ),
  );
}
function openLesson(lesson) {
  const answers = el("div", { class: "checklist" });
  let selected = null;
  const output = el("div", { class: "stack" });
  lesson.choices.forEach((choice, i) =>
    answers.append(
      el(
        "label",
        {},
        el("input", {
          type: "radio",
          name: lesson.id,
          value: i,
          onchange: () => (selected = i),
        }),
        choice,
      ),
    ),
  );
  const submit = button(
    "تقييم الإجابة وتشغيل المثال",
    () =>
      action(async () => {
        if (!state.project) throw Error("اختر مشروعًا لحفظ محاولة التعلم");
        if (selected === null) throw Error("اختر إجابة");
        const response = await api("learning/attempt", {
          project_id: state.project.project.id,
          lesson_id: lesson.id,
          answer_index: selected,
        });
        await refresh();
        output.replaceChildren(
          badge(
            response.result.correct ? "إجابة صحيحة" : "تحتاج مراجعة",
            response.result.correct ? "good" : "warn",
          ),
          el("p", {}, response.result.explanation),
          el("small", {}, response.result.assessment),
          el("h3", {}, "نتيجة الأداة على بيانات اصطناعية"),
          pre(response.result.analysis),
          el("small", {}, "حُفظت المحاولة وبياناتها وبصمتها كدليل في المشروع."),
        );
      }, submit),
    "primary",
  );
  modal(
    lesson.title,
    el(
      "div",
      { class: "stack" },
      el("div", { class: "notice info" }, lesson.scope),
      el("p", {}, lesson.concept),
      el("h3", {}, lesson.question),
      answers,
      submit,
      output,
      references([lesson.source]),
    ),
  );
}
function sections() {
  if (state.section) {
    const s = state.boot.catalog.find((s) => s.id === state.section);
    if (!s) return empty("قسم غير موجود", "");
    const ids = new Set(s.platforms.flatMap((p) => p.tool_ids));
    return el(
      "div",
      {},
      button("→ جميع الأقسام", () => go("sections"), "small ghost"),
      button("صيانة وتطوير هذا القسم", () => go("maintenance", s.id), "small"),
      el("div", { class: "divider" }),
      el(
        "div",
        { class: "notice info" },
        "قسم رئيسي ← منصات فرعية ← أدوات وتقنيات. توفر الأداة محدد بوظيفتها واختباراتها؛ لا يعني تغطية التخصص بالكامل.",
      ),
      panel(
        "أدوات القسم المتاحة",
        el(
          "div",
          { class: "grid" },
          state.boot.tools.filter((t) => ids.has(t.id)).map(toolCard),
        ),
      ),
      panel("المنصات والأدوات والتقنيات", s.platforms.map(platformCard)),
    );
  }
  const list = el(
    "div",
    { class: "grid" },
    state.boot.catalog.map(sectionCard),
  );
  const search = el("input", {
    type: "search",
    placeholder: "ابحث عن قسم أو منصة…",
    "aria-label": "بحث الأقسام",
    class: "search",
    oninput: (e) => {
      const q = e.target.value;
      list.replaceChildren(
        ...state.boot.catalog
          .filter((s) =>
            (s.name + s.platforms.map((p) => p.name).join(" ")).includes(q),
          )
          .map(sectionCard),
      );
    },
  });
  return el("div", {}, search, list);
}
function projects() {
  return state.boot.projects.length
    ? el(
        "div",
        { class: "grid" },
        state.boot.projects.map((p) =>
          el(
            "article",
            { class: "card" },
            badge("مشروع محلي"),
            el("h3", {}, p.name),
            el("p", {}, p.description || "لا يوجد وصف"),
            el("small", {}, when(p.created)),
            button(
              "فتح المشروع",
              () =>
                action(async () => {
                  state.project = await api("project?id=" + p.id);
                  go("evidence");
                }),
              "primary",
            ),
          ),
        ),
      )
    : panel(
        "المشاريع",
        empty(
          "مشروعك الأول يبدأ هنا",
          "أنشئ مساحة تجمع الملفات والنتائج والعلاقات.",
          button("إنشاء مشروع", newProject, "primary"),
        ),
      );
}
function evidence() {
  const missing = requireProject();
  if (missing) return missing;
  const file = el("input", { type: "file", "aria-label": "اختر ملف الدليل" });
  const upload = button(
    "رفع وحفظ الأصل",
    () =>
      action(async () => {
        if (!file.files[0]) throw Error("اختر ملفًا");
        const f = file.files[0];
        if (f.size > 16 * 1024 * 1024) throw Error("حد الملف 16 MiB");
        const bytes = new Uint8Array(await f.arrayBuffer());
        let raw = "";
        for (let i = 0; i < bytes.length; i += 32768)
          raw += String.fromCharCode(...bytes.subarray(i, i + 32768));
        await api("upload", {
          project_id: state.project.project.id,
          name: f.name,
          base64: btoa(raw),
        });
        await refresh();
        render();
        toast("حُفظ الدليل وبصمته");
      }),
    "primary",
  );
  return el(
    "div",
    {},
    panel(
      "إضافة دليل",
      el(
        "div",
        { class: "form-grid" },
        field("ملف من جهازك، حتى 16 MiB", file),
        el("div", { class: "actions" }, upload),
      ),
      el(
        "small",
        {},
        "التحليل حتى 4 MiB. تحفظ الملفات بأسماء داخلية؛ لا يُنفّذ محتواها.",
      ),
    ),
    panel(
      "مستودع أدلة المشروع",
      state.project.evidence.length
        ? table(
            ["الملف", "النوع / الحجم", "البصمة", "الإجراءات"],
            state.project.evidence.map((e) => [
              el(
                "div",
                {},
                el("b", {}, e.name),
                el("div", { class: "muted" }, when(e.created)),
              ),
              el(
                "div",
                {},
                badge(
                  e.kind === "original"
                    ? "أصل"
                    : e.kind === "reference"
                      ? "مرجع"
                      : e.kind === "learning"
                        ? "تعلّم"
                        : "نتيجة",
                  e.kind === "original" ? "" : "good",
                ),
                el("div", { class: "code" }, size(e.size)),
              ),
              el("span", { class: "code" }, e.sha256.slice(0, 18) + "…"),
              el(
                "div",
                { class: "actions" },
                button("عرض", () => inspect(e), "small"),
                button(
                  "تنزيل",
                  () =>
                    action(async () =>
                      download(
                        await api(
                          "evidence?project=" + e.project_id + "&id=" + e.id,
                          undefined,
                          true,
                        ),
                        e.name,
                      ),
                    ),
                  "small ghost",
                ),
              ),
            ]),
          )
        : empty(
            "لا توجد أدلة بعد",
            "ارفع ملفًا أو استخدم عينة موضحة من صفحة الأدوات.",
          ),
    ),
  );
}
function table(headers, rows) {
  const head = el(
    "thead",
    {},
    el(
      "tr",
      {},
      headers.map((t) => el("th", { scope: "col" }, t)),
    ),
  );
  const body = el(
    "tbody",
    {},
    rows.map((row) =>
      el(
        "tr",
        {},
        row.map((c) => el("td", {}, c)),
      ),
    ),
  );
  return el("div", { class: "table-wrap" }, el("table", {}, head, body));
}
async function inspect(e) {
  await action(async () => {
    const blob = await api(
      "evidence?project=" + e.project_id + "&id=" + e.id,
      undefined,
      true,
    );
    const value = await blob.slice(0, 200000).text();
    let parsed;
    try {
      parsed = JSON.parse(value);
    } catch {}
    const chart =
      parsed?.result?.power || parsed?.result?.trace?.map((x) => x.temperature);
    modal(
      e.name,
      pre({ id: e.id, sha256: e.sha256, size: e.size, parent_id: e.parent_id }),
      chart ? plot(chart) : null,
      pre(parsed || value),
    );
  });
}
function evidenceSelect() {
  return el(
    "select",
    { "aria-label": "الدليل المختار" },
    el("option", { value: "" }, "اختر دليلًا…"),
    (state.project?.evidence || []).map((e) =>
      el("option", { value: e.id }, e.name + " · " + size(e.size)),
    ),
  );
}
function toolCard(t) {
  return el(
    "article",
    { class: "card" },
    el("div", { class: "card-top" }, badge(t.section), badge("محلي", "good")),
    el("h3", {}, t.name),
    el("p", {}, t.input),
    el(
      "footer",
      {},
      el("small", {}, "لا شبكة · حد " + size(t.max_bytes || 4 * 1024 * 1024)),
      button("تحليل", () => openTool(t), "small primary"),
    ),
  );
}
function toolPage() {
  return el(
    "div",
    {},
    el(
      "div",
      { class: "notice info" },
      state.boot.tools.length + " أداة تحليل واختبار قواعد بمدخلات وحدود معلنة. لا تفحص الأدوات أهدافًا خارجية، ولا تنفذ ملفات الأدلة.",
    ),
    el("div", { class: "grid" }, state.boot.tools.map(toolCard)),
  );
}
function openTool(t) {
  const guide = el("div", {class:"notice info"},
    el("h3", {}, "طريقة التشغيل"),
    el("ol", {},
      el("li", {}, "أنشئ مشروعًا أو اختر مشروعك من القائمة العلوية."),
      el("li", {}, "ارفع ملفك الأصلي بالصيغة الموضحة أدناه، أو اختر ملفًا سبق حفظه."),
      el("li", {}, "اضغط تشغيل التحليل؛ تظهر النتيجة وحالة التنفيذ وتُحفظ مرتبطة بالأصل وبصمته.")),
    el("p", {}, "المدخل: " + t.input),
    el("p", {}, "حد الملف: " + size(t.max_bytes || 4 * 1024 * 1024) + " · تحليل محلي دون اتصال بهدف خارجي."),
    el("small", {}, "العينة التعليمية اختيارية واصطناعية؛ تشغيلها ليس تحليلًا لبياناتك أو إثباتًا لحماية جهازك."));
  if (!state.project) {
    const close = modal(t.name, guide, button("إنشاء مشروع لبدء التشغيل", () => { close(); newProject(); }, "primary"));
    return;
  }
  const projectId = state.project.project.id;
  const currentProject = () => state.project?.project.id === projectId;
  const select = evidenceSelect(),
    expect = el("textarea", {
      class: "code",
      rows: 3,
      placeholder: '{"count": 2}',
    }),
    result = el("div", { class: "stack" });
  const run = button(
    "تشغيل التحليل",
    () =>
      action(async () => {
        if (!currentProject()) throw Error("تغير المشروع؛ أغلق الأداة وافتحها من جديد");
        if (!select.value) throw Error("اختر دليلًا");
        let acceptance = {};
        try {
          acceptance = JSON.parse(expect.value || "{}");
        } catch {
          throw Error("معيار القبول يحتاج JSON صحيحًا");
        }
        const job = await api("run", {
          project_id: projectId,
          name: t.name,
          steps: [
            { tool: t.id, evidence_id: select.value, expect: acceptance },
          ],
        });
        if (!currentProject()) return;
        await refresh();
        if (currentProject()) result.replaceChildren(jobResult(job));
      }, run),
    "primary",
  );
  const sample =
    t.sample === null
      ? null
      : button(
          "إضافة عينة تعليمية",
          () =>
            action(async () => {
              if (!currentProject()) throw Error("تغير المشروع؛ أغلق الأداة وافتحها من جديد");
              const raw = new TextEncoder().encode(t.sample);
              let s = "";
              for (const b of raw) s += String.fromCharCode(b);
              const e = await api("upload", {
                project_id: projectId,
                name: "sample-" + t.id + ".txt",
                base64: btoa(s),
              });
              if (!currentProject()) return;
              await refresh();
              if (!currentProject()) return;
              select.append(el("option", { value: e.id }, e.name));
              select.value = e.id;
              toast("أضيفت عينة تعليمية منفصلة عن بياناتك");
            }),
          "ghost",
        );
  const file = el("input", {type:"file", "aria-label":"ملف الأداة: " + t.name});
  const upload = button("رفع ملفي لهذه الأداة", () => action(async () => {
    if (!currentProject()) throw Error("تغير المشروع؛ أغلق الأداة وافتحها من جديد");
    const selected = file.files[0];
    if (!selected) throw Error("اختر ملفًا من جهازك");
    const limit = t.max_bytes || 4 * 1024 * 1024;
    if (selected.size > limit) throw Error("الملف يتجاوز حد الأداة: " + size(limit));
    const bytes = new Uint8Array(await selected.arrayBuffer());
    let raw = "";
    for (let i = 0; i < bytes.length; i += 32768) raw += String.fromCharCode(...bytes.subarray(i, i + 32768));
    if (!currentProject()) throw Error("تغير المشروع؛ أغلق الأداة وافتحها من جديد");
    const evidence = await api("upload", {project_id:projectId, name:selected.name, base64:btoa(raw)});
    if (!currentProject()) return;
    await refresh();
    if (!currentProject()) return;
    select.append(el("option", {value:evidence.id}, evidence.name));
    select.value = evidence.id;
    file.value = "";
    toast("حُفظ ملفك الأصلي؛ اضغط تشغيل التحليل");
  }, upload));
  modal(
    t.name,
    el(
      "div",
      { class: "stack" },
      guide,
      field("اختر ملفك لهذه الأداة", file), upload,
      field("الدليل", select),
      field("معايير قبول اختيارية: مسار حقل ونتيجة مطابقة", expect),
      el(
        "small",
        {},
        "ترك المعايير فارغة يشغّل التحليل دون ادعاء اجتياز قبول.",
      ),
      el("div", { class: "actions" }, run, sample),
      result,
    ),
  );
}
function jobResult(job) {
  return el(
    "div",
    { class: "stack" },
    el(
      "div",
      { class: "result-head" },
      badge(
        statusText[job.status] || uiLabel(job.status),
        job.status === "succeeded" ? "good" : "bad",
      ),
      el(
        "small",
        {},
        (job.completed ?? job.executed) + " / " + job.planned + " خطوات",
      ),
    ),
    job.reused
      ? el(
          "small",
          {},
          "أعيد استخدام " +
            job.reused +
            " خطوة متحقق منها؛ نُفذت " +
            job.executed +
            " خطوة جديدة",
        )
      : null,
    job.results.map((r) =>
      el(
        "div",
        {},
        r.output?.result?.power
          ? plot(r.output.result.power)
          : r.output?.result?.trace
            ? plot(r.output.result.trace.map((x) => x.temperature))
            : null,
        pre(r),
      ),
    ),
  );
}
function resumeJob(job) {
  const steps = el(
    "textarea",
    { class: "code", rows: 12, "aria-label": "خطة الاستكمال" },
    JSON.stringify(job.spec.steps, null, 2),
  );
  const out = el("div", { class: "stack" });
  const submit = button(
    "تحقق واستكمل",
    () =>
      action(async () => {
        let parsed;
        try {
          parsed = JSON.parse(steps.value);
        } catch {
          throw Error("صيغة JSON غير صحيحة");
        }
        const resumed = await api("workflows/resume", {
          project_id: state.project.project.id,
          source_job_id: job.id,
          steps: parsed,
          name: ("استكمال: " + job.name).slice(0, 120),
        });
        await refresh();
        out.replaceChildren(jobResult(resumed));
      }, submit),
    "primary",
  );
  modal(
    "استكمال سير العمل",
    el(
      "div",
      { class: "stack" },
      el(
        "p",
        {},
        "يمكن تعديل الخطوات غير المنجزة فقط. يتحقق الخادم من الأصل والنتائج وبصمات المحرك؛ تغير المنجز أو المحرك يمنع إعادة الاستخدام.",
      ),
      field("خطة الاستكمال", steps),
      submit,
      out,
    ),
  );
}
function comparisonPanel() {
  const options = () =>
    el(
      "select",
      {},
      el("option", { value: "" }, "اختر نتيجة تحليل…"),
      state.project.evidence
        .filter((e) => e.kind === "result")
        .map((e) => el("option", { value: e.id }, e.name)),
    );
  const left = options(),
    right = options(),
    out = el("div", {});
  left.setAttribute("aria-label", "النتيجة الأولى");
  right.setAttribute("aria-label", "النتيجة الثانية");
  const compare = button(
    "مقارنة وحفظ الفرق",
    () =>
      action(async () => {
        if (!left.value || !right.value) throw Error("اختر نتيجتي تحليل");
        const response = await api("results/compare", {
          project_id: state.project.project.id,
          left_id: left.value,
          right_id: right.value,
        });
        await refresh();
        out.replaceChildren(
          badge(
            response.result.equal
              ? "النتائج متساوية ضمن المقارنة"
              : response.result.truncated
                ? "مقارنة جزئية"
                : "توجد فروق",
            response.result.equal ? "good" : "warn",
          ),
          pre(response.result),
        );
      }, compare),
    "primary",
  );
  return panel(
    "مقارنة نتائج الأداة نفسها",
    el(
      "div",
      { class: "stack" },
      el(
        "p",
        {},
        "الفروق بنيوية ومحدودة العدد؛ لا تثبت وحدها أن نتيجة أو إصدارًا أكثر أمنًا.",
      ),
      el(
        "div",
        { class: "form-grid" },
        field("النتيجة الأولى", left),
        field("النتيجة الثانية", right),
      ),
      compare,
      out,
    ),
  );
}
function workflows() {
  const missing = requireProject();
  if (missing) return missing;
  const template = [
    {
      tool: "hashes",
      evidence_id:
        state.project.evidence.find((e) => e.kind === "original")?.id ||
        "SELECT_EVIDENCE_ID",
      expect: {},
    },
  ];
  const steps = el(
      "textarea",
      { class: "code", rows: 10 },
      JSON.stringify(template, null, 2),
    ),
    name = el("input", { value: "سير عمل جديد", maxlength: 120 }),
    out = el("div", {});
  const run = button(
    "تشغيل الخطوات",
    () =>
      action(async () => {
        let spec;
        try {
          spec = JSON.parse(steps.value);
        } catch {
          throw Error("صيغة خطوات JSON غير صحيحة");
        }
        const job = await api("run", {
          project_id: state.project.project.id,
          name: name.value,
          steps: spec,
        });
        await refresh();
        out.replaceChildren(jobResult(job));
      }, run),
    "primary",
  );
  return el(
    "div",
    {},
    panel(
      "خطة التحليل",
      el(
        "div",
        { class: "stack" },
        field("اسم سير العمل", name),
        field("خطوات JSON", steps),
        el(
          "small",
          {},
          "1–20 خطوة. tool: معرف الأداة؛ evidence_id: دليل المشروع؛ from_step: رقم نتيجة سابقة يبدأ من صفر. expect: مطابقة حقول النتيجة. لا أوامر نظام.",
        ),
        run,
        out,
      ),
    ),
    panel(
      "مهام المشروع",
      // Legacy team jobs remain stored, but are not executable workflow plans.
      state.project.jobs.filter((j) => j.spec?.schema !== "was.agents/1").length
        ? state.project.jobs.filter((j) => j.spec?.schema !== "was.agents/1").map((j) =>
            el(
              "div",
              { class: "row" },
              el(
                "div",
                {},
                el("b", {}, j.name),
                el("div", { class: "muted" }, when(j.created)),
              ),
              el(
                "div",
                { class: "actions" },
                badge(
                  statusText[j.status] || uiLabel(j.status),
                  j.status === "succeeded" ? "good" : "bad",
                ),
                button("النتائج", () => modal(j.name, pre(j)), "small"),
                ["failed", "interrupted"].includes(j.status)
                  ? button("استكمال", () => resumeJob(j), "small primary")
                  : null,
              ),
            ),
          )
        : empty("لم تُشغّل مهام بعد", "كل تشغيل ناجح أو فاشل يظهر هنا."),
    ),
    comparisonPanel(),
  );
}
function svg(tag, props = {}) {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(props)) n.setAttribute(k, v);
  return n;
}
function plot(values) {
  const chart = svg("svg", {
    viewBox: "0 0 600 180",
    class: "chart",
    role: "img",
    "aria-label": "منحنى نتيجة التحليل",
  });
  chart.append(svg("line", { x1: 20, y1: 160, x2: 580, y2: 160 }));
  const min = Math.min(...values),
    range = Math.max(...values) - min || 1;
  chart.append(
    svg("polyline", {
      points: values
        .map(
          (v, i) =>
            20 +
            (i * 560) / Math.max(1, values.length - 1) +
            "," +
            (155 - ((v - min) * 130) / range),
        )
        .join(" "),
    }),
  );
  return chart;
}
function mapPage() {
  const missing = requireProject();
  if (missing) return missing;
  const list = state.project.evidence.slice(0, 30),
    graph = svg("svg", {
      viewBox: "0 0 800 360",
      class: "graph",
      role: "img",
      "aria-label": "خريطة علاقات أدلة المشروع",
    });
  const positions = {};
  list.forEach((e, i) => {
    positions[e.id] = [90 + (i % 5) * 155, 55 + Math.floor(i / 5) * 52];
  });
  for (const r of state.project.relations) {
    if (positions[r.source] && positions[r.target]) {
      const [a, b] = positions[r.source],
        [c, d] = positions[r.target];
      graph.append(svg("line", { x1: a, y1: b, x2: c, y2: d }));
    }
  }
  for (const e of list) {
    const [x, y] = positions[e.id],
      circle = svg("circle", {
        cx: x,
        cy: y,
        r: 15,
        class: e.kind === "original" ? "" : "result",
        tabindex: 0,
        role: "button",
        "aria-label": e.name,
      });
    circle.addEventListener("click", () => inspect(e));
    circle.addEventListener("keydown", (event) => {
      if (event.key === "Enter") inspect(e);
    });
    const label = svg("text", {
      x: x + 22,
      y: y + 4,
      "text-anchor": "start",
      direction: "ltr",
    });
    label.textContent = e.name.slice(0, 14);
    graph.append(circle, label);
  }
  const source = evidenceSelect(),
    target = evidenceSelect(),
    label = el("input", { placeholder: "سبب العلاقة ومصدرها", maxlength: 100 });
  return el(
    "div",
    {},
    panel(
      "الأصول والنتائج",
      list.length
        ? graph
        : empty(
            "لا توجد عقد بعد",
            "أضف أدلة وشغّل تحليلًا لربط النتيجة بالأصل.",
          ),
      el("small", {}, "العرض حتى 30 عقدة حديثة؛ الجدول يشمل جميع العلاقات."),
    ),
    panel(
      "إضافة علاقة موثقة",
      el(
        "div",
        { class: "form-grid" },
        field("من الدليل", source),
        field("إلى الدليل", target),
        field("وصف العلاقة", label),
        el(
          "div",
          { class: "actions" },
          button(
            "حفظ العلاقة",
            () =>
              action(async () => {
                await api("relations", {
                  project_id: state.project.project.id,
                  source: source.value,
                  target: target.value,
                  label: label.value,
                });
                await refresh();
                render();
              }),
            "primary",
          ),
        ),
      ),
    ),
    panel(
      "جدول العلاقات",
      table(
        ["من", "إلى", "العلاقة"],
        state.project.relations.map((r) => [
          state.project.evidence.find((e) => e.id === r.source)?.name ||
            r.source,
          state.project.evidence.find((e) => e.id === r.target)?.name ||
            r.target,
          r.label,
        ]),
      ),
    ),
  );
}
function workshop() {
  const missing = requireProject();
  if (missing) return missing;
  const code = el(
      "textarea",
      { class: "code", rows: 10 },
      'import hashlib\nsample = b"local research"\nprint(hashlib.sha256(sample).hexdigest())\n',
    ),
    out = el("div", {});
  const run = button(
    "تشغيل في العزل",
    () =>
      action(async () => {
        const response = await api("workshop", {
          project_id: state.project.project.id,
          code: code.value,
        });
        await refresh();
        out.replaceChildren(pre(response.result));
      }, run),
    "primary",
  );
  return panel(
    "ورشة Python",
    el(
      "div",
      { class: "notice" },
      "يتطلب Bubblewrap وLinux user namespaces. عند غياب العزل يرفض التشغيل. حدود: ذاكرة 192 MiB، معالج 3 ثوانٍ، وقت 10 ثوانٍ؛ دون شبكة أو ملفات مشاريعك.",
    ),
    el(
      "div",
      { class: "stack" },
      field("مثال: حساب بصمة بيانات ثابتة", code),
      el(
        "p",
        {},
        "تمرين: غيّر النص ثم قارن البصمتين. هل تغيرت النتيجة؟ احتفظ بناتج التجربة في المشروع.",
      ),
      run,
      out,
    ),
  );
}
function assistant() {
  const missing = requireProject();
  if (missing) return missing;
  const question = el("textarea", {
      placeholder: "ما الذي تريد مراجعته؟",
      maxlength: 4000,
    }),
    chosen = [];
  const list = el(
    "div",
    { class: "checklist" },
    state.project.evidence.map((e) =>
      el(
        "label",
        {},
        el("input", {
          type: "checkbox",
          value: e.id,
          onchange: (event) => {
            if (event.target.checked) chosen.push(e.id);
            else chosen.splice(chosen.indexOf(e.id), 1);
          },
        }),
        e.name,
      ),
    ),
  );
  const output = el("div", {}),
    send = button(
      "سؤال المحرك المحلي",
      () =>
        action(async () => {
          const response = await api("chat", {
            project_id: state.project.project.id,
            question: question.value,
            evidence_ids: chosen,
          });
          output.replaceChildren(
            panel(
              "إجابة تحتاج مراجعة",
              pre(response.answer),
              el("p", {}, response.limitation),
              pre(response.evidence),
            ),
          );
        }, send),
      "primary",
    );
  return el(
    "div",
    {},
    panel(
      "مساعد المشروع",
      el(
        "div",
        { class: "notice info" },
        "يحتاج محركًا محليًا متوافقًا مع llama.cpp أو Ollama على loopback. النموذج غير مضمّن في هذه النسخة. لا API مدفوع، ولا صلاحية تنفيذ أوامر للمساعد.",
      ),
      el(
        "div",
        { class: "stack" },
        field("الأدلة المسموح بمشاركتها مع النموذج (حتى 4)", list),
        field("السؤال", question),
        send,
      ),
    ),
    output,
  );
}
function auditPage() {
  const holder = panel("سلسلة الإجراءات", el("p", {}, "تحميل السجل…"));
  api("audit")
    .then((data) => {
      holder.replaceChildren(
        el(
          "div",
          { class: "panel-head" },
          el("h2", {}, "سلسلة الإجراءات"),
          badge(
            data.verification.valid ? "البصمات متسقة" : "فشل التحقق",
            data.verification.valid ? "good" : "bad",
          ),
        ),
        el(
          "p",
          {},
          "يكشف التحقق تغيّر السجلات؛ لا يحمي من مدير جهاز يعيد بناء السلسلة كاملة.",
        ),
        table(
          ["التسلسل", "الإجراء", "الوقت", "التفاصيل"],
          data.events.map((e) => [
            e.seq,
            el("span", { class: "code" }, e.action),
            when(e.time),
            el("span", { class: "code" }, e.details),
          ]),
        ),
      );
    })
    .catch((e) => toast(e.message, true));
  return holder;
}
function requirementsPage() {
  const holder = el("div", { class: "stack" });
  let currentPage = 1,
    requestNumber = 0;
  const query = el("input", {
    type: "search",
    maxlength: 200,
    placeholder: "ابحث في المعلومات أو المتطلبات",
    "aria-label": "بحث ملف المشروع",
  });
  const mode = el(
    "select",
    { "aria-label": "نمط عرض الملف" },
    el("option", { value: "requirements" }, "المتطلبات وحالة التنفيذ"),
    el("option", { value: "source" }, "جميع معلومات الملف الأصلي"),
  );
  const filter = el(
    "select",
    { "aria-label": "حالة المتطلب" },
    el("option", { value: "" }, "كل الحالات"),
  );
  const matches = el("div", { class: "stack" }),
    meta = el("div", {}),
    pager = el("div", { class: "actions" });
  let filtersBuilt = false;
  async function load() {
    const request = ++requestNumber;
    const data = await api(
      "requirements?q=" +
        encodeURIComponent(query.value) +
        "&mode=" +
        mode.value +
        "&status=" +
        filter.value +
        "&page=" +
        currentPage,
    );
    if (request !== requestNumber) return;
    if (!filtersBuilt) {
      for (const [k, v] of Object.entries(data.labels))
        filter.append(el("option", { value: k }, v));
      filtersBuilt = true;
    }
    filter.classList.toggle("hidden", mode.value === "source");
    meta.replaceChildren(
      el("div", { class: "notice info" }, data.notice),
      panel(
        "الملف المحفوظ والتعديلات النافذة",
        row("حجم الأصل", size(data.source.bytes)),
        row("مقاطع مفهرسة", data.counts.source_blocks),
        row("متطلبات مرتبطة بمصدرها", data.counts.requirements),
        row("مراجع وروابط من الملف", data.counts.references),
        el("div", { class: "code" }, "SHA256: " + data.source.sha256),
        el(
          "ul",
          {},
          data.overrides.map((t) => el("li", {}, t)),
        ),
        el(
          "div",
          { class: "actions" },
          button(
            "تنزيل الملف الأصلي",
            () =>
              action(async () =>
                download(
                  await api("requirements/source", undefined, true),
                  data.source.filename,
                ),
              ),
            "small",
          ),
          button(
            "إضافة المرجع للمشروع المختار",
            () =>
              action(async () => {
                if (!state.project) throw Error("اختر مشروعًا أولًا");
                const imported = await api("requirements/import", {
                  project_id: state.project.project.id,
                });
                await refresh();
                toast(
                  imported.reused
                    ? "المرجع محفوظ في المشروع مسبقًا"
                    : "أضيف مرجع الملف إلى المشروع",
                );
              }),
            "small primary",
          ),
          button(
            "تصدير سجل المعلومات JSON",
            () =>
              action(async () =>
                download(
                  await api("requirements/export", undefined, true),
                  "requirements-register.json",
                ),
              ),
            "small",
          ),
        ),
      ),
    );
    matches.replaceChildren(
      el("small", {}, data.matches + " نتيجة؛ الصفحة " + data.page),
      ...data.items.map((item) =>
        data.mode === "source"
          ? el(
              "article",
              { class: "card" },
              el("h3", {}, item.heading || "مقدمة الملف"),
              badge(
                item.kind === "historical"
                  ? "سجل تاريخي؛ ليس تحققًا لهذا الكود"
                  : "نص مرجعي",
              ),
              el(
                "small",
                {},
                "المصدر: الأسطر " + item.line_start + "–" + item.line_end,
              ),
              pre(item.text),
            )
          : el(
              "article",
              { class: "card" },
              el(
                "div",
                { class: "card-top" },
                el("span", { class: "code" }, item.id),
                badge(
                  data.labels[item.status],
                  item.status === "available"
                    ? "good"
                    : item.status === "partial"
                      ? "warn"
                      : "",
                ),
              ),
              el("h3", {}, item.title),
              el("p", {}, item.scope),
              el(
                "small",
                {},
                "مراجع التنفيذ: " + item.evidence_paths.join(" · "),
              ),
              el(
                "div",
                { class: "actions" },
                item.source_ids.map((id) =>
                  button(
                    "عرض نص المصدر",
                    () =>
                      action(async () => {
                        const result = await api("requirements/block?id=" + id);
                        modal(
                          "نص الملف الأصلي",
                          el("div", { class: "notice info" }, result.notice),
                          el("p", {}, result.block.heading),
                          el(
                            "small",
                            {},
                            "الأسطر " +
                              result.block.line_start +
                              "–" +
                              result.block.line_end,
                          ),
                          pre(result.block.text),
                        );
                      }),
                    "small ghost",
                  ),
                ),
              ),
            ),
      ),
    );
    pager.replaceChildren(
      button(
        "السابق",
        () => {
          currentPage--;
          load().catch((e) => toast(e.message, true));
        },
        "small",
      ),
      el(
        "span",
        { class: "muted" },
        data.page +
          " / " +
          Math.max(1, Math.ceil(data.matches / data.page_size)),
      ),
      button(
        "التالي",
        () => {
          currentPage++;
          load().catch((e) => toast(e.message, true));
        },
        "small",
      ),
    );
    pager.firstElementChild.disabled = currentPage <= 1;
    pager.lastElementChild.disabled =
      currentPage * data.page_size >= data.matches;
  }
  const form = el(
    "form",
    { class: "stack" },
    el(
      "div",
      { class: "form-grid" },
      field("البحث", query),
      field("العرض", mode),
      field("الحالة", filter),
    ),
    el("button", { type: "submit", class: "primary" }, "بحث في الملف"),
  );
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    currentPage = 1;
    load().catch((e) => toast(e.message, true));
  });
  mode.addEventListener("change", () => {
    currentPage = 1;
    filter.value = "";
    load().catch((e) => toast(e.message, true));
  });
  filter.addEventListener("change", () => {
    currentPage = 1;
    load().catch((e) => toast(e.message, true));
  });
  holder.append(panel("وظائف جاهزة للتشغيل",
    el("p", {}, "هذه وظائف مكتملة ضمن حدودها المعلنة. البنود الأصلية الواسعة أدناه تجمع وظائف أخرى؛ لذلك قد يبقى المتطلب الكبير جزئيًا."),
    el("div", {class:"grid"},
      el("article", {class:"card"}, badge("جاهز", "good"), el("h3", {}, "رفع الأدلة وحفظ الأصل والبصمة"),
        el("p", {}, "ارفع ملفك، واحفظ الأصل منفصلًا عن النتائج، وتحقق من بصمته عند القراءة."), button("فتح الأدلة", () => go("evidence"))),
      el("article", {class:"card"}, badge("جاهز", "good"), el("h3", {}, state.boot.tools.length + " أداة لتحليل الملفات"),
        el("p", {}, "مدخلات وحدود معلنة، وتشغيل فعلي بنتيجة محفوظة مرتبطة بملفها الأصلي؛ لا فحص حي لجهازك."), button("فتح أدوات التحليل", () => go("tools"))),
      el("article", {class:"card"}, badge("جاهز", "good"), el("h3", {}, "استيراد فهرس الثغرات والبحث دون إنترنت"),
        el("p", {}, "ملف KEV أصلي، وتحليل متحقق، وإثبات استيراد قابل للتنزيل، واحتفاظ بالفهرس السابق عند رفض ملف جديد."), button("فتح استيراد فهرس الثغرات", () => go("knowledge")))
    )), meta, panel("معلومات الملف والمتطلبات", form), matches, pager);
  load().catch((e) => toast(e.message, true));
  return holder;
}
function knowledgePage() {
  const missing = requireProject();
  if (missing) return missing;
  const holder = el(
    "div",
    { class: "stack" },
    el("p", {}, "تحميل حالة المصادر…"),
  );
  const pid = state.project.project.id;
  async function load() {
    const data = await api("knowledge?project=" + pid);
    const stateNode = panel(
      "المصادر واللقطات",
      el("div", { class: "notice info" }, data.privacy),
      data.sources.map((source) => {
        const cached = data.states.find((s) => s.source_id === source.id);
        return el(
          "article",
          { class: "card" },
          el("h3", {}, source.name),
          references([{ name: source.publisher, url: source.reference }]),
          cached.evidence_id
            ? el(
                "div",
                {},
                row("إصدار المصدر", cached.version),
                row("السجلات", cached.count),
                row("آخر فحص", when(cached.checked_at)),
                row("آخر تغير محتوى", when(cached.changed_at)),
                badge(
                  cached.stale ? "لقطة قديمة؛ تعذر آخر جلب" : "آخر جلب ناجح",
                  cached.stale ? "warn" : "good",
                ),
                pre({ sha256: cached.sha256, evidence_id: cached.evidence_id }),
              )
            : el(
                "p",
                {},
                cached.error || "لم يُجلب هذا المصدر في المشروع بعد.",
              ),
          button(
            "جلب المصدر العام",
            () =>
              action(async () => {
                await api("knowledge/refresh", {
                  project_id: pid,
                  source_id: source.id,
                });
                await refresh();
                await load();
                toast("تم فحص المصدر وحفظ التغيير إن وجد");
              }),
            "primary",
          ),
        );
      }),
      el("small", {}, data.limitation),
    );
    const enabled = el("input", {
      type: "checkbox",
      checked: data.schedule.enabled && data.schedule.project_id === pid,
    });
    const interval = el("input", {
      type: "number",
      min: 60,
      max: 86400,
      value: data.schedule.interval_seconds || 60,
    });
    const schedule = panel(
      "جدولة الفحص",
      el(
        "div",
        { class: "stack" },
        el(
          "p",
          {},
          "معطلة افتراضيًا. تعمل أثناء تشغيل الخدمة؛ الفحص لا يعني توفر سجل جديد كل دقيقة. عند الانقطاع تبقى آخر لقطة مع إظهار قدمها.",
        ),
        el(
          "div",
          { class: "checklist" },
          field("تفعيل الجلب لهذا المشروع", enabled),
        ),
        field("فاصل الفحص بالثواني", interval),
        button(
          "حفظ إعداد الجدولة",
          () =>
            action(async () => {
              await api("knowledge/settings", {
                project_id: pid,
                enabled: enabled.checked,
                interval_seconds: Number(interval.value),
              });
              await load();
              toast("تم حفظ الجدولة");
            }),
          "primary",
        ),
      ),
    );
    const query = el("input", {
        type: "search",
        maxlength: 120,
        placeholder: "CVE أو الشركة أو المنتج",
        "aria-label": "بحث المعرفة",
      }),
      results = el("div", {});
    const search = async () => {
      const found = await api(
        "knowledge/search?project=" +
          pid +
          "&q=" +
          encodeURIComponent(query.value),
      );
      results.replaceChildren(
        el("small", {}, found.total_matches + " نتيجة؛ العرض حتى50"),
        table(
          ["CVE", "المنتج", "الوصف"],
          found.items.map((r) => [
            r.cveID,
            r.vendorProject + " / " + r.product,
            r.vulnerabilityName,
          ]),
        ),
      );
    };
    const form = el(
      "form",
      { class: "stack" },
      field("بحث في آخر لقطة محفوظة", query),
      el("button", { type: "submit", class: "primary" }, "بحث"),
      results,
    );
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      action(search);
    });
    holder.replaceChildren(
      offlineKnowledgePanel(),
      stateNode,
      schedule,
      panel("بحث المعرفة دون إرسال السؤال للمصدر", form),
    );
  }
  load().catch((e) => toast(e.message, true));
  return holder;
}
function settings() {
  const b = state.boot;
  const password = el("input", {
      type: "password",
      minlength: 12,
      maxlength: 256,
      autocomplete: "new-password",
      placeholder: "كلمة حماية لا تحفظها المنصة",
    }),
    save = button(
      "تنزيل نسخة مشفرة",
      () =>
        action(async () => {
          const blob = await api("backup", { password: password.value }, true);
          password.value = "";
          download(blob, "was-platform.cyberbackup");
          toast("تم تصدير نسخة مشفرة؛ احتفظ بكلمة حمايتها خارج المنصة");
        }, save),
      "primary",
    );
  return el(
    "div",
    {},
    el(
      "div",
      { class: "grid two" },
      panel(
        "الموارد المحلية",
        row("الأدلة المخزنة", size(b.resources.evidence_bytes)),
        row("حصة الأدلة", size(b.resources.evidence_quota)),
        row("متاح في نظام الملفات", size(b.resources.filesystem_free)),
        row("معالجات المضيف", b.resources.cpu_count),
        el(
          "p",
          {},
          "هدف المشروع حتى 35 GB حسب آخر تعديل في الملف. القياس أعلاه لبيئة التشغيل الحالية، ولا يثبت حجم جهاز افتراضي متكامل.",
        ),
      ),
      panel(
        "نسخة احتياطية مشفرة",
        el(
          "div",
          { class: "stack" },
          el(
            "p",
            {},
            "AES-256-GCM ومفتاح مشتق من كلمة حماية. حد هذه النسخة 120 MiB من الأدلة. الاستعادة من الطرفية إلى مجلد جديد؛ لا تستعاد جلسات الدخول.",
          ),
          field("كلمة حماية النسخة", password),
          save,
        ),
      ),
    ),
    panel(
      "حالة التكاملات",
      table(
        ["القدرة", "الحالة", "حدود النسخة"],
        [
          [
            "التحليل والأدلة وسير العمل",
            badge("متاح", "good"),
            "محلي وبأدوات محددة",
          ],
          [
            "المنصات والأدوات",
            badge("هيكل محدث", "good"),
            "22 قسمًا و109 منصات بأدوات وتقنيات مباشرة",
          ],
          [
            "المساعد المحلي",
            badge("يتطلب نموذجًا", "warn"),
            "يضبط عنوان المحرك محليًا في إعدادات التشغيل",
          ],
          [
            "المعرفة وتحديث البرامج",
            badge("جلب معرفة متاح", "good"),
            "فهرس CISA وجدولة اختيارية؛ ترقية البرنامج عبر إصدار Git محدد ومختبر من طرفية لينكس",
          ],
          [
            "VirtualBox / OVA",
            badge("غير مبني"),
            "تعليمات تجهيز لينكس في المستودع",
          ],
          ["الجوال والأجهزة", badge("مؤجلة"), "لا ربط أو تحكم مادي"],
        ],
      ),
    ),
  );
}
function qualityPage() {
  const labels = {pending:"بانتظار الدفعة الأولى", running:"قيد الفحص", completed:"اكتملت جميع الحالات", failed:"توقف الفحص ويحتاج مراجعة"};
  const output = el("div", {"aria-live":"polite"});
  const comparison = el("div", {"aria-live":"polite"});
  let selectedRun = null;
  const exportRun = button("تنزيل تقرير الجودة JSON", () => {
    if (selectedRun) download(new Blob([JSON.stringify(selectedRun, null, 2)], {type:"application/json"}), "quality-" + selectedRun.id + ".json");
  });
  exportRun.disabled = true;
  const catalog = el("div");
  const saved = el("select", {"aria-label":"فحص جودة محفوظ"});
  const left = el("select", {"aria-label":"فحص الجودة الأول"});
  const right = el("select", {"aria-label":"فحص الجودة الثاني"});
  const advance = button("تشغيل دفعة الجودة التالية", () => action(async () => {
    if (!state.qualityRun) return;
    show(await api("quality/advance", {run_id:state.qualityRun}));
    await history();
  }));
  advance.disabled = true;
  function show(run) {
    state.qualityRun = run.id;
    selectedRun = run;
    exportRun.disabled = false;
    advance.disabled = !["pending", "running"].includes(run.status);
    const counts = run.counts;
    const passed = run.status === "completed" && run.passed === true;
    output.replaceChildren(
      el("p", {}, badge(passed ? "اجتازت جميع العينات الاصطناعية" : labels[run.status] || run.status, passed ? "good":"warn")),
      el("p", {}, "معرّف فحص الجودة: ", el("span", {class:"code"}, run.id)),
      el("progress", {max:Math.max(counts.total, 1), value:counts.completed, "aria-label":"تقدم حالات الجودة"}),
      el("p", {}, "نُفّذ: " + counts.completed + " / " + counts.total + " · اجتاز: " + counts.passed + " · أخفق: " + counts.failed + " · متبقٍ: " + Math.max(0, counts.total - counts.completed)),
      run.error_code ? el("p", {class:"notice"}, "توقف التحقق: " + run.error_code + "؛ ابدأ فحصًا جديدًا بعد المراجعة.") : null,
      run.status === "completed" && !passed ? el("p", {class:"notice"}, "اكتمل التنفيذ مع حالات أخفقت؛ راجع التفاصيل قبل الاعتماد على التغيير.") : null,
      el("details", {}, el("summary", {}, "بصمات نطاق الفحص والمحرك"), pre({version:run.version, suite_sha256:run.suite_sha256, engine_sha256:run.engine_sha256})),
      run.results.length ? table(["الحالة", "الأداة", "النتيجة", "الوقت والبصمات"], run.results.map(result => [
        result.case_id, toolDisplayName(result.tool), result.status === "passed" ? "اجتاز" : "أخفق",
        el("details", {}, el("summary", {}, String(result.elapsed_ms) + " ms زمن منقضٍ"), pre({error_code:result.error_code || null, input_sha256:result.input_sha256, expected_sha256:result.expected_sha256, result_sha256:result.result_sha256})),
      ])) : el("p", {class:"muted"}, "لم تُنفّذ أي حالة بعد؛ شغّل الدفعة التالية."));
  }
  async function history() {
    const data = await api("quality/history");
    if (!saved.isConnected) return;
    for (const [select, prompt, rows] of [
      [saved, "اختر فحص جودة محفوظًا", data.runs],
      [left, "اختر الفحص الأول", data.runs.filter(run => run.status === "completed")],
      [right, "اختر الفحص الثاني", data.runs.filter(run => run.status === "completed")],
    ]) {
      const selected = select === saved ? state.qualityRun || select.value : select.value;
      select.replaceChildren(el("option", {value:""}, prompt), ...rows.map(run =>
        el("option", {value:run.id, selected:run.id === selected}, run.id + " · " + (labels[run.status] || run.status))));
    }
  }
  const result = el("div", {}, panel("نطاق جودة الأدوات",
    el("p", {class:"notice"}, "هذا فحص لعينات اصطناعية ثابتة داخل البرنامج. نجاحه لا يثبت جودة كل المدخلات أو فعالية الحماية في العالم الحقيقي، ولا يمثل نسبة اكتمال المشروع."), catalog),
    panel("تشغيل فحص الجودة وحفظه", el("p", {}, "التشغيل يدوي وعلى دفعات محدودة. تُحفظ كل نتيجة ويمكن متابعة الفحص بعد مغادرة الصفحة أو إعادة تحميلها؛ لا تُرسل أدلة المشاريع إلى هذا الفحص."),
      el("div", {class:"actions"}, button("بدء فحص جودة جديد", () => action(async () => {
        show(await api("quality/start", {}));
        await history();
      }), "primary"), advance),
      field("فحص جودة محفوظ", saved), button("عرض فحص الجودة المحفوظ", () => action(async () => {
        if (!saved.value) throw Error("اختر فحص جودة محفوظًا أولًا");
        show(await api("quality?run=" + encodeURIComponent(saved.value)));
      })), exportRun, output),
    panel("مقارنة فحصين مكتملين", el("p", {}, "قارن ترتيب النتائج من الأول إلى الثاني. تظهر حالات التراجع والتحسن؛ اختلاف المحرك معلومة مستقلة، ولا تعني النتائج المتطابقة تطابق الكود."),
      field("فحص الجودة الأول", left), field("فحص الجودة الثاني", right),
      button("مقارنة فحوص الجودة", () => action(async () => {
        if (!left.value || !right.value) throw Error("اختر فحصين مكتملين أولًا");
        const data = await api("quality/compare", {left_id:left.value, right_id:right.value});
        comparison.replaceChildren(
          el("p", {}, "حالات تراجع: " + data.regressions.length + " · حالات تحسن: " + data.improvements.length + " · دون تغير: " + data.unchanged.length),
          data.left_id === data.right_id ? el("p", {class:"notice"}, "مقارنة الفحص بنفسه؛ هذه مراجعة للنتائج المحفوظة وليست تشغيلًا مستقلًا جديدًا.") : null,
          data.engine_changed ? el("p", {class:"notice"}, "بصمة المحرك مختلفة بين الفحصين.") : null,
          data.regressions.length ? el("p", {}, "حالات التراجع: " + data.regressions.join("، ")) : el("p", {}, "لا توجد حالات تراجع ضمن هذه العينات"),
          data.improvements.length ? el("p", {}, "حالات التحسن: " + data.improvements.join("، ")) : null,
          table(["الحالة", "الأداة", "الفحص الأول", "الفحص الثاني"], data.transitions.map(item => [item.case_id, item.tool, item.left === "passed" ? "اجتاز":"أخفق", item.right === "passed" ? "اجتاز":"أخفق"])));
      })), comparison));
  api("quality/catalog").then(data => {
    if (!catalog.isConnected) return;
    catalog.replaceChildren(el("p", {}, data.notice),
      el("p", {class:"muted"}, "الوقت في النتائج هو الزمن المنقضي المقاس؛ قيود التشغيل ليست قياسات لاستهلاك الذاكرة."),
      el("p", {}, "حد الدفعة: " + data.limits.batch_cases + " حالات · " + data.limits.batch_seconds + " ثوانٍ · أقصى احتفاظ: " + data.limits.runs + " فحصًا"),
      el("details", {}, el("summary", {}, "حالات الفحص وبصماته"), pre({suite_sha256:data.suite_sha256, engine_sha256:data.engine_sha256}), table(["الحالة", "الأداة", "الوصف"], data.cases.map(item => [item.id, item.tool, item.title]))));
  }).catch(e => { if (catalog.isConnected) toast(e.message, true); });
  history().catch(e => { if (saved.isConnected) toast(e.message, true); });
  if (state.qualityRun) {
    const id = state.qualityRun;
    api("quality?run=" + encodeURIComponent(id)).then(run => {
      if (output.isConnected && state.qualityRun === id) show(run);
    }).catch(e => { if (output.isConnected) toast(e.message, true); });
  }
  return result;
}
function maintenancePage() {
  const integrityScope = el("select", {"aria-label":"نطاق فحص بصمات الأدلة"},
    el("option", {value:""}, "جميع المشاريع"),
    state.boot.projects.map(p => el("option", {value:p.id}, p.name)));
  const integrityOutput = el("div", {"aria-live":"polite"});
  const savedIntegrity = el("select", {"aria-label":"فحص محفوظ"}, el("option", {value:""}, "اختر فحصًا محفوظًا"));
  async function refreshIntegrityHistory() {
    const data = await api("integrity/history");
    if (!savedIntegrity.isConnected) return;
    const selected = state.integrityScan || savedIntegrity.value;
    savedIntegrity.replaceChildren(el("option", {value:""}, "اختر فحصًا محفوظًا"),
      ...data.scans.map(scan => el("option", {value:scan.id, selected:scan.id === selected}, scan.id + " · " + (integrityLabels[scan.status] || scan.status))));
  }
  const integrityLabels = {pending:"بانتظار الدفعة الأولى", running:"قيد الفحص", completed:"اكتمل", failed:"لم يجتز الفحص التحقق"};
  const advanceIntegrity = button("فحص الدفعة التالية", () => action(async () => {
    if (!state.integrityScan) return;
    const scan = await api("integrity/advance", {scan_id:state.integrityScan});
    showIntegrity(scan);
    await refreshIntegrityHistory();
  }));
  advanceIntegrity.disabled = true;
  function showIntegrity(scan) {
    state.integrityScan = scan.id;
    advanceIntegrity.disabled = !["pending", "running"].includes(scan.status);
    const passed = scan.status === "completed" && scan.passed === true;
    integrityOutput.replaceChildren(
      el("p", {}, badge(passed ? "اكتمل فحص البصمات بنجاح" : integrityLabels[scan.status] || scan.status, passed ? "good":"warn")),
      el("p", {}, "معرّف الفحص: ", el("span", {class:"code"}, scan.id)),
      el("progress", {max:Math.max(scan.total, 1), value:scan.cursor, "aria-label":"تقدم فحص بصمات الأدلة"}),
      el("p", {}, "فُحص: " + scan.scanned + " / " + scan.total + " · متحقق: " + scan.verified + " · ملاحظات: " + scan.failed),
      scan.scope_changed ? el("p", {class:"notice"}, "تغيّر نطاق الأدلة بعد بدء الفحص؛ ابدأ فحصًا جديدًا للتحقق من الحالة الحالية.") : null,
      scan.status === "completed" && !passed ? el("p", {class:"notice"}, "انتهى الفحص مع ملاحظات تحتاج مراجعة؛ لم تجتز الأدلة التحقق الكامل.") : null,
      scan.issues?.length ? table(["معرّف الدليل", "الملاحظة"], scan.issues.map(issue => [issue.id, issue.reason])) : null,
      el("p", {class:"muted"}, scan.limitation));
  }
  const integrityPanel = panel("فحص بصمات الأدلة على دفعات",
    el("p", {}, "يتحقق من الملفات المحفوظة دون تعديلها. كل دفعة محدودة بـ100 ملف و64 MiB وثلاث ثوانٍ؛ اضغط متابعة حتى يكتمل الفحص. النتيجة تخص لقطة الأدلة وقت البدء، ولا تعني إصلاح محتوى ملف تالف."),
    field("نطاق فحص بصمات الأدلة", integrityScope),
    el("div", {class:"actions"}, button("بدء فحص بصمات الأدلة", () => action(async () => {
      showIntegrity(await api("integrity/start", {project_id:integrityScope.value || null}));
      await refreshIntegrityHistory();
    })), advanceIntegrity),
    field("فحص محفوظ", savedIntegrity),
    button("متابعة الفحص المحفوظ", () => action(async () => {
      if (!savedIntegrity.value) throw Error("اختر فحصًا محفوظًا أولًا");
      showIntegrity(await api("integrity?scan=" + encodeURIComponent(savedIntegrity.value)));
    })), integrityOutput);
  if (state.integrityScan) {
    const id = state.integrityScan;
    api("integrity?scan=" + encodeURIComponent(id)).then(scan => {
      if (integrityOutput.isConnected && state.integrityScan === id) showIntegrity(scan);
    }).catch(e => { if (integrityOutput.isConnected) toast(e.message, true); });
  }
  const scope = el("select", {"aria-label":"نطاق الصيانة"},
    el("option", {value:""}, "جميع الأقسام"),
    state.boot.catalog.map(s => el("option", {value:s.id, selected:s.id === state.section}, s.name)));
  const output = el("div", {"aria-live":"polite"});
  const history = el("div");
  const tasks = el("div");
  const labels = {open:"مفتوح", in_progress:"قيد التطوير", done:"منجز حسب مراجعة المالك"};
  function showReport(r) {
    output.replaceChildren(panel("نتيجة الفحص", badge(r.passed ? "اجتاز الفحص المحدد" : "توجد ملاحظات أو فحص غير مكتمل", r.passed ? "good":"warn"),
      el("p", {}, r.limitation),
      table(["الفحص", "النتيجة", "التفاصيل"], r.checks.map(c => [maintenanceCheckLabel(c.id), c.status === "passed" ? "اجتاز":"يحتاج مراجعة", pre(c.detail)])),
      el("p", {}, "إصلاحات صلاحيات: " + r.repairs.length)));
  }
  function showTasks(rows) {
    tasks.replaceChildren(...rows.map(t => {
      const select = el("select", {"aria-label":"حالة طلب " + t.title},
        Object.entries(labels).map(([value,label]) => el("option", {value, selected:t.status===value}, label)));
      return el("article", {class:"card"}, el("h3", {}, t.title),
        el("p", {}, state.boot.catalog.find(s=>s.id===t.section_id)?.name), select,
        button("حفظ حالة الطلب", () => action(async () => {
          const result = await api("development", {id:t.id, status:select.value});
          showTasks(result.tasks);
        })));
    }));
  }
  async function load() {
    const data = await api("maintenance");
    history.replaceChildren(...data.runs.map(r => button(when(r.created) + " · " + (r.operation === "repair" ? "إصلاح":"فحص") + " · " + (r.report.passed ? "اجتاز":"ملاحظات"), () => showReport(r.report), "small ghost")));
    showTasks(data.tasks);
  }
  const run = operation => action(async () => {
    output.replaceChildren(el("p", {}, "يجري التحقق من البيانات وتشغيل عينات الأدوات…"));
    const result = await api("maintenance", {operation, section_id:scope.value || null});
    showReport(result);
    await load();
  });
  const title = el("input", {maxlength:300, minlength:3, required:true});
  const taskScope = el("select", {}, state.boot.catalog.map(s=>el("option", {value:s.id, selected:s.id===state.section}, s.name)));
  const form = el("form", {onsubmit:e=>{
    e.preventDefault();
    action(async ()=>{
      const result = await api("development", {section_id:taskScope.value, title:title.value});
      title.value="";
      showTasks(result.tasks);
      toast("حُفظ طلب التطوير للمراجعة والتنفيذ");
    });
  }}, field("قسم طلب التطوير", taskScope), field("عنوان طلب التطوير أو الخطأ", title),
  el("button", {type:"submit", class:"primary"}, "تسجيل طلب تطوير"));
  load().catch(e=>toast(e.message,true));
  refreshIntegrityHistory().catch(e=>toast(e.message,true));
  return el("div", {}, panel("فحص وصيانة الأقسام", field("نطاق الصيانة", scope),
    el("p", {}, "فحص قاعدة البيانات وسلسلة التدقيق وبصمات الأدلة وصلاحيات الملفات، مع تشغيل عينات ثابتة للأدوات المرتبطة بالقسم. الإصلاح يضبط صلاحيات الملفات المعروفة المتحققة فقط؛ لا يحذف الأدلة أو يعيد كتابة سجل تالف."),
    el("div", {class:"actions"}, button("تشغيل الفحص", ()=>run("check"), "primary"), button("إصلاح الصلاحيات وإعادة الفحص", ()=>run("repair")), button("تحديث المعرفة العالمية", ()=>go("knowledge")))),
    output, integrityPanel, panel("سجل آخر الفحوص", history),
    panel("التطوير والإبلاغ عن الأخطاء", el("p", {}, "طلبات متابعة يراجعها المالك؛ تسجيل الطلب لا يغيّر كود البرنامج ولا يعني تنفيذ الإصلاح."), form, tasks),
    panel("ترقية برنامج لينكس", el("p", {}, "تُجهّز نسخة مستقلة من التزام Git محدد، وتُفحص قبل تفعيلها. نزّل نسخة احتياطية مشفرة وأوقف الخدمة قبل تبديل الإصدار. نفّذ الأوامر من طرفية لينكس داخل المستودع الخاص؛ التفاصيل في docs/Maintenance.md."),
      el("p", {}, "للترقية الموقعة: أضف --signed ENVELOPE TRUST إلى أمر التجهيز والتفعيل بعد إعداد مفتاحك وثقتك محليًا. تُثبت بصمة الثقة ويُمنع التفعيل غير الموقّع لهذه البادئة. راجع docs/Signed-Releases.md. لا ترفع المفتاح الخاص أو كلمة حمايته إلى المشروع."),
      pre("bash scripts/release.sh prepare COMMIT_SHA /path/to/private-releases\nbash scripts/release.sh activate COMMIT_SHA /path/to/private-releases\nbash scripts/release.sh rollback /path/to/private-releases"),
      el("p", {}, "ترقيات حزم النظام والأدوات الخارجية تحتاج مستودعاتها الموقعة وإدارة لينكس. لا يمكن لهذا الفحص ضمان إصلاح جميع الأعطال تلقائيًا.")));
}
window.addEventListener("hashchange", () => {
  const hash = location.hash.slice(1);
  if (hash.startsWith("section-")) {
    state.view = "sections";
    state.section = hash.slice(8);
  } else if (nav.some((n) => n[0] === hash)) {
    state.view = hash;
    state.section = null;
  } else {
    state.view = "dashboard";
    state.section = null;
  }
  if (state.boot) render();
});
start();
