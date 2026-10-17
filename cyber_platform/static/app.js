/* Offline UI: text nodes for all owner-controlled content; no external assets. */
const root = document.querySelector("#app");
const state = {
  boot: null,
  project: null,
  view: "dashboard",
  section: null,
  csrf: "",
  busy: false,
};
const nav = [
  ["dashboard", "◈", "نظرة عامة"],
  ["sections", "▦", "الأقسام والتخصصات"],
  ["projects", "▱", "المشاريع"],
  ["evidence", "◇", "الأدلة والملفات"],
  ["tools", "⌘", "أدوات التحليل"],
  ["workflows", "⇄", "سير العمل"],
  ["map", "⌗", "خريطة الأدلة"],
  ["workshop", "⌨", "ورشة البرمجة"],
  ["assistant", "✧", "المساعد المحلي"],
  ["audit", "≡", "سجل التدقيق"],
  ["settings", "⚙", "إدارة المنظومة"],
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
    ? (n / 1e6).toFixed(2) + " MB"
    : n >= 1024
      ? (n / 1024).toFixed(1) + " KB"
      : n + " B";
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
  location.hash = section ? "section-" + section : view;
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
      placeholder: "مثل: تحليل سجلات المختبر",
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
      el("small", {}, "CYBER RESEARCH PLATFORM"),
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
  const submit = el(
    "button",
    { type: "submit", class: "primary" },
    initialized ? "دخول مساحة العمل" : "إنشاء حساب المالك",
  );
  const form = el(
    "form",
    { class: "stack" },
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
          badge("20 قسمًا"),
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
      el("small", {}, "نسخة البناء 0.1.0"),
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
  content.append(
    el(
      "header",
      { class: "page-head" },
      el(
        "div",
        {},
        el("div", { class: "eyebrow" }, "WAS / WORKSPACE"),
        el(
          "h1",
          {},
          state.section
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
    dashboard,
    sections,
    projects,
    evidence,
    tools: toolPage,
    workflows,
    map: mapPage,
    workshop,
    assistant,
    audit: auditPage,
    settings,
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
    workflows: "خطوات قابلة للتتبع ومعايير قبول توقف السلسلة عند الفشل.",
    map: "كل علاقة تبدأ بدليل؛ اضغط عقدة لعرض سجلها.",
    workshop: "تعلّم وجرّب Python داخل عزل Linux، عند توفره.",
    assistant: "محرك محلي مشترك، مع أدلة تختارها أنت.",
    audit: "سجل إجراءات بسلسلة بصمات محلية قابلة للتحقق.",
    settings: "الموارد والنسخ الاحتياطية وحدود التشغيل.",
  }[state.view];
}
function dashboard() {
  const b = state.boot,
    p = state.project;
  return el(
    "div",
    {},
    el(
      "section",
      { class: "hero" },
      el(
        "div",
        {},
        badge("مركز البحث المحلي", "good"),
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
        el("b", {}, "20"),
        el("span", {}, "مجال بحث مترابط"),
      ),
    ),
    el(
      "div",
      { class: "stats" },
      stat("الأقسام الرئيسية", "20", "خريطة تنظيمية موثقة"),
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
          "تضم الخريطة 69 منصة و207 مختبرات مخططة. ظهورها لا يعني تجهيز بيئاتها.",
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
  const t = state.boot.tools.find((t) => t.section === s.id);
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
    el("p", {}, s.platforms.map((p) => p.name).join(" · ")),
    el(
      "footer",
      {},
      el("small", {}, t ? "أداة محلية متاحة" : "تصميم"),
      button("فتح القسم ←", () => go("sections", s.id), "small ghost"),
    ),
  );
}
function sections() {
  if (state.section) {
    const s = state.boot.catalog.find((s) => s.id === state.section);
    if (!s) return empty("قسم غير موجود", "");
    return el(
      "div",
      {},
      button("→ جميع الأقسام", () => go("sections"), "small ghost"),
      el("div", { class: "divider" }),
      el(
        "div",
        { class: "notice info" },
        "المختبرات أدناه هيكل مخطط من المتطلبات. الأداة المتاحة لهذا القسم موضحة بصورة مستقلة.",
      ),
      panel(
        "الأداة المحلية المتاحة",
        state.boot.tools.filter((t) => t.section === s.id).map(toolCard),
      ),
      panel(
        "المنصات والمختبرات",
        s.platforms.map((p) =>
          el(
            "details",
            { class: "lab" },
            el("summary", {}, p.name, " · ", badge("مخطط")),
            el(
              "div",
              { class: "lab-content" },
              p.labs.map((l) =>
                el(
                  "div",
                  {},
                  el("b", {}, l.name),
                  el(
                    "ul",
                    {},
                    l.children.map((c) => el("li", {}, c.name)),
                  ),
                  el("small", { class: "code" }, l.id),
                ),
              ),
            ),
          ),
        ),
      ),
      panel(
        "عقد المحرك التنظيمي",
        pre({
          id: s.engine_id,
          inputs: ["selected_project_evidence"],
          outputs: ["analysis_result", "provenance"],
          permissions: ["evidence.read", "result.write"],
          network: false,
          state: "logical_definition",
        }),
      ),
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
                  e.kind === "original" ? "أصل" : "نتيجة",
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
      el("small", {}, "لا شبكة · حد 4 MiB"),
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
      "20 محللًا مختلفًا بمدخلات وحدود معلنة. لا تفحص الأدوات أهدافًا خارجية، ولا تنفذ ملفات الأدلة.",
    ),
    el("div", { class: "grid" }, state.boot.tools.map(toolCard)),
  );
}
function openTool(t) {
  if (!state.project) {
    toast("أنشئ مشروعًا أو اختره أولًا", true);
    return;
  }
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
        if (!select.value) throw Error("اختر دليلًا");
        let acceptance = {};
        try {
          acceptance = JSON.parse(expect.value || "{}");
        } catch {
          throw Error("معيار القبول يحتاج JSON صحيحًا");
        }
        const job = await api("run", {
          project_id: state.project.project.id,
          name: t.name,
          steps: [
            { tool: t.id, evidence_id: select.value, expect: acceptance },
          ],
        });
        await refresh();
        result.replaceChildren(jobResult(job));
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
              const raw = new TextEncoder().encode(t.sample);
              let s = "";
              for (const b of raw) s += String.fromCharCode(b);
              const e = await api("upload", {
                project_id: state.project.project.id,
                name: "sample-" + t.id + ".txt",
                base64: btoa(s),
              });
              await refresh();
              select.append(el("option", { value: e.id }, e.name));
              select.value = e.id;
              toast("أضيفت عينة تعليمية منفصلة عن بياناتك");
            }),
          "ghost",
        );
  modal(
    t.name,
    el(
      "div",
      { class: "stack" },
      el("p", {}, t.input),
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
        statusText[job.status] || job.status,
        job.status === "succeeded" ? "good" : "bad",
      ),
      el("small", {}, job.executed + " / " + job.planned + " خطوات"),
    ),
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
      state.project.jobs.length
        ? state.project.jobs.map((j) =>
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
                  statusText[j.status] || j.status,
                  j.status === "succeeded" ? "good" : "bad",
                ),
                button("النتائج", () => modal(j.name, pre(j)), "small"),
              ),
            ),
          )
        : empty("لم تُشغّل مهام بعد", "كل تشغيل ناجح أو فاشل يظهر هنا."),
    ),
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
            "المختبرات التخصصية الـ207",
            badge("مخططة", "warn"),
            "الهيكل محفوظ؛ لا ادعاء تجهيزها",
          ],
          [
            "المساعد المحلي",
            badge("يتطلب نموذجًا", "warn"),
            "يضبط عنوان المحرك محليًا في إعدادات التشغيل",
          ],
          [
            "تحديثات البرامج والمصادر",
            badge("غير منفذة"),
            "لا تنزيل أو تركيب صامت",
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
window.addEventListener("hashchange", () => {
  const hash = location.hash.slice(1);
  if (hash.startsWith("section-")) {
    state.view = "sections";
    state.section = hash.slice(8);
  } else if (nav.some((n) => n[0] === hash)) {
    state.view = hash;
    state.section = null;
  }
  if (state.boot) render();
});
start();
