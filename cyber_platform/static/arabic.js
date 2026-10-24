/* Presentation labels only. Source data, identifiers and exported JSON stay intact. */
const ARABIC_UI_LABELS = Object.freeze({
  succeeded:"نجح التنفيذ", failed:"أخفق", running:"قيد التنفيذ", interrupted:"توقف التنفيذ", pending:"بانتظار التنفيذ",
  completed:"مكتمل", paused:"متوقف مؤقتًا", skipped:"تم تجاوز الخطوة", cancelled:"ملغى", passed:"اجتاز التحقق",
  reviewed:"تمت المراجعة", not_reviewed:"لم يُفحص ضمن النطاق", not_evaluated:"لم يُقيّم", available:"متاح للتشغيل",
  locked:"يتطلب إنجاز السابق", stale:"يحتاج إعادة تحقق", blocked:"محجوب بسبب تعارض", approved:"معتمد", disabled:"معطل", revoked:"مسحوب الاعتماد",
  high:"مرتفعة", medium:"متوسطة", low:"منخفضة", critical:"حرجة", warning:"تحذير", error:"خطأ", note:"ملاحظة", none:"دون مستوى محدد",
  hash_checked:"تحققت البصمة", replayed_passed:"أعيد التحقق واجتاز", replayed_failed:"أعيد التحقق وأخفق", replayed_not_evaluated:"أعيد التنفيذ دون تقييم مرجعي",
  not_replayed_budget:"لم تُعد التجربة بسبب حد الموارد", snapshot_only:"لقطة تاريخية فقط",
  within_validity_period:"ضمن فترة الصلاحية المحددة", not_yet_valid:"لم تبدأ الصلاحية", expired:"منتهية الصلاحية", valid:"صحيح", invalid:"غير صحيح",
  answer:"الإجابة", authority:"الخادم المرجعي", additional:"سجل إضافي",
  file:"ملف", directory:"مجلد", symlink:"رابط رمزي", hardlink:"رابط صلب", special:"عضو خاص",
  database:"قاعدة البيانات", audit:"سلسلة التدقيق", evidence:"بصمات الأدلة", permissions:"صلاحيات الملفات",
  unsupported_permissions:"صلاحيات غير مدعومة", license_review:"مراجعة الترخيص", incompatible_runtime:"عدم توافق بيئة التشغيل",
  missing_dependency:"اعتمادية غير موجودة", version_conflict:"تعارض إصدار الاعتمادية", dependency_not_approved:"اعتمادية غير معتمدة",
  dependency_cycle:"دورة في الاعتماديات", dependency_blocked:"اعتمادية محجوبة",
  insecure_transport:"اتصال مسجل دون تشفير النقل", credentials_over_http:"اعتمادات عبر اتصال غير مشفر", missing_csp:"سياسة أمان المحتوى غير مسجلة",
  missing_hsts:"سياسة فرض الاتصال المشفر غير مسجلة", missing_nosniff:"حماية تخمين نوع المحتوى غير مسجلة",
  cors_wildcard_credentials:"تعارض إعدادات مشاركة الموارد والاعتمادات", cookie_without_secure:"ملف ارتباط دون اشتراط اتصال مشفر",
  cookie_without_http_only:"ملف ارتباط دون قصر الوصول على بروتوكول الويب", cookie_without_same_site:"ملف ارتباط دون سياسة الموقع نفسه",
  same_site_none_without_secure:"ملف ارتباط عابر للمواقع دون اشتراط التشفير",
  hostNetwork:"مشاركة شبكة المضيف", hostPID:"مشاركة عمليات المضيف", hostIPC:"مشاركة اتصالات المضيف الداخلية",
  service_account_token_mount:"تركيب رمز حساب الخدمة", host_path_volume:"ربط مجلد من المضيف", privileged_container:"حاوية بامتيازات موسعة",
  privilege_escalation:"تصعيد الامتيازات غير محجوب", non_root_not_required:"عدم اشتراط مستخدم غير إداري", writable_root_filesystem:"نظام الملفات الجذري قابل للكتابة",
  root_uid:"تشغيل بمعرف المستخدم الإداري", capabilities_not_dropped:"لم تُسقط قدرات النظام المطلوبة", added_capabilities:"قدرات إضافية ممنوحة",
  seccomp_not_confined:"مرشح استدعاءات النظام غير مقيد", image_not_digest_pinned:"الصورة غير مثبتة ببصمة محتوى",
  missing_cpu_limit:"غياب حد المعالج", missing_memory_limit:"غياب حد الذاكرة", zero_cpu_limit:"حد المعالج مسجل بقيمة صفر", zero_memory_limit:"حد الذاكرة مسجل بقيمة صفر",
  exposed_service:"خدمة معروضة خارج الشبكة الداخلية", wildcard_rbac:"صلاحيات وصول عامة بنجمة", broad_subject_binding:"ربط صلاحيات بفئة واسعة",
  root_or_unspecified_user:"مستخدم الخدمة إداري أو غير محدد", namespaces_not_fully_restricted:"نطاقات العزل غير مقيدة بالكامل",
  capability_bounding_not_empty:"حد القدرات يسمح بقدرات نظام", ambient_capabilities:"قدرات موروثة ممنوحة",
  missing_NoNewPrivileges:"منع اكتساب امتيازات جديدة غير مفعل", missing_PrivateDevices:"عزل الأجهزة غير مفعل",
  missing_ProtectKernelTunables:"حماية إعدادات النواة غير مفعلة", missing_ProtectKernelModules:"حماية وحدات النواة غير مفعلة",
  missing_ProtectKernelLogs:"حماية سجلات النواة غير مفعلة", missing_ProtectControlGroups:"حماية مجموعات التحكم غير مفعلة",
  missing_RestrictSUIDSGID:"تقييد بتات الامتيازات غير مفعل", missing_MemoryDenyWriteExecute:"منع الكتابة والتنفيذ في الذاكرة غير مفعل",
  missing_LockPersonality:"تثبيت شخصية التنفيذ غير مفعل", missing_PrivateTmp:"عزل الملفات المؤقتة غير مفعل",
  missing_ProtectSystem:"حماية ملفات النظام غير مفعلة", missing_ProtectHome:"حماية مجلدات المستخدمين غير مفعلة",
  option_command:"خيار تنفيذ أمر مرتبط بالمفتاح", option_environment:"خيار بيئة مرتبط بالمفتاح",
  option_permitopen:"خيار السماح بوجهات تحويل الاتصال", option_permitlisten:"خيار السماح بوجهات الاستماع",
  option_cert_authority:"مفتاح موثق كسلطة شهادات", option_no_touch_required:"مفتاح يسمح بالاستخدام دون تأكيد لمسي",
  link_member:"رابط أرشيف يحتاج سياسة استخراج مستقلة",
  option_tunnel:"خيار نفق مرتبط بالمفتاح",
  duplicate_key:"مفتاح عام مكرر", weak_rsa_size:"مفتاح تشفير دون حد الحجم الموصى به", unsafe_path:"مسار عضو غير آمن",
  unsafe_link_target:"وجهة رابط غير مقيدة", special_member:"عضو خاص في نظام الملفات", encrypted_member:"عضو مشفر لم يُفحص محتواه",
  privileged_mode:"صلاحيات عضو تسمح بامتيازات إضافية", world_writable:"عضو قابل للكتابة من الجميع", declared_expansion:"تمدد معلن يتجاوز حد المراجعة",
  path_type_conflict:"تعارض نوع عضو مع مسار فرعي", duplicate_path:"مسار عضو مكرر",
});
const ARABIC_EVIDENCE_KINDS = Object.freeze({
  original:"ملف أصلي", reference:"مرجع", result:"نتيجة تحليل", knowledge:"لقطة معرفة", "knowledge-file":"إثبات استيراد فهرس الثغرات", learning:"تقييم تعلّم",
  "learning-assessment":"تقييم تعلّم", events:"أحداث موحدة", "normalized-events":"أحداث موحدة", "detection-test":"اختبار قواعد كشف",
  "plan-result":"نتيجة خطوة خطة", "plan-template":"قالب خطة", "plan-run":"تشغيل خطة", "plan-instantiation":"إثبات إنشاء خطة",
  "plugin-installation":"سجل تثبيت وتشغيل إضافة", "graph-entity":"كيان موثق", "graph-relation":"علاقة موثقة", "detection-fixture":"عينة مرجعية لقاعدة كشف", "detection-acceptance":"تقرير قبول قواعد الكشف",
  "coverage-scan":"فحص تغطية", "project-report":"تقرير مشروع", "plugin-registry":"سجل بيانات إضافة", "comparison":"مقارنة نتائج",
});
function uiLabel(value) {
  return typeof value === "string" && Object.hasOwn(ARABIC_UI_LABELS, value) ? ARABIC_UI_LABELS[value] : value;
}
function evidenceKindLabel(value) {
  return typeof value === "string" && Object.hasOwn(ARABIC_EVIDENCE_KINDS, value) ? ARABIC_EVIDENCE_KINDS[value] : value;
}
function toolDisplayName(identifier) {
  return state.boot?.tools.find(tool => tool.id === identifier)?.name || identifier;
}
function maintenanceCheckLabel(identifier) {
  return typeof identifier === "string" && identifier.startsWith("tool:") ? "اختبار الأداة: " + toolDisplayName(identifier.slice(5)) : uiLabel(identifier);
}
function findingDescription(code, fallback) {
  const translated = uiLabel(code);
  return translated !== code ? translated + ". ملاحظة ضمن مراجعة الملف؛ تحتاج تحققًا حسب سياق التشغيل." : fallback;
}
