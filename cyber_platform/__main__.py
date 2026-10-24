import argparse
import getpass
import os
from pathlib import Path
from . import backup, desktop, plugin_package
from .server import App
from .store import Problem, Store


def main():
    parser = argparse.ArgumentParser(description="WAS local cyber research platform")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", aliases=["desktop"])
    serve.add_argument("--data", default=os.environ.get("WAS_DATA_DIR", str(Path.home() / ".local/share/was-platform")))
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--quota", type=int, default=2_000_000_000)
    serve.add_argument("--browser", choices=("auto",) + desktop.BROWSERS, default="auto", help="Chromium app-window browser (desktop only)")
    install = sub.add_parser("install-desktop", help="Install an application-menu entry for this Python installation")
    install.add_argument("--data", default=os.environ.get("WAS_DATA_DIR", str(Path.home() / ".local/share/was-platform")))
    install.add_argument("--applications-dir", help="Override the per-user applications directory")
    install.add_argument("--port", type=int, default=8080)
    install.add_argument("--browser", choices=("auto",) + desktop.BROWSERS, default="auto")
    install.add_argument("--replace", action="store_true", help="Replace this application's existing menu entry")
    restore = sub.add_parser("restore")
    restore.add_argument("file")
    restore.add_argument("destination")
    keygen = sub.add_parser("plugin-keygen", help="إنشاء مفتاح ناشر محلي بأمر المالك الصريح")
    keygen.add_argument("--output", required=True)
    package = sub.add_parser("plugin-package", help="توقيع حزمة إضافة محلية دون تشغيلها")
    for name in ("key", "manifest", "module", "fixtures", "output"):
        package.add_argument("--" + name, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command in ("plugin-keygen", "plugin-package"):
            from .store import encode
            result = plugin_package.generate_key(args.output) if args.command == "plugin-keygen" else plugin_package.build(
                args.key, args.manifest, args.module, args.fixtures, args.output)
            print(encode(result))
            return
        if args.command == "install-desktop":
            target = desktop.install_entry(args.data, args.applications_dir, args.port, args.browser, args.replace)
            print(f"Application-menu entry installed: {target}")
            return
        if args.command == "restore":
            backup.restore(Path(args.file).read_bytes(), getpass.getpass("Backup password: "), args.destination)
            print("Backup verified and restored to a new directory. Sessions were not restored.")
            return
        if args.quota < 1024 * 1024 or args.quota > 35_000_000_000:
            raise Problem("Evidence quota must be 1 MiB..35 GB")
        store = Store(args.data, args.quota)
        app = App(("127.0.0.1", args.port), store, os.environ.get("WAS_AI_URL", "http://127.0.0.1:8081/v1"), os.environ.get("WAS_AI_MODEL", "local"))
        print(f"WAS started on loopback port {app.server_port}. Data directory: {store.root}", flush=True)
        if not store.setting("owner"):
            print("Owner enrollment requires the private setup-token file in the data directory. Read it locally; do not share it in chat or Git.", flush=True)
        try:
            if args.command == "desktop":
                desktop.run(app, store.root, args.browser)
            else:
                app.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            app.server_close()
            store.close()
    except (Problem, OSError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
