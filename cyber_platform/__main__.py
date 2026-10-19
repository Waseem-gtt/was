import argparse
import getpass
import os
import threading
import webbrowser
from pathlib import Path
from . import backup
from .server import App
from .store import Problem, Store


def main():
    parser = argparse.ArgumentParser(description="WAS local cyber research platform")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", aliases=["desktop"])
    serve.add_argument("--data", default=os.environ.get("WAS_DATA_DIR", str(Path.home() / ".local/share/was-platform")))
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--quota", type=int, default=2_000_000_000)
    restore = sub.add_parser("restore")
    restore.add_argument("file")
    restore.add_argument("destination")
    args = parser.parse_args()
    os.umask(0o077)
    try:
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
                threading.Thread(target=webbrowser.open, args=(f"http://127.0.0.1:{app.server_port}",), daemon=True).start()
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
