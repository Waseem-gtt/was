"""Linux app-window launcher and explicit per-user desktop integration."""
import os
import shutil
import subprocess  # nosec B404 — fixed browser choices and arguments; no shell or evidence commands.
import sys
import tempfile
import threading
from pathlib import Path

from .store import Problem


BROWSERS = ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")


def browser_executable(choice="auto"):
    if choice != "auto" and choice not in BROWSERS:
        raise Problem("Unsupported desktop browser")
    for name in BROWSERS if choice == "auto" else (choice,):
        executable = shutil.which(name)
        if executable:
            return executable
    raise Problem("Desktop mode requires Chromium or Google Chrome. Install one from a trusted Linux source, or use 'serve' and open the loopback address yourself.")


def browser_arguments(executable, port, profile):
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise Problem("Invalid desktop loopback port")
    return [executable, "--user-data-dir=" + str(profile), "--no-first-run",
            "--no-default-browser-check", "--disable-background-networking",
            "--disable-component-update", "--disable-sync", "--disable-extensions",
            "--no-proxy-server", "--app=http://127.0.0.1:" + str(port)]


def run(app, data_root, choice="auto"):
    """Keep this server and its private app window in the same lifecycle.

    A fresh profile prevents Chromium forwarding the request to another process,
    making process exit a useful application-window lifecycle signal. Chromium's
    normal sandbox remains enabled. No shell or file-derived command is used.
    """
    executable = browser_executable(choice)
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise Problem("Desktop mode requires a Linux graphical session (DISPLAY or WAYLAND_DISPLAY). Use 'serve' for a headless machine.")
    with tempfile.TemporaryDirectory(prefix=".desktop-", dir=data_root) as profile:
        process = None
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        try:
            # Arguments and executable come only from this module and fixed choices.
            process = subprocess.Popen(browser_arguments(executable, app.server_port, profile))  # nosec B603
            status = process.wait()
            if status:
                raise Problem("The application window could not start or exited with an error. Check the Linux graphical session and Chromium installation; browser sandboxing was not disabled.")
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            app.shutdown()
            thread.join(timeout=15)


def _safe_text(value):
    text = str(value)
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise Problem("Desktop entry paths must not contain control characters")
    return text


def _exec_argument(value):
    text = _safe_text(value).replace("%", "%%")
    # Desktop Entry Exec quoting is separate from shell quoting; no shell runs.
    text = "".join("\\" + char if char in '\\"`$' else char for char in text)
    # The entry parser unescapes backslashes before parsing Exec quoting.
    return '"' + text.replace("\\", "\\\\") + '"'


def _entry_value(value):
    return _safe_text(value).replace("\\", "\\\\")


def desktop_entry(data, port=8080, browser="auto"):
    if browser != "auto" and browser not in BROWSERS:
        raise Problem("Unsupported desktop browser")
    if not 0 <= port <= 65535:
        raise Problem("Invalid desktop loopback port")
    data = Path(data).expanduser().absolute()
    command = [sys.executable, "-m", "cyber_platform", "desktop", "--data", str(data),
               "--port", str(port), "--browser", browser]
    return "\n".join([
        "[Desktop Entry]", "Type=Application", "Name=واس — منصة البحث السيبراني",
        "Comment=Private local cyber research application", "Icon=applications-science",
        "Exec=" + " ".join(_exec_argument(item) for item in command),
        "Path=" + _entry_value(Path(__file__).absolute().parent.parent),
        "Terminal=false", "Categories=Education;Development;", "StartupNotify=false", "",
    ])


def install_entry(data, applications_dir=None, port=8080, browser="auto", replace=False):
    """Install one entry only on an explicit owner CLI request, without root."""
    if applications_dir is None:
        xdg = os.environ.get("XDG_DATA_HOME", "")
        base = Path(xdg) if xdg and Path(xdg).is_absolute() else Path.home() / ".local/share"
        applications_dir = base / "applications"
    target_dir = Path(applications_dir).expanduser().absolute()
    contents = desktop_entry(data, port, browser)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "was-platform.desktop"
    if target.is_symlink():
        raise Problem("Refusing to replace a symlink desktop entry")
    if not replace:
        # Exclusive creation prevents accidental overwrite on repeat installs.
        with target.open("x", encoding="utf-8") as stream:
            stream.write(contents)
    else:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", prefix=".was-desktop-", dir=target_dir, delete=False) as stream:
            temporary = Path(stream.name)
            try:
                stream.write(contents)
                stream.flush()
                os.fsync(stream.fileno())
            except BaseException:
                temporary.unlink(missing_ok=True)
                raise
        try:
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    target.chmod(0o600)
    return target
