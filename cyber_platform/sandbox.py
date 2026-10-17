"""Linux-only Python workshop: namespace isolation is mandatory, no fallback."""
import os
import resource
import signal
import subprocess
import tempfile
from pathlib import Path
from .store import Problem


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (192 * 1024 * 1024, 192 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))


def command(input_dir):
    args = ["/usr/bin/bwrap", "--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL", "--clearenv"]
    for path in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(path).exists():
            args += ["--ro-bind", path, path]
    return args + ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--ro-bind", str(input_dir), "/work",
                   "--chdir", "/work", "--setenv", "PATH", "/usr/bin:/bin", "/usr/bin/python3", "-I", "-S", "/work/main.py"]


def run(code):
    if not isinstance(code, str) or not 1 <= len(code.encode()) <= 16000:
        raise Problem("حد كود الورشة 16 KB")
    if not Path("/usr/bin/bwrap").is_file():
        raise Problem("Bubblewrap غير مثبت؛ التشغيل غير المعزول ممنوع", 503)
    with tempfile.TemporaryDirectory(prefix="was-workshop-") as tmp:
        base = Path(tmp)
        source = base / "input"
        source.mkdir()
        (source / "main.py").write_text(code)
        with (base / "stdout").open("w+b") as out, (base / "stderr").open("w+b") as err:
            process = subprocess.Popen(command(source), stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       env={"PATH": "/usr/bin:/bin"}, start_new_session=True, preexec_fn=limits)
            timed_out = False
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                timed_out = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            out.seek(0)
            err.seek(0)
            stdout, stderr = out.read(65536).decode(errors="replace"), err.read(65536).decode(errors="replace")
        if "bwrap:" in stderr:
            raise Problem("عزل Linux غير متاح في المضيف؛ لم يُشغّل الكود", 503)
        return {"status": "succeeded" if process.returncode == 0 else "failed", "exit_code": process.returncode,
                "stdout": stdout, "stderr": stderr, "timed_out": timed_out,
                "limits": {"memory_mib": 192, "cpu_seconds": 3, "wall_seconds": 10, "network": False},
                "limitations": "أدوات النظام العامة مقروءة؛ لا بيانات المالك أو شبكة المضيف. عزل namespaces ليس آلة افتراضية."}
