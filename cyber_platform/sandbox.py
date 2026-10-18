"""Linux-only Python workshop: namespace isolation is mandatory, no fallback."""
import os
import signal
# Required fixed Bubblewrap launcher; no shell execution.
import subprocess  # nosec B404
import tempfile
from pathlib import Path
from .store import Problem


def command(input_dir):
    # A fixed prlimit wrapper avoids Python preexec_fn in the threaded server.
    args = ["/usr/bin/prlimit", "--cpu=3:3", "--as=201326592:201326592", "--fsize=1048576:1048576", "--nofile=32:32", "--core=0:0", "--nproc=64:64", "--",
            "/usr/bin/bwrap", "--die-with-parent", "--new-session", "--unshare-all", "--cap-drop", "ALL", "--clearenv"]
    for path in ("/usr", "/bin", "/lib", "/lib64"):
        if Path(path).exists():
            args += ["--ro-bind", path, path]
    # /tmp is a new private tmpfs inside the namespace, not a host temp path.
    return args + ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--ro-bind", str(input_dir), "/work",  # nosec B108
                   "--chdir", "/work", "--setenv", "PATH", "/usr/bin:/bin", "/usr/bin/python3", "-I", "-S", "/work/main.py"]


def run(code):
    if not isinstance(code, str) or not 1 <= len(code.encode()) <= 16000:
        raise Problem("حد كود الورشة 16 KB")
    if not Path("/usr/bin/bwrap").is_file():
        raise Problem("أداة عزل Bubblewrap غير مثبتة؛ التشغيل غير المعزول ممنوع", 503)
    if not Path("/usr/bin/prlimit").is_file():
        raise Problem("أداة حدود الموارد prlimit غير متاحة؛ لم يُشغّل العزل", 503)
    with tempfile.TemporaryDirectory(prefix="was-workshop-") as tmp:
        base = Path(tmp)
        source = base / "input"
        source.mkdir()
        (source / "main.py").write_text(code)
        with (base / "stdout").open("w+b") as out, (base / "stderr").open("w+b") as err:
            # Fixed executable/argv; code is a mounted file, never shell arguments.
            process = subprocess.Popen(command(source), stdin=subprocess.DEVNULL, stdout=out, stderr=err,  # nosec B603
                                       env={"PATH": "/usr/bin:/bin"}, start_new_session=True)
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
        if "bwrap:" in stderr or "prlimit:" in stderr:
            raise Problem("عزل Linux غير متاح في المضيف؛ لم يُشغّل الكود", 503)
        return {"status": "succeeded" if process.returncode == 0 else "failed", "exit_code": process.returncode,
                "stdout": stdout, "stderr": stderr, "timed_out": timed_out,
                "limits": {"memory_mib": 192, "cpu_seconds": 3, "wall_seconds": 10, "network": False},
                "limitations": "أدوات النظام العامة مقروءة؛ لا بيانات المالك أو شبكة المضيف. عزل namespaces ليس آلة افتراضية."}
