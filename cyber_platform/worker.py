"""Resource-bounded execution of trusted analyzers; never execute uploaded code."""
import multiprocessing
import os
import resource
from . import tools


def _analyze(connection, tool, data):
    try:
        # This is a fresh spawned interpreter, not a fork of the threaded server.
        # Analyzers are trusted code and still share the OS identity; this is a
        # CPU/memory boundary, not a filesystem/network namespace sandbox.
        os.environ.clear()
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if tool == "knowledge-catalog":
            from .knowledge_files import parse
            result = parse(data)
        elif tool == "detection-acceptance":
            from .detection_acceptance import execute_batch
            result = execute_batch(data)
        else:
            result = tools.analyze(tool, data)
        connection.send({"ok": True, "result": result})
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, MemoryError, RecursionError) as exc:
        connection.send({"ok": False, "error": str(exc)[:300] or "Analyzer resource limit exceeded"})
    finally:
        connection.close()


def analyze(tool, data, timeout=10):
    if tool not in (*tools.REGISTRY, "knowledge-catalog", "detection-acceptance") or not isinstance(data, bytes) or len(data) > 4 * 1024 * 1024:
        raise ValueError("Invalid analyzer or input exceeds 4 MiB")
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_analyze, args=(sender, tool, data), daemon=True)
    try:
        process.start()
        sender.close()
        if not receiver.poll(timeout):
            raise ValueError("Analyzer exceeded its execution time limit")
        try:
            response = receiver.recv()
        except (EOFError, OSError):
            raise ValueError("Analyzer stopped at a resource limit or failed") from None
        if not response["ok"]:
            raise ValueError(response["error"])
        return response["result"]
    finally:
        sender.close()
        receiver.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join(timeout=2)
            process.close()
