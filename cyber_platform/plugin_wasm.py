"""Explicitly installed Wasm plugins: no imports, WASI or host capabilities.

This boundary is separate from trusted analyzers and the Python workshop. The
caller must verify the owner's publisher trust and the signed package before
using it. The only data supplied to guest code is the selected input byte string.
"""
import hashlib
import importlib.metadata
import json
import multiprocessing
import os
from pathlib import Path
import resource


ABI = "was.plugin-wasm/1"
LIMITS = {"module_bytes": 1024 * 1024, "input_bytes": 65536,
          "output_bytes": 65536, "memory_bytes": 32 * 1024 * 1024,
          "fuel": 2_000_000, "cpu_seconds": 3, "wall_seconds": 5,
          "worker_address_bytes": 1024 * 1024 * 1024, "batch_inputs": 10}
ERROR = "تعذر تشغيل الإضافة ضمن عقد العزل والموارد؛ لم تُعلن نتيجة ناجحة"


def fingerprint():
    """Bind persisted executions to the runtime, ABI and exact implementation."""
    definition = {"abi": ABI, "limits": LIMITS,
                  "wasmtime": importlib.metadata.version("wasmtime"),
                  "implementation": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    return hashlib.sha256(json.dumps(definition, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(ERROR)
        result[key] = value
    return result


def _constant(_):
    raise ValueError(ERROR)


def _result(raw):
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                            parse_constant=_constant)
        if not isinstance(result, (dict, list)):
            raise ValueError(ERROR)
        # Reject surrogate codepoints and retain a bounded serializable result.
        encoded = json.dumps(result, ensure_ascii=False, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
        if len(encoded) > LIMITS["output_bytes"]:
            raise ValueError(ERROR)
        return result
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ValueError(ERROR) from None


def _prepare(module_bytes):
    """Compile and check capabilities only inside the bounded child."""
    import wasmtime

    config = wasmtime.Config()
    config.consume_fuel = True
    config.parallel_compilation = False
    config.shared_memory = False
    config.wasm_memory64 = False
    config.wasm_multi_memory = False
    config.wasm_stack_switching = False
    config.max_wasm_stack = 256 * 1024
    # Avoid reserving the default multi-gigabyte Wasm32 address range. The
    # independent Store limiter enforces actual guest linear-memory growth.
    config.memory_reservation = 0
    config.memory_reservation_for_growth = 0
    config.memory_guard_size = 0
    config.memory_init_cow = False
    engine = wasmtime.Engine(config)
    module = wasmtime.Module(engine, module_bytes)
    if list(module.imports):
        raise ValueError(ERROR)
    exports = {item.name: item.type for item in module.exports}
    if set(exports) != {"memory", "alloc", "analyze"}:
        raise ValueError(ERROR)
    memory_type = exports["memory"]
    if not isinstance(memory_type, wasmtime.MemoryType) or memory_type.is_64 or memory_type.is_shared:
        raise ValueError(ERROR)
    if memory_type.limits.min * 65536 > LIMITS["memory_bytes"]:
        raise ValueError(ERROR)
    for name, params, results in (("alloc", ["i32"], ["i32"]),
                                  ("analyze", ["i32", "i32"], ["i64"])):
        kind = exports[name]
        if not isinstance(kind, wasmtime.FuncType) or [str(t) for t in kind.params] != params or [str(t) for t in kind.results] != results:
            raise ValueError(ERROR)
    return engine, module


def _run(prepared, input_bytes):
    """Each input receives a fresh Store/Instance, without shared guest state."""
    import wasmtime

    engine, module = prepared
    store = wasmtime.Store(engine)
    store.set_limits(memory_size=LIMITS["memory_bytes"], table_elements=1024,
                     instances=1, tables=1, memories=1)
    store.set_fuel(LIMITS["fuel"])
    # There is no Linker and no WasiConfig: nothing can resolve a host function.
    instance = wasmtime.Instance(store, module, [])
    items = instance.exports(store)
    memory = items["memory"]
    pointer = items["alloc"](store, len(input_bytes))
    if type(pointer) is not int or pointer < 0 or pointer + len(input_bytes) > memory.data_len(store):
        raise ValueError(ERROR)
    memory.write(store, input_bytes, pointer)
    packed = items["analyze"](store, pointer, len(input_bytes))
    pointer, length = (packed & 0xFFFFFFFFFFFFFFFF) >> 32, packed & 0xFFFFFFFF
    if length > LIMITS["output_bytes"] or pointer + length > memory.data_len(store):
        raise ValueError(ERROR)
    return _result(bytes(memory.read(store, pointer, pointer + length)))


def _child(connection, module_bytes, inputs):
    try:
        os.environ.clear()
        resource.setrlimit(resource.RLIMIT_CPU, (LIMITS["cpu_seconds"], LIMITS["cpu_seconds"]))
        resource.setrlimit(resource.RLIMIT_AS, (LIMITS["worker_address_bytes"], LIMITS["worker_address_bytes"]))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        prepared = _prepare(module_bytes)
        result = [_run(prepared, value) for value in inputs]
        connection.send({"ok": True, "result": result})
    except Exception:
        # Guest traps and compiler/parser errors must not reveal input values,
        # module names, native paths or worker exception details.
        try:
            connection.send({"ok": False})
        except (OSError, EOFError):
            pass
    finally:
        connection.close()


def execute_batch(module, inputs):
    """One compile and one aggregate process budget; independent guest states."""
    if type(module) is not bytes or not 8 <= len(module) <= LIMITS["module_bytes"] or not module.startswith(b"\0asm\x01\0\0\0"):
        raise ValueError(ERROR)
    if type(inputs) is not list or not 1 <= len(inputs) <= LIMITS["batch_inputs"] or any(type(value) is not bytes or len(value) > LIMITS["input_bytes"] for value in inputs):
        raise ValueError(ERROR)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_child, args=(sender, module, inputs), daemon=True)
    try:
        process.start()
        sender.close()
        if not receiver.poll(LIMITS["wall_seconds"]):
            raise ValueError(ERROR)
        try:
            response = receiver.recv()
        except (EOFError, OSError):
            raise ValueError(ERROR) from None
        if not isinstance(response, dict) or response.get("ok") is not True or set(response) != {"ok", "result"}:
            raise ValueError(ERROR)
        result = response["result"]
        if type(result) is not list or len(result) != len(inputs):
            raise ValueError(ERROR)
        # Independently validate each bounded output, not an unbounded envelope.
        return [_result(json.dumps(value, ensure_ascii=False, allow_nan=False,
                                   separators=(",", ":")).encode()) for value in result]
    except (OSError, RuntimeError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ValueError(ERROR) from None
    finally:
        sender.close()
        receiver.close()
        if process.pid is not None:
            if process.is_alive():
                process.kill()
            process.join(timeout=2)
            process.close()


def execute(module, input_data):
    """Execute a verified installed module with just the selected input bytes."""
    return execute_batch(module, [input_data])[0]
