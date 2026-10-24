"""Actual Wasm execution and isolation, using synthetic modules only."""
import multiprocessing
import time
import unittest
from unittest.mock import Mock, patch

import wasmtime
from cyber_platform import plugin_wasm as runtime


def length_module(divisor=10):
    """Variable-input fixture shared by package and browser acceptance tests."""
    return bytes(wasmtime.wat2wasm('''(module
      (memory (export "memory") 2)
      (data (i32.const 0) "{\\"length_mod10\\":0}")
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "analyze") (param i32 i32) (result i64)
        (i32.store8 (i32.const 16)
          (i32.add (i32.const 48)
            (i32.rem_u (local.get 1) (i32.const ''' + str(divisor) + '''))))
        (i64.const 18)))'''))


def result_module(raw=b'{}', *, pointer=0, length=None, body=None, pages=2):
    escaped = ''.join('\\%02x' % b for b in raw)
    packed = pointer * (2**32) + (len(raw) if length is None else length)
    return bytes(wasmtime.wat2wasm('''(module
      (memory (export "memory") '''+str(pages)+''')
      (data (i32.const 0) "'''+escaped+'''")
      (func (export "alloc") (param i32) (result i32) (i32.const 1024))
      (func (export "analyze") (param i32 i32) (result i64)
        '''+(body or '(i64.const '+str(packed)+')')+'''))'''))


def silent_child(connection, module, inputs):
    # Trusted test worker only: verify the independent parent wall watchdog.
    time.sleep(10)


class WasmRuntimeTests(unittest.TestCase):
    def fails(self, module, input_data=b'private synthetic input'):
        with self.assertRaisesRegex(ValueError, '^'+runtime.ERROR+'$'):
            runtime.execute(module, input_data)

    def test_variable_input_runs_actual_module_in_fresh_worker(self):
        module = length_module()
        self.assertEqual(runtime.execute(module, b'abcd'), {'length_mod10': 4})
        self.assertEqual(runtime.execute(module, b'12345678901'), {'length_mod10': 1})
        self.assertEqual(runtime.execute(module, b''), {'length_mod10': 0})

    def test_replacement_module_changes_behavior(self):
        self.assertEqual(runtime.execute(length_module(), b'abcdef'), {'length_mod10': 6})
        self.assertEqual(runtime.execute(length_module(5), b'abcdef'), {'length_mod10': 1})

    def test_batch_compiles_once_and_returns_one_result_per_input(self):
        values=[b'x'*i for i in range(10)]
        self.assertEqual(runtime.execute_batch(length_module(),values),[{'length_mod10':i} for i in range(10)])

    def test_batch_uses_fresh_guest_state_for_each_fixture(self):
        # A global counter must be1 each time, not1,2,3 from a reused instance.
        module=bytes(wasmtime.wat2wasm('''(module
          (global $counter (mut i32) (i32.const 0))
          (memory (export "memory") 2) (data (i32.const 0) "[0]")
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "analyze") (param i32 i32) (result i64)
            (global.set $counter (i32.add (global.get $counter) (i32.const 1)))
            (i32.store8 (i32.const 1) (i32.add (global.get $counter) (i32.const 48)))
            (i64.const 3)))'''))
        self.assertEqual(runtime.execute_batch(module,[b'a',b'b',b'c']),[[1],[1],[1]])

    def test_batch_shape_and_count_are_checked_before_worker(self):
        with patch.object(runtime.multiprocessing,'get_context') as context:
            for values in ([],[b'']*11,(b'a',),[b'valid','invalid']):
                with self.subTest(values=values):
                    with self.assertRaisesRegex(ValueError,'^'+runtime.ERROR+'$'):
                        runtime.execute_batch(length_module(),values)
            context.assert_not_called()

    def test_input_is_only_bytes_and_limits_checked_before_worker(self):
        with patch.object(runtime.multiprocessing, 'get_context') as context:
            for module, data in ((b'', b''), ('module', b''), (b'\0asm\x01\0\0\0'+b'x'*runtime.LIMITS['module_bytes'], b''),
                                 (length_module(), 'input'), (length_module(), b'x' * (runtime.LIMITS['input_bytes']+1))):
                with self.subTest(module=type(module), data=type(data)):
                    self.fails(module, data)
            context.assert_not_called()

    def test_maximum_input_is_permitted_when_guest_has_space(self):
        self.assertEqual(runtime.execute(length_module(), b'x'*runtime.LIMITS['input_bytes']), {'length_mod10': 6})

    def test_invalid_binary_fails_without_compiler_details(self):
        self.fails(b'\0asm\x01\0\0\0not a valid section')

    def test_every_host_import_is_rejected_including_files_network_and_environment(self):
        for name in ('path_open', 'sock_accept', 'environ_get', 'random_get', 'clock_time_get'):
            source='''(module (import "wasi_snapshot_preview1" "'''+name+'''" (func))
              (memory (export "memory") 2)
              (func (export "alloc") (param i32) (result i32) (i32.const 1024))
              (func (export "analyze") (param i32 i32) (result i64) (i64.const 0)))'''
            with self.subTest(name=name):
                self.fails(bytes(wasmtime.wat2wasm(source)))

    def test_non_wasi_host_import_cannot_gain_capabilities(self):
        self.fails(bytes(wasmtime.wat2wasm('''(module (import "env" "read_owner_secret" (func))
          (memory (export "memory") 2)
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "analyze") (param i32 i32) (result i64) (i64.const 0)))''')))

    def test_export_contract_requires_exact_names_and_types(self):
        sources = [
            '(module)',
            '(module (memory (export "memory") 2) (func (export "alloc") (param i64) (result i32) (i32.const 0)) (func (export "analyze") (param i32 i32) (result i64) (i64.const 0)))',
            '(module (memory (export "memory") 2) (func (export "alloc") (param i32) (result i32) (i32.const 0)) (func (export "analyze") (param i32 i32) (result i32) (i32.const 0)))',
            '(module (memory (export "memory") 2) (func (export "alloc") (param i32) (result i32) (i32.const 0)) (func (export "analyze") (param i32 i32) (result i64) (i64.const 0)) (func (export "extra")))',
        ]
        for source in sources:
            with self.subTest(source=source):self.fails(bytes(wasmtime.wat2wasm(source)))

    def test_infinite_loop_terminates_at_fuel_limit(self):
        self.fails(result_module(body='(loop $forever (br $forever)) (i64.const 0)'))

    def test_start_function_loop_is_also_fuel_limited(self):
        source='''(module (memory (export "memory") 2)
          (func $start (loop $forever (br $forever))) (start $start)
          (func (export "alloc") (param i32) (result i32) (i32.const 1024))
          (func (export "analyze") (param i32 i32) (result i64) (i64.const 0)))'''
        self.fails(bytes(wasmtime.wat2wasm(source)))

    def test_initial_memory_over_budget_is_rejected(self):
        self.fails(result_module(pages=runtime.LIMITS['memory_bytes']//65536+1))

    def test_memory_growth_above_budget_cannot_succeed(self):
        # Return success iff an attempt to grow by 513 pages is rejected (-1).
        body='''(i32.const 0) (i32.const 123) i32.store8
          (i32.const 513) memory.grow (i32.const -1) i32.ne
          if unreachable end (i64.const 2)'''
        self.assertEqual(runtime.execute(result_module(b'{}', body=body), b''), {})

    def test_out_of_bounds_input_pointer_is_rejected(self):
        source='''(module (memory (export "memory") 1)
          (func (export "alloc") (param i32) (result i32) (i32.const -1))
          (func (export "analyze") (param i32 i32) (result i64) (i64.const 0)))'''
        self.fails(bytes(wasmtime.wat2wasm(source)))

    def test_out_of_bounds_and_oversized_output_is_rejected(self):
        for pointer, length in ((0xffffffff, 2), (131072, 1), (0, runtime.LIMITS['output_bytes']+1)):
            with self.subTest(pointer=pointer,length=length):self.fails(result_module(pointer=pointer,length=length))

    def test_output_requires_bounded_strict_json_object_or_array(self):
        for raw in (b'not JSON', b'null', b'42', b'"string"', b'{"x":NaN}', b'{"x":1,"x":2}', b'{"x":"\\ud800"}', b'\xff'):
            with self.subTest(raw=raw):self.fails(result_module(raw))
        self.assertEqual(runtime.execute(result_module(b'[1,{"valid":true}]'), b''), [1, {'valid':True}])

    def test_trap_and_native_details_do_not_leak_input_or_names(self):
        self.fails(result_module(body='unreachable (i64.const 0)'), b'very private source')

    def test_worker_is_joined_after_success_and_failure(self):
        before={p.pid for p in multiprocessing.active_children()}
        self.assertEqual(runtime.execute(result_module(), b''), {})
        self.fails(result_module(body='unreachable (i64.const 0)'))
        self.assertEqual({p.pid for p in multiprocessing.active_children()}, before)

    def test_wall_watchdog_kills_and_joins_a_nonresponsive_worker(self):
        before={p.pid for p in multiprocessing.active_children()}
        with patch.object(runtime,'_child',silent_child), patch.dict(runtime.LIMITS,wall_seconds=0.05):
            self.fails(length_module())
        self.assertEqual({p.pid for p in multiprocessing.active_children()},before)

    def test_worker_start_failure_is_constant_and_closes_connections(self):
        receiver,sender,process=Mock(),Mock(),Mock(pid=None)
        process.start.side_effect=OSError('private native path must not escape')
        context=Mock()
        context.Pipe.return_value=(receiver,sender)
        context.Process.return_value=process
        with patch.object(runtime.multiprocessing,'get_context',return_value=context):
            self.fails(length_module())
        receiver.close.assert_called_once()
        sender.close.assert_called_once()

    def test_fingerprint_binds_implementation_runtime_and_limits(self):
        first=runtime.fingerprint()
        self.assertEqual(first,runtime.fingerprint())
        self.assertEqual(len(first),64)
        with patch.dict(runtime.LIMITS, fuel=runtime.LIMITS['fuel']+1):
            self.assertNotEqual(first,runtime.fingerprint())
        with patch.object(runtime.importlib.metadata,'version',return_value='different-runtime'):
            self.assertNotEqual(first,runtime.fingerprint())

