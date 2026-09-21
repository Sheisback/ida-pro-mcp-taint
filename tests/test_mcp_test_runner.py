"""HTTP test harness lifecycle and module-lookup proxy regression tests."""

import asyncio
import importlib.util
import sys
import threading
import types
from pathlib import Path

import pytest

from test_mainthread_pump import MainThreadPump


@pytest.fixture
def harness_module(monkeypatch):
    root = Path(__file__).resolve().parents[1] / 'src/ida_pro_mcp/ida_mcp'
    server = types.SimpleNamespace(tools=types.SimpleNamespace(methods={}))
    for name in ('_runner_test', '_runner_test.tests'):
        package = types.ModuleType(name)
        package.__path__ = []
        monkeypatch.setitem(sys.modules, name, package)
    monkeypatch.setitem(sys.modules, '_runner_test.rpc', types.SimpleNamespace(MCP_SERVER=server))
    spec = importlib.util.spec_from_file_location('_runner_test.tests.mcp_mode', root/'tests/mcp_mode.py')
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('failure', [None, ValueError('failed')])
def test_harness_pumps_on_owner_and_propagates_results(harness_module, failure):
    pump = MainThreadPump()
    harness = harness_module._AsyncHarness(pump)
    harness.start()
    thread = harness.thread
    owner = threading.get_ident()
    def sdk_call():
        assert threading.get_ident() == owner
        if failure:
            raise failure
        return {'failed': 2}  # Failed test result must not become success.
    async def request():
        return await asyncio.to_thread(pump.submit, sdk_call, timeout=1)
    try:
        if failure:
            with pytest.raises(ValueError, match='failed'):
                harness.run(request(), timeout=1)
        else:
            assert harness.run(request(), timeout=1) == {'failed': 2}
        assert not pump.active and pump.busy_status() is None
    finally:
        harness.stop()
    assert not thread.is_alive()


def test_proxy_patches_module_lookup_not_imported_alias(harness_module, monkeypatch):
    module = types.ModuleType('_runner_fake_api')
    def original():
        return 'direct'
    original.__module__ = module.__name__
    module.example = original
    monkeypatch.setitem(sys.modules, module.__name__, module)
    harness_module.MCP_SERVER.tools.methods = {'example': original}
    mode = harness_module._McpMode()
    mode.driver_thread_id = threading.get_ident()
    calls = []
    async def call_tool(name, arguments):
        calls.append((name, arguments))
        return types.SimpleNamespace(isError=False, structuredContent={'result': 'transport'})
    mode.session = types.SimpleNamespace(call_tool=call_tool)
    mode.harness = types.SimpleNamespace(run=asyncio.run)
    alias = module.example
    mode._patch_tools()
    try:
        assert module.example() == 'transport'
        assert alias() == 'direct'
        assert calls == [('example', {})]
    finally:
        mode._unpatch_tools()
    assert module.example is original


def test_failed_enable_cleans_up_and_does_not_publish_instance(harness_module, monkeypatch):
    calls = []
    def fail(self):
        calls.append('enable')
        raise RuntimeError('startup')
    monkeypatch.setattr(harness_module._McpMode, 'enable', fail)
    monkeypatch.setattr(harness_module._McpMode, 'disable', lambda self: calls.append('disable'))
    with pytest.raises(RuntimeError, match='startup'):
        harness_module.enable_mcp_mode()
    assert calls == ['enable', 'disable']
    assert harness_module._instance is None


def test_timeout_cancels_request_and_stops_thread(harness_module):
    pump = MainThreadPump()
    harness = harness_module._AsyncHarness(pump)
    cancelled = threading.Event()
    harness.start()
    thread = harness.thread
    async def request():
        try:
            await asyncio.sleep(60)
        finally:
            cancelled.set()
    try:
        with pytest.raises(TimeoutError):
            harness.run(request(), timeout=.02)
    finally:
        harness.stop()
    assert cancelled.is_set()
    assert not thread.is_alive()
    assert harness.loop.is_closed()
    assert not pump.active


def test_keyboard_interrupt_still_stops_server_and_loop(harness_module, monkeypatch):
    mode = harness_module._McpMode()
    cleaned = []
    def interrupt(coro):
        coro.close()
        raise KeyboardInterrupt()
    mode.harness = types.SimpleNamespace(run=interrupt, stop=lambda: cleaned.append('loop'))
    monkeypatch.setattr(harness_module.MCP_SERVER, 'stop', lambda: cleaned.append('server'), raising=False)
    harness_module._instance = mode
    with pytest.raises(KeyboardInterrupt):
        harness_module.disable_mcp_mode()
    assert cleaned == ['server', 'loop']
    assert harness_module._instance is None
