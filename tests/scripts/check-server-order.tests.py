"""Run the platform's checker against a deterministic delayed-list fixture."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
UNIX = os.name != 'nt'
CHECKER = Path(os.environ.get('MCP_WRIT_CHECK_SERVER_SCRIPT',
                             ROOT / ('scripts/check-server.sh' if UNIX else 'scripts/check-server.ps1')))
SHELL = os.environ.get('MCP_WRIT_TEST_POWERSHELL', 'pwsh')
NODE = shutil.which('node')
assert NODE, 'node is required'

scenarios = ('v25', 'v26', 'list-error') + (('nonzero-exit',) if UNIX else ())
for scenario in scenarios:
    with tempfile.TemporaryDirectory(prefix='check-server-order-') as temporary:
        work = Path(temporary)
        shutil.copyfile(ROOT / 'tests/fixtures/mcp_servers/check_server_order.cjs', work / 'run')
        trace = work / 'trace.jsonl'
        env = dict(os.environ, MCP_WRIT_ORDER_SCENARIO=scenario, MCP_WRIT_ORDER_TRACE=str(trace))
        if UNIX:
            command = ['sh', str(CHECKER), '--policy', 'unused.kdl',
                       '--audit-log', str(work / 'audit.jsonl'), '--call',
                       '{"name":"read_file","arguments":{}}', '--mcp-writ', NODE, '--', 'unused-server']
        else:
            command = [SHELL, '-NoProfile', '-File', str(CHECKER), '-Policy', 'unused.kdl',
             '-AuditLog', str(work / 'audit.jsonl'), '-Call', '{"name":"read_file","arguments":{}}',
             '-McpWrit', NODE, 'unused-server']
        completed = subprocess.run(
            command,
            cwd=work, env=env, capture_output=True, encoding='utf-8', errors='replace', timeout=60,
        )
        output = completed.stdout + completed.stderr
        assert trace.is_file(), (
            f'{scenario}: server produced no trace\n{output}')
        events = [json.loads(line) for line in trace.read_text(encoding='utf-8').splitlines()]
        calls = [event for event in events if event['event'] == 'tools/call']
        if scenario == 'nonzero-exit':
            assert completed.returncode != 0, output
            assert len(calls) == 1, events
            assert 'check-server: PASS' not in output, output
            print('PASS: nonzero child exit cannot be reported as success')
            continue
        if scenario == 'list-error':
            assert completed.returncode != 0, output
            assert 'tools/list' in (event['event'] for event in events), events
            assert 'carries "error"' in output, output
            assert not calls, 'tools/call must not follow an unsuccessful tools/list'
        else:
            assert completed.returncode == 0, output
            assert len(calls) == 1, events
            session = [event['event'] for event in events if event['pid'] == calls[0]['pid']]
            assert session.index('list-response') < session.index('tools/call'), session
            expected_generation = '2026-07-28' if scenario == 'v26' else '2025-11-25'
            assert f'negotiated generation: {expected_generation}' in output, output
            if scenario == 'v26':
                assert session[0] == 'server/discover' and 'initialize' not in session, session
                for event in events:
                    if event['event'] in ('server/discover', 'tools/list', 'tools/call'):
                        assert event['params']['_meta']['io.modelcontextprotocol/protocolVersion'] == expected_generation, event
            else:
                assert session[:2] == ['initialize', 'notifications/initialized'], session
            assert 'check-server: PASS' in completed.stdout, completed.stdout
        print(f'PASS: {scenario} request ordering and verdict')
