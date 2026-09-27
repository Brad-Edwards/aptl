"""Exercise protocol admission and revocation through real subprocess pipes."""

import asyncio
import json
import os
import sys

from aptl.workbench.profiles import profile_for
from aptl.workbench.relay import RelayLaunch, RelayPolling, relay_mcp

SERVER = r"""
import json,signal,sys
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
for line in sys.stdin:
    request=json.loads(line)
    if 'id' not in request: continue
    method=request['method']
    if method=='initialize': result={'protocolVersion':'2024-11-05','capabilities':{'tools':{}},'serverInfo':{'name':'fixture','version':'1'}}
    elif method=='tools/list': result={'tools':[{'name':n,'inputSchema':{'type':'object'}} for n in TOOLS]}
    else: result={'content':[{'type':'text','text':'executed'}]}
    print(json.dumps({'jsonrpc':'2.0','id':request['id'],'result':result}),flush=True)
"""


def test_real_pipe_relay_admits_inventory_denies_blue_and_revokes_live_session(
    tmp_path,
):
    async def exercise():
        revoked = False
        authorizations = 0
        cleanups = []
        tasks = set()
        selected = profile_for("red").servers[0]

        def authorize():
            nonlocal authorizations
            authorizations += 1
            if revoked:
                raise ValueError("revoked")

        def check_revocation():
            if revoked:
                raise ValueError("revoked")

        async def connected(reader, writer):
            task = asyncio.current_task()
            tasks.add(task)
            try:
                await relay_mcp(
                    reader,
                    writer,
                    launch=RelayLaunch(
                        argv=(
                            sys.executable,
                            "-c",
                            "TOOLS=" + repr(selected.tool_names) + "\n" + SERVER,
                        ),
                        cwd=tmp_path,
                        env={"PATH": os.defpath},
                        server=selected,
                    ),
                    authorize=authorize,
                    cleanup_observer=cleanups.append,
                    check_revocation=check_revocation,
                    polling=RelayPolling(
                        revocation_seconds=0.01,
                        authorization_seconds=1,
                    ),
                )
            finally:
                tasks.remove(task)
                writer.close()

        listener = await asyncio.start_server(connected, "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", listener.sockets[0].getsockname()[1]
        )

        async def request(method, identifier, params):
            writer.write(
                (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": identifier,
                            "method": method,
                            "params": params,
                        }
                    )
                    + "\n"
                ).encode()
            )
            await writer.drain()
            return json.loads(await asyncio.wait_for(reader.readline(), 5))

        response = await request(
            "initialize",
            1,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        )
        assert "result" in response
        response = await request(
            "tools/call", 2, {"name": "kali_info", "arguments": {}}
        )
        assert response["result"]["content"][0]["text"] == "executed"
        assert authorizations == 3
        revoked = True
        assert await asyncio.wait_for(reader.read(), 5) == b""
        writer.close()
        await writer.wait_closed()
        listener.close()
        await listener.wait_closed()
        if tasks:
            await asyncio.gather(*tasks)
        assert cleanups == [True]

    asyncio.run(exercise())
