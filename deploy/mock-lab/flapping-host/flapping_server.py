"""Simulates a time-of-day unstable host toggling ports 8081/8082 with an HTTP control port 9099."""

import asyncio
import json
import os


class FlappingState:
    def __init__(self) -> None:
        self.active = True
        self.servers: list[asyncio.AbstractServer] = []


async def handle_service_port(
    port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        await asyncio.wait_for(reader.read(512), timeout=1.0)
        body = f"flapping-service-{port}".encode("utf-8")
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("utf-8")
            + body
        )
        writer.write(resp)
        await writer.drain()
    except asyncio.TimeoutError:
        pass
    finally:
        writer.close()


async def start_flapping_ports(state: FlappingState) -> None:
    if state.servers:
        return
    for port in (8081, 8082):
        srv = await asyncio.start_server(
            lambda r, w, p=port: handle_service_port(p, r, w),
            "0.0.0.0",
            port,
        )
        state.servers.append(srv)


async def stop_flapping_ports(state: FlappingState) -> None:
    for srv in state.servers:
        srv.close()
        await srv.wait_closed()
    state.servers.clear()


async def handle_control(
    state: FlappingState, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    try:
        raw = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        first_line = raw.decode("utf-8", errors="ignore").splitlines()[0] if raw else ""
        if "POST /toggle" in first_line:
            state.active = not state.active
            if state.active:
                await start_flapping_ports(state)
            else:
                await stop_flapping_ports(state)
        payload = json.dumps({"active": state.active, "ports": [8081, 8082] if state.active else []}).encode(
            "utf-8"
        )
        resp = (
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode("utf-8")
            + payload
        )
        writer.write(resp)
        await writer.drain()
    finally:
        writer.close()


async def auto_toggle_loop(state: FlappingState, interval_sec: int) -> None:
    while True:
        await asyncio.sleep(interval_sec)
        state.active = not state.active
        if state.active:
            await start_flapping_ports(state)
        else:
            await stop_flapping_ports(state)


async def main() -> None:
    interval = int(os.environ.get("FLAP_INTERVAL_SECONDS", "60"))
    state = FlappingState()
    await start_flapping_ports(state)
    ctrl = await asyncio.start_server(
        lambda r, w: handle_control(state, r, w), "0.0.0.0", 9099
    )
    print(f"mock-flapping-host listening (control :9099, interval {interval}s)", flush=True)
    asyncio.create_task(auto_toggle_loop(state, interval))
    async with ctrl:
        await ctrl.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
