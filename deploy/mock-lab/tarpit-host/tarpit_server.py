"""Simulates a firewall/tarpit opening >200 TCP ports (10001..10220) to verify Tarpit Guard."""

import asyncio
import os


async def handle_tarpit_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await asyncio.sleep(0.05)
    finally:
        writer.close()


async def main() -> None:
    start_port = int(os.environ.get("TARPIT_START_PORT", "10001"))
    port_count = int(os.environ.get("TARPIT_PORT_COUNT", "220"))
    servers = []
    for port in range(start_port, start_port + port_count):
        srv = await asyncio.start_server(handle_tarpit_conn, "0.0.0.0", port)
        servers.append(srv)

    print(
        f"mock-tarpit-host listening on {port_count} ports ({start_port}..{start_port + port_count - 1})",
        flush=True,
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
