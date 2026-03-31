import os
import sys
from pathlib import Path


def get_int_env(name: str, default: int) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        raise SystemExit(f"{name} 必须是整数，当前值: {raw}")


def main() -> int:
    port_start = get_int_env("WARP_PORT_START", 12001)
    port_end = get_int_env("WARP_PORT_END", 12005)
    front_port = get_int_env("WARP_FRONT_PORT", 1080)

    if port_start <= 0 or port_end <= 0 or front_port <= 0:
        raise SystemExit("端口必须为正整数")
    if port_end < port_start:
        raise SystemExit("WARP_PORT_END 不能小于 WARP_PORT_START")

    ports = list(range(port_start, port_end + 1))
    if not ports:
        raise SystemExit("端口范围不能为空")

    services_lines = []
    backend_lines = []

    for port in ports:
        name = f"microwarp-{port}"
        services_lines.append(
            f"  {name}:\n"
            f"    image: ghcr.io/ccbkkb/microwarp:latest\n"
            f"    container_name: {name}\n"
            f"    restart: unless-stopped\n"
            f"    ports:\n"
            f"      - \"{port}:1080\"\n"
            f"    cap_add:\n"
            f"      - NET_ADMIN\n"
            f"      - SYS_MODULE\n"
            f"    sysctls:\n"
            f"      - net.ipv4.conf.all.src_valid_mark=1\n"
        )
        backend_lines.append(f"    server {name} {name}:1080 check")

    compose_path = Path("docker-compose.microwarp.generated.yml")
    haproxy_path = Path("haproxy.cfg")

    compose_content = (
        "# 由 scripts/generate_microwarp_compose.py 自动生成\n"
        "version: '3.8'\n\n"
        "services:\n"
        + "".join(services_lines)
        + "\n"
        "  microwarp-lb:\n"
        "    image: haproxy:2.9-alpine\n"
        "    container_name: microwarp-lb\n"
        "    restart: unless-stopped\n"
        "    ports:\n"
        f"      - \"{front_port}:1080\"\n"
        "    volumes:\n"
        "      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro\n"
        "    depends_on:\n"
        + "".join([f"      - microwarp-{port}\n" for port in ports])
    )

    haproxy_content = (
        "# 由 scripts/generate_microwarp_compose.py 自动生成\n"
        "global\n"
        "    log stdout format raw local0\n"
        "    maxconn 2048\n"
        "\n"
        "defaults\n"
        "    mode tcp\n"
        "    timeout connect 5s\n"
        "    timeout client  1m\n"
        "    timeout server  1m\n"
        "    option tcplog\n"
        "\n"
        "frontend socks5_in\n"
        "    bind *:1080\n"
        "    default_backend microwarp_pool\n"
        "\n"
        "backend microwarp_pool\n"
        "    balance roundrobin\n"
        + "\n".join(backend_lines)
        + "\n"
    )

    compose_path.write_text(compose_content, encoding="utf-8")
    haproxy_path.write_text(haproxy_content, encoding="utf-8")

    print(
        "生成完成:\n"
        f"- {compose_path} (端口范围 {port_start}-{port_end})\n"
        f"- {haproxy_path} (统一入口端口 {front_port})"
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
