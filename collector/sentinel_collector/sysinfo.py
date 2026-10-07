import platform
import socket


def os_name() -> str | None:
    return {"Linux": "LINUX", "Windows": "WINDOWS"}.get(platform.system())


def primary_ip() -> str | None:
    """The address the OS would use to reach the outside. A UDP connect() sends no packet."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # TEST-NET-1: never routed
            return s.getsockname()[0]
    except OSError:
        return None
