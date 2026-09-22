"""
Banner Grabber Module - Extracted from CyberScan's port_scanner.py
Handles banner extraction and service fingerprinting for network reconnaissance.

NiteSentinel v1.2 Enterprise - Integrated Port Scanner
"""
import asyncio
import socket
from typing import Tuple


async def probe_for_banner(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    port: int,
    target: str
) -> str:
    """
    Send protocol-specific probes to elicit banners from services.
    
    Args:
        reader: AsyncIO stream reader
        writer: AsyncIO stream writer
        port: Target port number
        target: Target hostname/IP
        
    Returns:
        Banner string or empty string
    """
    try:
        if port in (80, 8080, 8000):
            # HTTP probe
            msg = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()
            writer.write(msg)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode(errors='ignore').strip()
        
        if port in (25, 587):
            # SMTP - wait for greeting then send EHLO
            try:
                initial = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                if initial:
                    return initial.decode(errors='ignore').strip()
            except asyncio.TimeoutError:
                pass
            
            writer.write(b"EHLO example.com\r\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode(errors='ignore').strip()

        if port == 21:
            # FTP usually sends banner on connect
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return data.decode(errors='ignore').strip()
            
    except Exception:
        pass
    
    return ""


async def scan_port_async(
    *args,
    target: str = "localhost",
    port: int = 80,
    timeout: float = 1.0,
    service_probe: bool = True,
    **kwargs
) -> Tuple[int, bool, str, str]:
    """
    Scan a single port asynchronously with banner grabbing.
    
    Args:
        target: Target hostname or IP
        port: Port number to scan
        timeout: Connection timeout in seconds
        service_probe: Whether to probe for service identification
        
    Returns:
        Tuple of (port, is_open, service, banner)
    """
    if len(args) >= 1:
        target = args[0]
    if len(args) >= 2:
        port = args[1]
    conn_fut = asyncio.open_connection(target, port)
    try:
        reader, writer = await asyncio.wait_for(conn_fut, timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False, "closed", ""

    # Port is open
    banner = ""
    service = "unknown"
    
    try:
        if service_probe:
            # Try to read initial banner first (some services send immediately like SSH, FTP, SMTP)
            try:
                initial_data = await asyncio.wait_for(reader.read(1024), timeout=0.5)
                if initial_data:
                    banner = initial_data.decode(errors='ignore').strip()
            except asyncio.TimeoutError:
                pass

            # If no banner, try to probe or handle specific ports
            if not banner:
                banner = await probe_for_banner(reader, writer, port, target)
            
            # If still no banner and port 443, try SSL
            if not banner and port == 443:
                service = "https"
                banner = "TLS/SSL Service"

    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    # Service detection based on banner and port
    from nitesentinels.scanners.service_detector import detect_service
    service = detect_service(port, banner)
    
    return port, True, service, banner
