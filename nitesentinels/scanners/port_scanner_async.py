"""
Async Port Scanner Module - Extracted from CyberScan
High-performance asynchronous port scanning engine with banner grabbing.

NiteSentinel v1.2 Enterprise - Integrated Port Scanner
"""
import asyncio
import queue
import socket
import sys
import threading
from typing import AsyncGenerator, List, Tuple, Union

from nitesentinels.scanners.banner_grabber import scan_port_async
from nitesentinels.core.utils import logger


# Improve Windows compatibility for asyncio
if sys.platform == 'win32':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def parse_ports(port_str: Union[str, List[int]]) -> List[int]:
    """
    Parse port specification string or list into list of port numbers.
    Supports ranges (e.g., "1-1024") and comma-separated values (e.g., "80,443,8080") or list of ints.
    
    Args:
        port_str: Port specification string or list of integers
        
    Returns:
        Sorted list of unique port numbers
    """
    if isinstance(port_str, (list, tuple, set)):
        return sorted(p for p in port_str if isinstance(p, int) and 0 < p < 65536)
    
    ports = set()
    for part in str(port_str).split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a, b = map(int, part.split('-', 1))
                ports.update(range(a, b + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return sorted(p for p in ports if 0 < p < 65536)


async def scan_generator(
    target: str,
    ports: List[int],
    concurrency: int = 100,
    timeout: float = 1.0,
    service_probe: bool = True
) -> AsyncGenerator[Tuple[int, bool, str, str], None]:
    """
    Async generator that yields scan results as they complete.
    
    Args:
        target: Target hostname or IP
        ports: List of port numbers to scan
        concurrency: Maximum concurrent connections
        timeout: Connection timeout in seconds
        service_probe: Whether to probe for service identification
        
    Yields:
        Tuples of (port, is_open, service, banner)
    """
    semaphore = asyncio.Semaphore(concurrency)

    async def sem_scan(p):
        async with semaphore:
            return await scan_port_async(target, p, timeout, service_probe)

    # Create all tasks
    tasks = [asyncio.create_task(sem_scan(p)) for p in ports]
    
    # As each task completes, yield it
    for future in asyncio.as_completed(tasks):
        result = await future
        yield result


def scan_generator_sync(
    target: str,
    ports: str = '1-1024',
    concurrency: int = 100,
    timeout: float = 1.0,
    service_probe: bool = True
):
    """
    Synchronous generator for Flask or other sync frameworks to consume results.
    
    Args:
        target: Target hostname or IP
        ports: Port specification string
        concurrency: Maximum concurrent connections
        timeout: Connection timeout in seconds
        service_probe: Whether to probe for service identification
        
    Yields:
        Tuples of (port, is_open, service, banner)
    """
    # Resolve target first
    try:
        resolved = socket.gethostbyname(target)
    except Exception as e:
        logger.error(f"Failed to resolve {target}: {e}")
        return

    port_list = parse_ports(ports)
    if not port_list:
        logger.warning(f"No valid ports parsed from: {ports}")
        return

    q = queue.Queue()
    
    # Sentinel for end of stream
    SENTINEL = object()

    def runner():
        async def async_wrapper():
            async for item in scan_generator(resolved, port_list, concurrency, timeout, service_probe):
                q.put(item)
        
        try:
            asyncio.run(async_wrapper())
        except Exception as e:
            logger.error(f"Error in scan runner: {e}")
        finally:
            q.put(SENTINEL)

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    
    while True:
        item = q.get()
        if item is SENTINEL:
            break
        yield item


class _AwaitableList(list):
    def __await__(self):
        async def _resolve():
            return self
        return _resolve().__await__()


def scan_target(
    target: str,
    ports: str = "1-1024",
    concurrency: int = 100,
    timeout: float = 1.0,
    service_probe: bool = True,
    verbose: bool = False
) -> List[Tuple[int, str, str]]:
    """
    High-level scanning function.
    Supports both synchronous and asynchronous (awaited) callers.
    Blocks until all ports are scanned.
    
    Args:
        target: Target hostname or IP
        ports: Port specification string
        concurrency: Maximum concurrent connections
        timeout: Connection timeout in seconds
        service_probe: Whether to probe for service identification
        verbose: Print results as they're found
        
    Returns:
        List of tuples (port, service, banner) for open ports
    """
    try:
        resolved = socket.gethostbyname(target)
    except Exception as e:
        logger.error(f"Failed to resolve {target}: {e}")
        return _AwaitableList([])

    port_list = parse_ports(ports)
    if not port_list:
        logger.warning(f"No valid ports parsed from: {ports}")
        return _AwaitableList([])

    async def run_scan():
        results = []
        async for port, is_open, svc, banner in scan_generator(resolved, port_list, concurrency, timeout, service_probe):
            if is_open:
                results.append((port, svc, banner))
                if verbose:
                    logger.info(f"[+] Port {port}/tcp open ({svc})")
        return sorted(results)

    try:
        loop = asyncio.get_running_loop()
        if loop and loop.is_running():
            return run_scan()
    except RuntimeError:
        pass

    try:
        res = asyncio.run(run_scan())
        return _AwaitableList(res)
    except Exception as e:
        logger.error(f"Error during scan: {e}")
        return _AwaitableList([])
