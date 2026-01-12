import asyncio
import logging

logger = logging.getLogger(__name__)

# Common top ports
TOP_PORTS = [80, 443, 8080, 8443, 22, 21, 3306, 3389, 25, 53]

class PortScanner:
    def __init__(self, ports=None, timeout=2):
        self.ports = ports or TOP_PORTS
        self.timeout = timeout

    async def check_port(self, ip: str, port: int) -> bool:
        """
        Attempts a TCP connect to (ip, port).
        Returns True if successful, False otherwise.
        """
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def scan(self, ip: str) -> list:
        """
        Scans top ports on the given IP concurrently.
        Returns list of open ports.
        """
        open_ports = []
        tasks = [self.check_port(ip, p) for p in self.ports]
        
        # Run all check_port in parallel
        results = await asyncio.gather(*tasks)
        
        for port, is_open in zip(self.ports, results):
            if is_open:
                open_ports.append(port)
        
        if open_ports:
            # logger.info(f"Open ports for {ip}: {open_ports}")
            pass
            
        return open_ports
