from rich.console import Console
from rich.table import Table
from src.utils import extract_json_data, threadpool_executer
import socket
import sys
import pyfiglet

console = Console()

class NetScan:

    PORTS_DATA_FILE = "src/iana_ports.json"

    def __init__(self):
        self.ports_info = {}
        self.open_ports = []
        self.remote_host = ""

    def get_ports_info(self):
        data = extract_json_data(NetScan.PORTS_DATA_FILE)
        self.ports_info = {int(k): v for (k, v) in data.items()}

    def scan_port(self, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        conn_status = sock.connect_ex((self.remote_host, port))
        if conn_status == 0:
            self.open_ports.append(port)
        sock.close()

    def show_completion_message(self):
        print()
        if self.open_ports:
            console.print("Scan Completed. Open Ports:", style="bold blue")
            table = Table(show_header=True, header_style="bold green")
            table.add_column("PORT", style="blue")
            table.add_column("STATE", style="blue", justify="center")
            table.add_column("SERVICE", style="blue")
            for port in self.open_ports:
                table.add_row(str(port), "OPEN", self.ports_info[port])
            console.print(table)
        else:
            console.print(f"No Open Ports Found on Target", style="bold red")

    @staticmethod
    def show_startup_message():
        ascii_art = pyfiglet.figlet_format("x NetScan x")
        console.print(f"[bold green]{ascii_art}[/bold green]")
        console.print("*" * 64, style="bold green")
        console.print(
            "*" * 8, "TCP Port Scanner - By BlogByteSecurity Ver.1.0", "*" * 8, style="bold green"
        )
        console.print("*" * 64, style="bold green")
        print()

    @staticmethod
    def get_host_ip_addr(target):
        try:
            ip_addr = socket.gethostbyname(target)
        except socket.gaierror as e:
            console.print(f"{e}. Exiting.", style="bold red")
            sys.exit()
        console.print(f"\nIP address acquired: [bold blue]{ip_addr}[/bold blue]")
        return ip_addr

    def initialize(self):
        self.show_startup_message()
        self.get_ports_info()
        try:
            target = console.input("[bold blue]Target: ")
        except KeyboardInterrupt:
            console.print(f"\nRoger that! Exiting.", style="bold red")
            sys.exit()
        self.remote_host = self.get_host_ip_addr(target)
        try:
            input("\nNetScan is ready. Press ENTER to run the scanner.")
        except KeyboardInterrupt:
            console.print(f"\nRoger that. Exiting.", style="bold red")
            sys.exit()
        else:
            self.run()

    def run(self):
        threadpool_executer(
            self.scan_port, self.ports_info.keys(), len(self.ports_info.keys())
        )
        self.show_completion_message()

if __name__ == "__main__":
    netscan = NetScan()
    netscan.initialize()