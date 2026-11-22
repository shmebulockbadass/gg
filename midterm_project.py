import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]
SCANME_PORTS = [22, 80, 443, 9929, 31337]  # Known open/interesting ports on scanme.nmap.org


def validate_port(port_str):
    """Validate that a single port is an integer between 1 and 65535."""
    try:
        port = int(port_str.strip())
    except ValueError:
        raise ValueError(f"Invalid port '{port_str}': must be an integer.")
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid port {port}: must be between 1 and 65535.")
    return port


def parse_port_range(start_str, end_str):
    """Validate and return a list of ports for a custom range."""
    start_port = validate_port(start_str)
    end_port = validate_port(end_str)
    if start_port > end_port:
        raise ValueError(f"Invalid range: start port ({start_port}) is greater than end port ({end_port}).")
    return list(range(start_port, end_port + 1))


def resolve_host(target):
    """Resolve a hostname to an IPv4 address with error handling."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ConnectionError(f"Unreachable host: could not resolve '{target}'.")


def scan_port(ip, port, timeout=0.5):
    """Attempt a TCP connection to a single port. Returns port if open, else None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                return port
    except (socket.timeout, OSError):
        pass
    return None


def get_service_name(port):
    """Look up the standard service name for a port, if available."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def run_scan(target, ports, timeout=0.5, max_workers=100):
    """Scan a list of ports on a target host and report open ports and timing."""
    print(f"\n--- Scanning {target} ({len(ports)} ports) ---")
    try:
        ip = resolve_host(target)
        print(f"Resolved {target} -> {ip}")
    except ConnectionError as e:
        print(f"[ERROR] {e}")
        return None

    open_ports = []
    start_time = time.perf_counter()

    try:
        with ThreadPoolExecutor(max_workers=min(max_workers, len(ports))) as executor:
            futures = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result is not None:
                    open_ports.append(result)
    except KeyboardInterrupt:
        print("\n[ABORTED] Scan interrupted by user.")
        return None

    elapsed = time.perf_counter() - start_time
    open_ports.sort()

    if open_ports:
        print("Open ports found:")
        for port in open_ports:
            print(f"  - Port {port}/tcp ({get_service_name(port)})")
    else:
        print("No open ports found (host may be filtering traffic or offline).")

    rate = len(ports) / elapsed if elapsed > 0 else 0
    print(f"Completed in {elapsed:.3f}s ({rate:.1f} ports/sec)")
    return elapsed


def run_performance_benchmark():
    """Compare scan performance across different port range sizes on localhost."""
    ranges = [
        ("Small (1-100)", list(range(1, 101))),
        ("Medium (1-500)", list(range(1, 501))),
        ("Large (1-1000)", list(range(1, 1001))),
    ]
    print("\n=== Performance Benchmark on localhost ===")
    results = []
    for label, ports in ranges:
        elapsed = run_scan("127.0.0.1", ports, timeout=0.2, max_workers=100)
        if elapsed is not None:
            results.append((label, len(ports), elapsed))

    print("\n=== Benchmark Summary ===")
    print(f"{'Range':<18} {'Ports':<10} {'Time (s)':<10} {'Ports/sec':<10}")
    print("-" * 50)
    for label, count, elapsed in results:
        rate = count / elapsed if elapsed > 0 else 0
        print(f"{label:<18} {count:<10} {elapsed:<10.3f} {rate:<10.1f}")


def main():
    while True:
        print("\n=== Python TCP Port Scanner ===")
        print("1. Scan common ports on localhost")
        print("2. Scan a custom port range on localhost")
        print("3. Scan selected ports on scanme.nmap.org")
        print("4. Scan custom host & ports (test error handling)")
        print("5. Run performance benchmark (different port ranges)")
        print("6. Exit")

        choice = input("\nSelect an option (1-6): ").strip()

        if choice == "1":
            run_scan("127.0.0.1", COMMON_PORTS)

        elif choice == "2":
            start_str = input("Enter start port (1-65535): ")
            end_str = input("Enter end port (1-65535): ")
            try:
                ports = parse_port_range(start_str, end_str)
                run_scan("127.0.0.1", ports)
            except ValueError as e:
                print(f"[ERROR] {e}")

        elif choice == "3":
            custom = input(f"Enter comma-separated ports or press Enter for default {SCANME_PORTS}: ").strip()
            try:
                ports = [validate_port(p) for p in custom.split(",")] if custom else SCANME_PORTS
                # Slightly longer timeout for remote internet hosts
                run_scan("scanme.nmap.org", ports, timeout=1.5)
            except ValueError as e:
                print(f"[ERROR] {e}")

        elif choice == "4":
            host = input("Enter target host (e.g., invalid.host.local or 192.0.2.1): ").strip()
            ports_input = input("Enter comma-separated ports (e.g., 22,80,443): ").strip()
            try:
                ports = [validate_port(p) for p in ports_input.split(",")]
                run_scan(host, ports, timeout=1.0)
            except ValueError as e:
                print(f"[ERROR] {e}")

        elif choice == "5":
            run_performance_benchmark()

        elif choice == "6":
            print("Exiting.")
            break

        else:
            print("[ERROR] Invalid menu choice. Please enter a number from 1 to 6.")


if __name__ == "__main__":
    main()