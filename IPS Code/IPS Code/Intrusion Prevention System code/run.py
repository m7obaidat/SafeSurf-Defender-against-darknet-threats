# Required modules for system-level operations and IPS setup
import os
import sys
import subprocess
from src.IPS import setup_nfqueue

# Ensure the script is run with root privileges
if os.geteuid() != 0:
    raise PermissionError("This script requires root privileges. Please run with 'sudo'.")

# Function to list all available network interfaces except loopback
def list_network_interfaces():
    interfaces = []
    result = subprocess.check_output(['ip', '-o', 'link', 'show'], text=True)
    for line in result.splitlines():
        parts = line.split(':')
        if len(parts) > 1:
            name = parts[1].strip().split('@')[0]
            if name != 'lo':
                interfaces.append(name)
    return interfaces

# Function to flush all iptables rules and reset policies
def flush_iptables():
    subprocess.run(['iptables', '-F'], check=True)
    subprocess.run(['iptables', '-X'], check=True)
    subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
    subprocess.run(['iptables', '-t', 'nat', '-X'], check=True)
    subprocess.run(['iptables', '-P', 'INPUT', 'ACCEPT'], check=True)
    subprocess.run(['iptables', '-P', 'FORWARD', 'ACCEPT'], check=True)
    subprocess.run(['iptables', '-P', 'OUTPUT', 'ACCEPT'], check=True)
    print("[+] Flushed all iptables rules.")

# Function to set the default route via a specific WAN interface
def set_default_gateway(wan_interface, gateway_ip):
    subprocess.run(['ip', 'route', 'del', 'default'], check=True)
    subprocess.run(['ip', 'route', 'add', 'default', 'via', gateway_ip, 'dev', wan_interface], check=True)
    print(f"[+] Default gateway set to {gateway_ip} via {wan_interface}")

# Function to configure NAT and NFQUEUE rules using iptables
def set_iptables_rules(wan_interface, local_interfaces):
    # Enable IP forwarding
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True)

    # Set up NAT masquerading for outbound traffic from WAN interface
    subprocess.run(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', wan_interface, '-j', 'MASQUERADE'], check=True)

    # Route all forwarded packets through NFQUEUE using the mangle table
    subprocess.run([
        'iptables', '-t', 'mangle', '-I', 'FORWARD', '-j', 'NFQUEUE',
        '--queue-balance', '0:3',
        '--queue-bypass'
    ], check=True)

    # Allow traffic between WAN and LAN interfaces
    for local_interface in local_interfaces:
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', local_interface, '-o', wan_interface, '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'FORWARD', '-i', wan_interface, '-o', local_interface, '-m', 'state', '--state', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'], check=True)

    print("[+] iptables rules set using NFQUEUE in the mangle table with --queue-bypass.")

# Function to apply advanced sysctl networking optimizations
def configure_sysctl():
    sysctl_settings = [
        # Connection tracking and buffer tuning
        "net.netfilter.nf_conntrack_max=900000000",
        "net.core.rmem_max=33554432",
        "net.core.wmem_max=33554432",
        "net.ipv4.tcp_rmem=4096 16777216 67108864",
        "net.ipv4.tcp_wmem=4096 65536 67108864",

        # Congestion control and probing
        "net.ipv4.tcp_congestion_control=cubic",
        "net.ipv4.tcp_mtu_probing=1",
        "net.ipv4.tcp_fastopen=3",

        # Disable IPv6 for performance/stability
        "net.ipv6.conf.all.disable_ipv6=1",
        "net.ipv6.conf.default.disable_ipv6=1",
        "net.ipv6.conf.lo.disable_ipv6=1",

        # TCP connection and socket tuning
        "net.ipv4.tcp_fin_timeout=30",
        "net.ipv4.tcp_keepalive_time=900",
        "net.ipv4.tcp_synack_retries=2",
        "net.ipv4.ip_local_port_range=2000 65535",
        "net.ipv4.tcp_rfc1337=1",
        "net.ipv4.tcp_keepalive_probes=5",
        "net.ipv4.tcp_keepalive_intvl=15",
        "net.ipv4.tcp_max_tw_buckets=2880000",
        "net.ipv4.tcp_tw_reuse=1",

        # Memory and socket buffer sizes
        "net.core.rmem_default=62914560",
        "net.core.rmem_max=99999999",
        "net.core.wmem_default=62914560",
        "net.core.wmem_max=99999999",
        "net.core.somaxconn=32768",
        "net.core.netdev_max_backlog=65536",
        "net.core.optmem_max=25165824",

        # TCP/UDP memory allocation
        "net.ipv4.tcp_mem=1310720 2621440 5242880",
        "net.ipv4.udp_mem=1310720 2621440 5242880",
        "net.ipv4.tcp_rmem=873800 167772160 1677721600",
        "net.ipv4.udp_rmem_min=163840",
        "net.ipv4.tcp_wmem=655360 167772160 1677721600",
        "net.ipv4.udp_wmem_min=163840"
    ]
    for setting in sysctl_settings:
        subprocess.run(['sysctl', '-w', setting], check=True)
    print("[+] Applied sysctl optimizations.")

# Function to display the IP addresses of WAN and LAN interfaces
def print_ip_info(wan_interface, local_interfaces):
    result = subprocess.check_output(['ip', '-o', '-4', 'addr', 'show'], text=True)
    print("\nInterfaces and IP addresses:")
    for line in result.strip().split('\n'):
        parts = line.split()
        interface_name = parts[1]
        ip_address = parts[3]
        if interface_name == wan_interface:
            print(f"WAN (wan) -> {interface_name} -> v4: {ip_address}")
        elif interface_name in local_interfaces:
            print(f"LAN (lan) -> {interface_name} -> v4: {ip_address}")

# Main configuration function that wires everything together
def configure_ips(wan_interface, local_interfaces, gateway_ip):
    flush_iptables()
    set_default_gateway(wan_interface, gateway_ip)
    set_iptables_rules(wan_interface, local_interfaces)
    configure_sysctl()
    print_ip_info(wan_interface, local_interfaces)

    # Setup and run the NFQUEUE-based intrusion prevention sniffer
    sniffer = setup_nfqueue(
        to_csv=False,
        output_file='./flows_test.csv',
        verbose=False
    )

    if sniffer is None:
        print("[-] Failed to start NFQUEUE sniffer. Exiting.")
        sys.exit(1)

    print("[+] Starting Intrusion Prevention System.....")
    try:
        sniffer()
        sniffer.join()
    except KeyboardInterrupt:
        print('[!] Stopping the IPS...')
        sniffer.stop()
        sniffer.join()

# Entry point when script is executed directly
if __name__ == '__main__':
    interfaces = list_network_interfaces()
    print("Available interfaces:", interfaces)

    # Get WAN, LAN interfaces and gateway IP from user
    wan_interface = input("Enter WAN interface (e.g., eth0): ").strip()
    local_interfaces_input = input("Enter local interfaces (comma separated, e.g., eth1, eth2): ").strip()
    local_interfaces = [i.strip() for i in local_interfaces_input.split(',')]
    gateway_ip = input(f"Enter the gateway IP for {wan_interface} (e.g., 192.168.1.1): ").strip()

    # Validate selected interfaces
    if wan_interface not in interfaces or not all(i in interfaces for i in local_interfaces):
        print("Invalid interface(s) selected.")
        sys.exit(1)

    # Configure and start the IPS
    configure_ips(wan_interface, local_interfaces, gateway_ip)

