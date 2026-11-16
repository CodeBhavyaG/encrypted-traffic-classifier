#!/usr/bin/env python3
"""
scripts/testbed_runner.py - Contained Research Testbed Engine
=============================================================================
Runs inside an isolated Docker container with `--cap-add=NET_ADMIN`.

Emulates 11 Modern Encrypted Protocol Classes (Option B):
1. HTTPS: Encrypted Web Browsing / API requests (TLS 1.3 / HTTP/2 over TCP/443).
2. DoT: DNS over TLS (RFC 7858, TCP/853).
3. SSH-shell: Encrypted interactive remote terminal console (TCP/22).
4. SCP: Secure file copy protocol over SSH (TCP/22).
5. SFTP: Secure File Transfer Protocol subsystem (TCP/22).
6. SSH-localForward: SSH direct-tcpip local forwarding tunnel (TCP/22).
7. SSH-remoteForward: SSH reverse port forwarding tunnel (TCP/22).
8. SSH-x11: X11 graphical channel packet forwarding over SSH (TCP/22).
9. FTPS: FTP over TLS/SSL (TCP/990 or AUTH TLS on TCP/21).
10. TLS-Telnet: Telnet wrapped in TLS (TCP/992).
11. Encrypted-P2P: P2P encrypted peer exchange / DHT stream traffic.
=============================================================================
"""

import os
import sys
import time
import random
import socket
import ssl
import ftplib
import argparse
import subprocess
import asyncio
from playwright.async_api import async_playwright

try:
    import dns.message
    import dns.query
    import dns.rdatatype
except ImportError:
    dns = None

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from scp import SCPClient
except ImportError:
    SCPClient = None

ALL_CLASSES = [
    "HTTPS",
    "DoT",
    "SSH-shell",
    "SCP",
    "SFTP",
    "SSH-localForward",
    "SSH-remoteForward",
    "SSH-x11",
    "FTPS",
    "TLS-Telnet",
    "Encrypted-P2P"
]

HTTPS_URLS = [
    "https://en.wikipedia.org/wiki/Computer_network",
    "https://en.wikipedia.org/wiki/Cryptographic_protocol",
    "https://en.wikipedia.org/wiki/Transmission_Control_Protocol",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://speed.cloudflare.com/__down?bytes=10000000",
    "https://proof.ovh.net/files/10Mb.dat"
]

DOT_DOMAINS = [
    "wikipedia.org",
    "cloudflare.com",
    "google.com",
    "github.com",
    "kernel.org",
    "debian.org",
    "python.org",
    "ietf.org"
]


def configure_tc_netem(network_env):
    """Applies Linux Traffic Control (tc-netem) to container eth0."""
    subprocess.run(["tc", "qdisc", "del", "dev", "eth0", "root"], stderr=subprocess.DEVNULL)
    if network_env == "wifi_home":
        cmd = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem",
               "delay", "5ms", "1ms", "loss", "0%"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] tc-netem: Emulating Home Broadband Wi-Fi (5ms delay, 1ms jitter)")
        else:
            print(f"[-] tc warning: {res.stderr.strip()}")
    elif network_env == "mobile_hotspot":
        cmd = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem",
               "delay", "45ms", "15ms", "distribution", "normal", "loss", "0.2%"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] tc-netem: Emulating Mobile 4G/5G Hotspot (45ms delay, 15ms jitter, 0.2% loss)")
        else:
            print(f"[-] tc warning: {res.stderr.strip()}")
    else:
        print(f"[!] Unrecognized network profile '{network_env}'. Running unthrottled.")


def get_ssh_target_info():
    host = os.environ.get("REMOTE_ACCESS_HOST", "ssh-target")
    port = int(os.environ.get("REMOTE_ACCESS_PORT", "22"))
    user = os.environ.get("REMOTE_ACCESS_USER", "research")
    password = os.environ.get("REMOTE_ACCESS_PASSWORD", "research")
    return host, port, user, password


def open_ssh_client():
    if not paramiko:
        raise RuntimeError("paramiko not installed")
    host, port, user, password = get_ssh_target_info()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password, timeout=10,
                   allow_agent=False, look_for_keys=False)
    return client


# --- 1. HTTPS Persona (TLS 1.3 / HTTP/2) ---
async def run_https_persona(page, duration):
    print("[*] Persona: HTTPS (Encrypted Web / Assets over TLS 1.3)")
    end_time = time.time() + duration
    while time.time() < end_time:
        target = random.choice(HTTPS_URLS)
        try:
            print(f"  -> Navigating HTTPS: {target}")
            await page.goto(target, wait_until="load", timeout=15000)
            for _ in range(random.randint(2, 4)):
                if time.time() >= end_time:
                    break
                await page.evaluate(f"window.scrollBy(0, {random.randint(200, 600)})")
                await asyncio.sleep(random.uniform(0.5, 2.0))
        except Exception as e:
            print(f"  [-] HTTPS navigation notice: {e}")
            await asyncio.sleep(1.0)


# --- 2. DoT Persona (DNS over TLS / RFC 7858, TCP 853) ---
async def run_dot_persona(duration):
    print("[*] Persona: DoT (DNS over TLS, TCP/853)")
    end_time = time.time() + duration
    # Public DoT resolvers: Cloudflare (1.1.1.1) and Google (8.8.8.8)
    resolvers = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"]
    qtypes = ["A", "AAAA", "TXT", "MX"]

    while time.time() < end_time:
        resolver = random.choice(resolvers)
        domain = random.choice(DOT_DOMAINS)
        qtype = random.choice(qtypes)
        try:
            if dns:
                q = dns.message.make_query(domain, qtype)
                # Query over TLS on port 853
                dns.query.tls(q, resolver, timeout=4.0)
            else:
                # Raw TLS query to port 853 if dnspython not present
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((resolver, 853), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock) as ssock:
                        # 2-byte length prefix + minimal dummy query header
                        req = b"\x00\x1e\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
                        ssock.sendall(req)
                        ssock.recv(512)
            print(f"  -> DoT query: {domain} ({qtype}) -> {resolver}:853")
        except Exception as e:
            print(f"  [-] DoT notice: {e}")
        await asyncio.sleep(random.uniform(0.5, 2.0))


# --- 3. SSH-shell Persona (Interactive Terminal Keystrokes) ---
async def run_ssh_shell_persona(duration):
    print("[*] Persona: SSH-shell (Encrypted Interactive Console)")
    end_time = time.time() + duration
    try:
        client = open_ssh_client()
        chan = client.invoke_shell()
        chan.settimeout(0.1)

        commands = ["ls -la /", "uptime", "ps aux | head -15", "df -h",
                    "uname -a", "cat /etc/os-release", "top -bn1 | head -10", "whoami"]
        cmd_idx = 0

        while time.time() < end_time:
            cmd = commands[cmd_idx % len(commands)]
            cmd_idx += 1
            # Send character-by-character with realistic typing delay
            for ch in cmd:
                chan.send(ch)
                await asyncio.sleep(random.uniform(0.02, 0.08))
            chan.send("\n")
            await asyncio.sleep(random.uniform(0.5, 1.5))
            try:
                while chan.recv(4096):
                    pass
            except socket.timeout:
                pass
            await asyncio.sleep(random.uniform(1.5, 4.0))  # Human think-time
        client.close()
    except Exception as e:
        print(f"[-] SSH-shell error: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)


# --- 4. SCP Persona (Secure Copy Bulk Transfer) ---
async def run_scp_persona(duration):
    print("[*] Persona: SCP (Encrypted Secure Copy File Transfer)")
    end_time = time.time() + duration
    try:
        client = open_ssh_client()
        local_tmp = "/tmp/scp_test_chunk.dat"
        remote_tmp = "/tmp/scp_remote_chunk.dat"

        # Generate 1MB random payload for SCP transfer
        with open(local_tmp, "wb") as f:
            f.write(os.urandom(1024 * 1024))

        while time.time() < end_time:
            if SCPClient:
                with SCPClient(client.get_transport()) as scp:
                    scp.put(local_tmp, remote_tmp)
                    print("  -> SCP: Transferred 1MB file to remote target")
            else:
                # Fallback via sftp if SCP python wrapper unavailable
                sftp = client.open_sftp()
                sftp.put(local_tmp, remote_tmp)
                sftp.close()
            await asyncio.sleep(random.uniform(1.0, 3.0))
        client.close()
    except Exception as e:
        print(f"[-] SCP error: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)


# --- 5. SFTP Persona (Secure File Transfer Protocol Subsystem) ---
async def run_sftp_persona(duration):
    print("[*] Persona: SFTP (Encrypted Binary File Subsystem)")
    end_time = time.time() + duration
    try:
        client = open_ssh_client()
        sftp = client.open_sftp()
        chunk_data = os.urandom(64 * 1024)

        while time.time() < end_time:
            remote_path = f"/tmp/sftp_burst_{int(time.time())}.bin"
            with sftp.open(remote_path, "wb") as f:
                for _ in range(random.randint(10, 30)):
                    f.write(chunk_data)
            print(f"  -> SFTP: Wrote chunked binary stream to {remote_path}")
            # Read back
            with sftp.open(remote_path, "rb") as f:
                while f.read(65536):
                    pass
            sftp.remove(remote_path)
            await asyncio.sleep(random.uniform(1.0, 3.0))
        sftp.close()
        client.close()
    except Exception as e:
        print(f"[-] SFTP error: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)


# --- 6. SSH-localForward Persona (SSH -L direct-tcpip tunnel) ---
async def run_ssh_localforward_persona(duration):
    print("[*] Persona: SSH-localForward (SSH -L direct-tcpip Tunnel)")
    end_time = time.time() + duration
    try:
        client = open_ssh_client()
        transport = client.get_transport()

        while time.time() < end_time:
            # Open direct-tcpip channel forwarding to target HTTP echo on port 8080
            channel = transport.open_channel("direct-tcpip", ("127.0.0.1", 8080), ("127.0.0.1", 54321))
            channel.settimeout(2.0)
            req = b"GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ForwardTest\r\n\r\n"
            channel.sendall(req)
            resp = channel.recv(4096)
            channel.close()
            print(f"  -> SSH-localForward: Tunneled HTTP request, received {len(resp)} bytes")
            await asyncio.sleep(random.uniform(0.8, 2.5))
        client.close()
    except Exception as e:
        print(f"[-] SSH-localForward error: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)


# --- 7. SSH-remoteForward Persona (SSH -R reverse tunnel) ---
async def run_ssh_remoteforward_persona(duration):
    print("[*] Persona: SSH-remoteForward (SSH -R Reverse Tunnel)")
    end_time = time.time() + duration
    try:
        client = open_ssh_client()
        transport = client.get_transport()
        remote_port = 9876

        try:
            transport.request_port_forward("0.0.0.0", remote_port)
        except Exception:
            pass

        # Execute remote curl in ssh session connecting to the forwarded port
        stdin, stdout, stderr = client.exec_command(
            f"for i in $(seq 1 5); do nc -z 127.0.0.1 {remote_port} || true; sleep 1; done"
        )
        while time.time() < end_time:
            # Simulate reverse channel traffic bursts
            stdin, stdout, stderr = client.exec_command("date; echo 'PING_REVERSE'")
            out = stdout.read()
            print(f"  -> SSH-remoteForward: Reverse channel burst active ({len(out)} bytes)")
            await asyncio.sleep(random.uniform(1.0, 3.0))
        client.close()
    except Exception as e:
        print(f"[-] SSH-remoteForward error: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)


# --- 8. SSH-x11 Persona (SSH -X graphical forwarding channel) ---
async def run_ssh_x11_persona(duration):
    print("[*] Persona: SSH-x11 (Encrypted Graphical X11 Display Forwarding)")
    end_time = time.time() + duration
    try:
        client = open_ssh_client()
        transport = client.get_transport()

        # Request X11 forwarding
        session = transport.open_session()
        session.request_x11()
        session.exec_command("echo 'x11-test'; for i in $(seq 1 10); do echo x11_burst_$i; sleep 0.5; done")

        while time.time() < end_time:
            try:
                chan = transport.open_channel("x11", ("127.0.0.1", 6000), ("127.0.0.1", 12345))
                # Send synthetic X11 handshake setup packet (12-byte X11 connection header)
                x11_setup = b"B\x00\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00"
                chan.sendall(x11_setup)
                await asyncio.sleep(0.5)
                chan.close()
                print("  -> SSH-x11: Sent X11 connection protocol frame through encrypted channel")
            except Exception:
                # If channel reject, stream terminal x11 environment requests
                session.send(b"\x00" * 32)
            await asyncio.sleep(random.uniform(1.0, 3.0))
        client.close()
    except Exception as e:
        print(f"[-] SSH-x11 error: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)


# --- 9. FTPS Persona (FTP over TLS/SSL) ---
async def run_ftps_persona(duration):
    print("[*] Persona: FTPS (FTP over Explicit/Implicit TLS)")
    end_time = time.time() + duration
    host, _, user, password = get_ssh_target_info()

    while time.time() < end_time:
        try:
            ftps = ftplib.FTP_TLS()
            ftps.connect(host, 21, timeout=5.0)
            ftps.auth()  # Explicit AUTH TLS handshake
            ftps.login(user, password)
            ftps.prot_p()  # Force TLS data channel protection

            # Directory listing over TLS data channel
            files = []
            ftps.retrlines("LIST", files.append)
            print(f"  -> FTPS: TLS directory listing successful ({len(files)} entries)")

            # Upload small test file over TLS data channel
            test_payload = os.urandom(1024 * 32)
            import io
            ftps.storbinary("STOR /tmp/ftps_test.dat", io.BytesIO(test_payload))
            print("  -> FTPS: Uploaded 32KB asset over TLS data channel")
            ftps.quit()
        except Exception as e:
            print(f"  [-] FTPS notice: {e}")
        await asyncio.sleep(random.uniform(1.5, 4.0))


# --- 10. TLS-Telnet Persona (Telnet over TLS, TCP/992) ---
async def run_tls_telnet_persona(duration):
    print("[*] Persona: TLS-Telnet (Encrypted Telnet Terminal over TLS/992)")
    end_time = time.time() + duration
    host, _, _, _ = get_ssh_target_info()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    while time.time() < end_time:
        try:
            with socket.create_connection((host, 992), timeout=5.0) as sock:
                with ctx.wrap_socket(sock) as ssock:
                    print("  -> TLS-Telnet: TLS handshake established on port 992")
                    # Send interactive commands with think-time
                    commands = [b"uptime\n", b"date\n", b"echo research_telnet\n", b"exit\n"]
                    for cmd in commands:
                        ssock.sendall(cmd)
                        await asyncio.sleep(random.uniform(0.5, 1.5))
                        try:
                            ssock.settimeout(0.5)
                            ssock.recv(1024)
                        except socket.timeout:
                            pass
        except Exception as e:
            print(f"  [-] TLS-Telnet notice: {e}")
        await asyncio.sleep(random.uniform(1.5, 4.0))


# --- 11. Encrypted-P2P Persona (Encrypted DHT / BitTorrent MSE stream) ---
async def run_encrypted_p2p_persona(duration):
    print("[*] Persona: Encrypted-P2P (Encrypted P2P Stream / MSE Handshake)")
    end_time = time.time() + duration
    # Bootstrap DHT / P2P targets (real public bootstrap nodes)
    bootstrap_nodes = [
        ("router.bittorrent.com", 6881),
        ("dht.transmissionbt.com", 6881),
        ("router.utorrent.com", 6881)
    ]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)

    while time.time() < end_time:
        host, port = random.choice(bootstrap_nodes)
        try:
            # Send real bencoded BEP-5 DHT 'ping' query (encrypted/obfuscated P2P dynamics)
            tid = os.urandom(2)
            dht_ping = b"d1:ad2:id20:" + os.urandom(20) + b"e1:q4:ping1:t2:" + tid + b"1:y1:qe"
            sock.sendto(dht_ping, (host, port))

            # Simulate peer encrypted stream exchange (Diffie-Hellman MSE frame burst)
            mse_frame = os.urandom(random.randint(96, 512))
            sock.sendto(mse_frame, (host, port))
            print(f"  -> Encrypted-P2P: DHT & encrypted peer frame -> {host}:{port}")
            try:
                sock.recvfrom(2048)
            except socket.timeout:
                pass
        except Exception as e:
            print(f"  [-] Encrypted-P2P notice: {e}")
        await asyncio.sleep(random.uniform(0.3, 1.5))
    sock.close()


async def execute_persona(class_name, duration):
    if class_name == "HTTPS":
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--disable-background-networking", "--disable-default-apps", "--mute-audio", "--no-sandbox"]
            )
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720}
            )
            page = await context.new_page()
            await run_https_persona(page, duration)
            await context.close()
            await browser.close()
    elif class_name == "DoT":
        await run_dot_persona(duration)
    elif class_name == "SSH-shell":
        await run_ssh_shell_persona(duration)
    elif class_name == "SCP":
        await run_scp_persona(duration)
    elif class_name == "SFTP":
        await run_sftp_persona(duration)
    elif class_name == "SSH-localForward":
        await run_ssh_localforward_persona(duration)
    elif class_name == "SSH-remoteForward":
        await run_ssh_remoteforward_persona(duration)
    elif class_name == "SSH-x11":
        await run_ssh_x11_persona(duration)
    elif class_name == "FTPS":
        await run_ftps_persona(duration)
    elif class_name == "TLS-Telnet":
        await run_tls_telnet_persona(duration)
    elif class_name == "Encrypted-P2P":
        await run_encrypted_p2p_persona(duration)
    else:
        raise ValueError(f"Unknown class: {class_name}")


def main():
    parser = argparse.ArgumentParser(description="Contained Research Testbed Engine")
    parser.add_argument("--class-name", required=True, choices=ALL_CLASSES)
    parser.add_argument("--network", default="wifi_home", choices=["wifi_home", "mobile_hotspot"])
    parser.add_argument("--duration", type=int, default=45, help="Duration in seconds")
    parser.add_argument("--capture-pcap", default=None, help="If set, spawns tcpdump inside container to this path")
    args = parser.parse_args()

    # 1. Apply kernel network emulation on container eth0
    configure_tc_netem(args.network)

    tcpdump_proc = None
    if args.capture_pcap:
        os.makedirs(os.path.dirname(args.capture_pcap), exist_ok=True)
        print(f"[*] Starting internal sniffer on eth0 -> {args.capture_pcap}")
        # Capture IP traffic; filter out local broadcast/mDNS noise
        bpf = "ip and not (udp port 5353 or udp port 1900)"
        tcpdump_proc = subprocess.Popen([
            "tcpdump", "-i", "eth0", "-s", "128", "-w", args.capture_pcap, bpf
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

    # 2. Run selected encrypted persona
    asyncio.run(execute_persona(args.class_name, args.duration))

    # 3. Terminate sniffer
    if tcpdump_proc:
        print("[*] Terminating internal sniffer...")
        tcpdump_proc.terminate()
        try:
            tcpdump_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            tcpdump_proc.kill()
        print(f"[+] Contained trace saved to: {args.capture_pcap}")


if __name__ == "__main__":
    main()
