#!/usr/bin/env python3
"""
scripts/testbed_runner.py - Contained Research Testbed Engine
=============================================================================
Runs inside an isolated Docker container with `--cap-add=NET_ADMIN`.

Responsibilities:
1. Kernel Emulation: Uses Linux `tc-netem` on virtual `eth0` to mathematically
   emulate network profiles (`wifi_home` vs `mobile_hotspot`) with zero manual intervention.
2. Contained Sniffer: Captures only the container's isolated packets on `eth0`.
   Host macOS telemetry never enters this capture.
3. Headless Persona: Drives Chromium with stochastic behavior and synthetic WebRTC A/V.
=============================================================================
"""

import os
import sys
import time
import random
import argparse
import subprocess
import asyncio
from playwright.async_api import async_playwright

BROWSING_URLS = [
    "https://en.wikipedia.org/wiki/Computer_network",
    "https://en.wikipedia.org/wiki/Cryptographic_protocol",
    "https://en.wikipedia.org/wiki/Transmission_Control_Protocol",
    "https://en.wikipedia.org/wiki/Machine_learning",
    "https://en.wikipedia.org/wiki/Internet_protocol_suite",
    "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    "https://en.wikipedia.org/wiki/Deep_learning"
]

STREAMING_URLS = [
    "https://upload.wikimedia.org/wikipedia/commons/transcoded/c/c0/Big_Buck_Bunny_4K.webm/Big_Buck_Bunny_4K.webm.1080p.vp9.webm",
    "https://upload.wikimedia.org/wikipedia/commons/transcoded/b/b3/Big_Buck_Bunny_Trailer_400p.ogv/Big_Buck_Bunny_Trailer_400p.ogv.720p.vp9.webm",
    "https://upload.wikimedia.org/wikipedia/commons/transcoded/f/f1/Sintel_movie_4K.webm/Sintel_movie_4K.webm.1080p.vp9.webm"
]

DOWNLOAD_URLS = [
    # High-speed verified CDN binary test assets
    "https://speed.cloudflare.com/__down?bytes=50000000",
    "https://proof.ovh.net/files/100Mb.dat",
    "https://speed.cloudflare.com/__down?bytes=100000000"
]



def configure_tc_netem(network_env):
    """
    Applies Linux Traffic Control (tc-netem) directly to the container's virtual eth0.
    Eliminates all manual network switching.
    """
    # Remove existing root qdisc
    subprocess.run(["tc", "qdisc", "del", "dev", "eth0", "root"], stderr=subprocess.DEVNULL)
    
    if network_env == "wifi_home":
        # Home Broadband Wi-Fi: 5ms delay +/- 1ms, 0% loss
        cmd = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem",
               "delay", "5ms", "1ms", "loss", "0%"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] tc-netem: Emulating Home Broadband Wi-Fi (5ms base delay, 1ms jitter)")
        else:
            print(f"[-] tc warning: {res.stderr.strip()}")

    elif network_env == "mobile_hotspot":
        # Cellular 4G/5G Hotspot: 45ms delay +/- 15ms, normal distribution, 0.2% loss
        cmd = ["tc", "qdisc", "add", "dev", "eth0", "root", "netem",
               "delay", "45ms", "15ms", "distribution", "normal", "loss", "0.2%"]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode == 0:
            print("[+] tc-netem: Emulating Mobile 4G/5G Hotspot (45ms base delay, 15ms jitter, 0.2% loss)")
        else:
            print(f"[-] tc warning: {res.stderr.strip()}")
    else:
        print(f"[!] Unrecognized network profile '{network_env}'. Running unthrottled.")


async def run_browsing_persona(page, duration):
    """Simulates real human browsing with stochastic scrolling and think-time."""
    print("[*] Persona: Active Web Browsing")
    end_time = time.time() + duration
    visited = 0

    while time.time() < end_time:
        remaining = int(max(0, end_time - time.time()))
        elapsed = duration - remaining
        target = random.choice(BROWSING_URLS)
        visited += 1
        print(f"  [Progress: {elapsed:2d}s / {duration}s] [{visited}] Visiting: {target}")
        try:
            await page.goto(target, wait_until="domcontentloaded", timeout=12000)
            
            # Simulate human reading and scrolling
            scroll_steps = random.randint(3, 6)
            for _ in range(scroll_steps):
                if time.time() >= end_time:
                    break
                scroll_pixels = random.randint(250, 750)
                await page.evaluate(f"window.scrollBy(0, {scroll_pixels});")
                think_time = max(1.0, random.gauss(2.5, 0.8))
                await asyncio.sleep(min(think_time, max(0.1, end_time - time.time())))
        except Exception as e:
            print(f"  [-] Navigation notice: {e}")
            await asyncio.sleep(2)

    print(f"[+] Browsing completed ({visited} pages visited).")


async def run_streaming_persona(page, duration):
    """Simulates video streaming with chunk buffering and seeking."""
    print("[*] Persona: Video Streaming (HD Video Playback + Buffer Bursts)")
    target = random.choice(STREAMING_URLS)
    print(f"  -> Streaming source: {target}")

    try:
        await page.goto(target, wait_until="commit", timeout=10000)
        await asyncio.sleep(1.0)
        await page.evaluate("""() => {
            const v = document.querySelector('video');
            if (v) {
                v.muted = true;
                v.play();
            }
        }""")
    except Exception as e:
        print(f"  [-] Video load notice: {e}")

    end_time = time.time() + duration
    while time.time() < end_time:
        remaining = int(max(0, end_time - time.time()))
        elapsed = duration - remaining
        print(f"  [Progress: {elapsed:2d}s / {duration}s] Video playback active...")
        
        sleep_interval = min(random.uniform(5.0, 8.0), max(0.5, end_time - time.time()))
        await asyncio.sleep(sleep_interval)
        
        if time.time() >= end_time:
            break

        try:
            await page.evaluate("""() => {
                const v = document.querySelector('video');
                if (v && !v.ended) {
                    v.currentTime += 10;
                }
            }""")
            print("  -> User scrubbed video forward 10s (re-buffering burst)")
        except Exception:
            pass

    print(f"[+] Video streaming session finished ({duration}s completed).")



async def run_remote_access_persona(page, duration):
    """
    Simulates encrypted remote administration over SSH, the modern umbrella for the
    NIMS classes {TELNET, shell, localForwarding, remoteForwarding, x11, scp, sftp}:
    - Interactive shell keystrokes (small packets, human think-time; TELNET/shell)
    - direct-tcpip tunnel channels (ssh -L style port forwarding)
    - Periodic SFTP bulk bursts (scp/sftp)
    The SSH server MUST be off-box (reachable via eth0) or nothing is captured.
    """
    try:
        import paramiko
    except ImportError:
        print("[-] paramiko not installed in this environment. Remote access persona unavailable.")
        end_time = time.time() + duration
        while time.time() < end_time:
            await asyncio.sleep(1)
        return
    import socket

    host = os.environ.get("REMOTE_ACCESS_HOST", "")
    port = int(os.environ.get("REMOTE_ACCESS_PORT", "22"))
    user = os.environ.get("REMOTE_ACCESS_USER", "root")
    password = os.environ.get("REMOTE_ACCESS_PASSWORD", "")
    print(f"[*] Persona: Encrypted Remote Access (SSH shell + forward + sftp) -> {user}@{host}:{port}")

    if not host:
        print("[-] REMOTE_ACCESS_HOST not set: no off-box SSH target, nothing to capture. Sleeping.")
        end_time = time.time() + duration
        while time.time() < end_time:
            await asyncio.sleep(1)
        return

    client = None
    end_time = time.time() + duration
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, port=port, username=user, timeout=10,
                       allow_agent=False, look_for_keys=False, password=password)
        print("[+] SSH transport established. Interactive shell open.")

        shell_chan = client.invoke_shell()
        shell_chan.settimeout(0.05)

        commands = ["ls -la /", "uptime", "ps aux | head -20", "df -h",
                    "cat /etc/os-release", "who", "echo research",
                    "uname -a", "top -bn1 | head -15", "free -m"]
        cmd_idx = 0
        sftp_next = time.time() + random.uniform(5, 10)
        forward_next = time.time() + random.uniform(3, 6)

        def drain_shell():
            try:
                while True:
                    if not shell_chan.recv(4096):
                        break
            except socket.timeout:
                pass

        drain_shell()  # consume banner/prompt

        while time.time() < end_time:
            # --- Interactive keystrokes (TELNET/shell dynamics) ---
            if shell_chan:
                cmd = commands[cmd_idx % len(commands)]
                cmd_idx += 1
                for ch in cmd:
                    shell_chan.send(ch)
                    await asyncio.sleep(random.uniform(0.01, 0.05))
                shell_chan.send("\n")
                await asyncio.sleep(random.uniform(1.0, 2.5))  # command output burst
                drain_shell()
                await asyncio.sleep(random.uniform(2.0, 6.0))  # human think-time

            # --- Tunnel channel (localForwarding/remoteForwarding dynamics) ---
            if time.time() >= forward_next:
                forward_next = time.time() + random.uniform(4, 8)
                try:
                    chan = client.get_transport().open_channel(
                        "direct-tcpip", ("example.com", 80), ("127.0.0.1", 0))
                    chan.sendall(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
                    chan.settimeout(3)
                    try:
                        while chan.recv(4096):
                            pass
                    except socket.timeout:
                        pass
                    chan.close()
                    print("  -> Tunneled HTTP fetch through SSH (port-forward burst)")
                except Exception as e:
                    print(f"  [-] Forward notice: {e}")

            # --- SFTP bulk push (scp/sftp dynamics) ---
            if time.time() >= sftp_next:
                sftp_next = time.time() + random.uniform(5, 10)
                try:
                    sftp = client.open_sftp()
                    payload = os.urandom(random.randint(64 * 1024, 256 * 1024))
                    with sftp.open(f"/tmp/research_{int(time.time())}.bin", "wb") as f:
                        f.write(payload)
                    sftp.close()
                    print("  -> SFTP bulk burst transferred")
                except Exception as e:
                    print(f"  [-] SFTP notice: {e}")

        shell_chan.close()
    except Exception as e:
        print(f"[-] Remote access persona notice: {e}")
        while time.time() < end_time:
            await asyncio.sleep(1)
    finally:
        if client:
            client.close()
    print(f"[+] Remote access session terminated ({duration}s completed).")


async def run_download_persona(page, duration):
    """
    Simulates high-throughput asset downloads:
    - Actively streams large binary chunks continuously for the full duration.
    - Saturates TCP window with 1450-1500 byte MTU packets (extreme downlink asymmetry).
    """
    import urllib.request
    print("[*] Persona: High-Throughput Asset Download (Bulk TCP Transfer)")
    target = random.choice(DOWNLOAD_URLS)
    print(f"  -> Downloading binary stream from: {target}")

    end_time = time.time() + duration
    total_bytes = 0

    try:
        req = urllib.request.Request(
            target,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            while time.time() < end_time:
                # Read 64KB chunks continuously to flood the wire
                chunk = resp.read(65536)
                if not chunk:
                    # If file completes before duration, restart download
                    target = random.choice(DOWNLOAD_URLS)
                    req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
                    resp = urllib.request.urlopen(req, timeout=10)
                    continue

                total_bytes += len(chunk)
                remaining = int(max(0, end_time - time.time()))
                elapsed = duration - remaining
                if elapsed % 10 == 0 and elapsed > 0:
                    mb_downloaded = total_bytes / (1024 * 1024)
                    print(f"  [Progress: {elapsed:2d}s / {duration}s] Downloaded {mb_downloaded:.1f} MB (saturating MTU)...")
                await asyncio.sleep(0.001)  # Yield control to event loop

    except Exception as e:
        print(f"  [-] Download stream notice: {e}")
        # Fallback to keep running until duration
        while time.time() < end_time:
            await asyncio.sleep(1)

    mb_final = total_bytes / (1024 * 1024)
    print(f"[+] File download completed: {mb_final:.1f} MB downloaded across wire ({duration}s completed).")


async def execute_persona(class_name, duration):
    """Launches Playwright Chromium with synthetic media devices."""
    if class_name == "remote_access":
        # SSH persona: no browser needed, skip Chromium entirely.
        await run_remote_access_persona(None, duration)
        return

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--use-fake-ui-for-media-stream",
                "--use-fake-device-for-media-stream",
                "--disable-background-networking",
                "--disable-default-apps",
                "--mute-audio",
                "--no-sandbox"
            ]
        )
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720}
        )
        page = await context.new_page()

        if class_name == "browsing":
            await run_browsing_persona(page, duration)
        elif class_name == "streaming":
            await run_streaming_persona(page, duration)
        elif class_name == "file_download":
            await run_download_persona(page, duration)

        await context.close()
        await browser.close()


def main():
    parser = argparse.ArgumentParser(description="Contained Research Testbed Engine")
    parser.add_argument("--class-name", required=True, choices=["streaming", "remote_access", "file_download", "browsing"])
    parser.add_argument("--network", default="wifi_home", choices=["wifi_home", "mobile_hotspot"])
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--capture-pcap", default=None, help="If set, spawns tcpdump inside container to this path")
    args = parser.parse_args()

    # 1. Apply kernel network emulation on container eth0
    configure_tc_netem(args.network)

    tcpdump_proc = None
    if args.capture_pcap:
        os.makedirs(os.path.dirname(args.capture_pcap), exist_ok=True)
        print(f"[*] Starting internal sniffer on eth0 -> {args.capture_pcap}")
        bpf = "ip and not (udp port 5353 or udp port 1900 or port 53)"
        tcpdump_proc = subprocess.Popen([
            "tcpdump", "-i", "eth0", "-s", "128", "-w", args.capture_pcap, bpf
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)

    # 2. Run the Playwright persona
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
