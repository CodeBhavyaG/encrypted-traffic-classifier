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
    "https://speed.hetzner.de/100MB.bin",
    "https://ash-speed.hetzner.com/100MB.bin",
    "https://proof.ovh.net/files/100Mb.dat"
]

WEBRTC_TEST_URL = "https://webrtc.github.io/samples/src/content/peerconnection/pc1/"


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


async def run_videocall_persona(page, duration):
    """Simulates WebRTC video conferencing with synthetic A/V feeds."""
    print("[*] Persona: Video Conferencing (WebRTC Full Duplex)")
    print(f"  -> Connecting to WebRTC test endpoint: {WEBRTC_TEST_URL}")

    try:
        await page.goto(WEBRTC_TEST_URL, wait_until="domcontentloaded", timeout=15000)
        
        start_btn = await page.wait_for_selector("#startButton", timeout=5000)
        if start_btn:
            await start_btn.click()
            await asyncio.sleep(1)

        call_btn = await page.wait_for_selector("#callButton", timeout=5000)
        if call_btn:
            await call_btn.click()
            print("[+] WebRTC Bidirectional Peer Connection ESTABLISHED!")
            print("  -> Transmitting synthetic 720p 30fps video + audio duplex stream...")
    except Exception as e:
        print(f"  [-] WebRTC notice: {e}")

    end_time = time.time() + duration
    while time.time() < end_time:
        remaining = int(max(0, end_time - time.time()))
        elapsed = duration - remaining
        if elapsed % 10 == 0:
            print(f"  [Progress: {elapsed:2d}s / {duration}s] Active WebRTC call streaming...")
        await asyncio.sleep(1)

    try:
        hangup_btn = await page.wait_for_selector("#hangupButton", timeout=2000)
        if hangup_btn:
            await hangup_btn.click()
    except Exception:
        pass

    print(f"[+] Video conference call terminated ({duration}s completed).")


async def run_download_persona(page, duration):
    """Simulates high-throughput asset downloads."""
    print("[*] Persona: High-Throughput Asset Download")
    target = random.choice(DOWNLOAD_URLS)
    print(f"  -> Fetching: {target}")

    try:
        await page.goto(target, timeout=duration * 1000)
    except Exception:
        pass

    end_time = time.time() + duration
    while time.time() < end_time:
        remaining = int(max(0, end_time - time.time()))
        elapsed = duration - remaining
        if elapsed % 10 == 0:
            print(f"  [Progress: {elapsed:2d}s / {duration}s] Bulk download active...")
        await asyncio.sleep(1)

    print(f"[+] File download session complete ({duration}s completed).")


async def execute_persona(class_name, duration):
    """Launches Playwright Chromium with synthetic media devices."""
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
        elif class_name == "video_call":
            await run_videocall_persona(page, duration)
        elif class_name == "file_download":
            await run_download_persona(page, duration)

        await context.close()
        await browser.close()


def main():
    parser = argparse.ArgumentParser(description="Contained Research Testbed Engine")
    parser.add_argument("--class-name", required=True, choices=["streaming", "video_call", "file_download", "browsing"])
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
