# AGENT.md - Encrypted Traffic Classifier & Research Testbed

## 1. Project Identity & Objective
- **Project Title**: Encrypted Traffic Classification ("Guessing what is inside a sealed parcel")
- **Role**: Senior Network Security Researcher and Machine Learning Engineer.
- **Core Thesis**: Classify encrypted network traffic into 4 application types strictly using external physical/statistical traffic dynamics (packet lengths, inter-arrival times, burstiness, directional ratios) without inspecting payloads (TLS 1.3 / HTTPS encryption) and without shortcut learning (zero IP/port memorization).
- **Golden Rule**: **NO MANUAL WORKFLOWS**. The user must NOT manually click browser links, toggle Wi-Fi, or switch to a physical phone hotspot. Everything must be automated, contained, and programmatic.

---

## 2. Target Classes (The 4 Applications)
1. `streaming`: Video Streaming (HD video playback, DASH/HLS chunk buffering bursts).
2. `video_call`: Video Conferencing (WebRTC bidirectional audio/video duplex, steady ~20ms interval, UDP/SRTP dominant).
3. `file_download`: High-throughput asset/file download (MTU saturation ~1450-1500 bytes, heavy downlink asymmetry).
4. `browsing`: Interactive web browsing (stochastic human think-time, scrolling, internal page transitions).

---

## 3. Strict Research Constraints & Methodology

### A. Total Isolation & No Host OS Telemetry
- Data collection must run inside a **contained Linux environment (Docker testbed)** with its own virtual network interface (`eth0`).
- macOS host background noise (iCloud Drive, Apple push notifications `apsd`, Spotlight, mDNS/Bonjour) must NEVER enter the capture trace.

### B. Programmatic Network Emulation (NO MANUAL SWITCHING TO HOTSPOT)
- Switching network conditions is done **purely programmatically** using Linux Traffic Control (`tc-netem`) inside the container:
  - **`wifi_home` profile**: 5ms base delay, $\pm1\text{ms}$ jitter, 0% packet loss.
  - **`mobile_hotspot` profile**: 45ms base delay, $\pm15\text{ms}$ jitter, 0.2% random packet loss, cellular rate profile.
- The user runs one command specifying `--network wifi_home` or `--network mobile_hotspot`, and the container's virtual network card applies the physical profile instantly.

### C. Headless Robot Personas (Playwright)
- No human touching a browser. Headless Chromium executes automated personas with identical TLS client fingerprints (JA3/JA4 invariant across classes).
- Synthetic media (`--use-fake-device-for-media-stream` and `--use-fake-ui-for-media-stream`) generates authentic audio/video RTP traffic for `video_call`.

### D. Zero Shortcut Learning (Strict Anonymization)
- Feature extraction MUST strip: Source IP, Destination IP, Source Port, Destination Port, absolute timestamps.
- Only statistical invariants are kept: packet size distributions (min, max, mean, std, percentiles), IAT distributions, uplink/downlink ratios, flow duration, protocol flag (`is_udp`).

### E. Evaluation & Generalization Benchmark
- Train & compare: Random Forest, Gradient Boosting, Standardized Logistic Regression.
- Output: Precision/Recall/F1 per class, Confusion Matrices, Gini/MDI Feature Importance.
- **Cross-Network Generalization Benchmark**:
  - Train on `wifi_home` $\rightarrow$ Test on `mobile_hotspot`
  - Train on `mobile_hotspot` $\rightarrow$ Test on `wifi_home`
  - Proves the model learned application dynamics rather than network delay artifacts.

---

## 4. Testbed Implementation Details

### Files & Roles:
- `Dockerfile.testbed`: Contained Linux environment with Playwright Chromium, `tc` (`iproute2`), `tcpdump`, Python, and dependencies.
- `scripts/testbed_runner.py`: Single automated script that:
  1. Configures `tc-netem` on `eth0` according to the selected network profile (`wifi_home` vs `mobile_hotspot`).
  2. Spawns `tcpdump` on isolated `eth0`.
  3. Launches the headless Chromium persona.
  4. Flushes the `.pcap` cleanly upon completion to the mounted `./datasets/raw` volume.
- `scripts/run_container_experiment.sh`: One-command host runner that launches the Docker container with `--cap-add=NET_ADMIN` (for `tc-netem`).
- `src/extract_features.py`: Lightning-fast bidirectional flow aggregator (`dpkt`), strips metadata, exports `datasets/processed/traffic_features.csv`.
- `src/train_evaluate.py`: ML pipeline, cross-network generalization benchmark, confusion matrix rendering, and feature importance analysis.

---

## 5. Absolute Prohibitions for the Assistant
- **NEVER** ask the user to switch to a physical phone hotspot or toggle their host Wi-Fi.
- **NEVER** ask the user to manually browse, stream, or open browser tabs.
- **NEVER** include IP addresses, port numbers, or timestamps in ML feature matrices.
- **ALWAYS** check Docker daemon readiness and provide clean containerized execution paths.
