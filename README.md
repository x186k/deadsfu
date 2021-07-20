 
 <!-- model:  https://github.com/typesense/typesense -->


<div align="center">
<img src="https://raw.githubusercontent.com/x186k/deadsfu/main/logotitle.svg" alt="deadsfu logo" width="150" height="75"/>
</br>
Software to run scalable cloud-native WebRTC broadcasting systems.
</br></br>
A MIT Open Source Millicast Alternative.
</br></br>
The 'dead-simple' broadcasting option for WebRTC
</br></br>
<a href="https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A" rel="nofollow">
<img src="https://img.shields.io/badge/slack%20community-join-d90368" data-canonical-src="https://img.shields.io/badge/slack%20community-join-d90368" style="max-width:100%;"></a>
</div>

## Quick Links  <!-- omit in toc -->

- [Features](#features)
- [Install](#install)
- [Quick Start: Browser-input Streaming](#quick-start-browser-input-streaming)
- [Tutorial: Browser-input Streaming](#tutorial-browser-input-streaming)
- [Getting Support](#getting-support)
- [Contributing](#contributing)
- [Getting Latest Updates](#getting-latest-updates)
- [Compile From Source](#compile-from-source)

<!--
todo
- [Benchmarks](#benchmarks)
-  
-  - [Who's using this](#whos-using-this)
- - [API Documentation](#api-documentation)
- [API Clients](#api-clients)
- [Search UI Components](#search-ui-components)
-->

## Features

- **Dead-Simple Usage:** Meticulously crafted for ease-of-use, scalability, and performance.
- **OBS Compatible:** The SFU can work as a back-end to do multi-server OBS to WebRTC broadcasting.
- **Zero-conf Inside-firewall Use:** Auto-local IP addr detection, DNS registration and HTTPS setup for one-liner SFU setup.
- **Zero-conf HTTPS Certificates:** Just like Caddy, HTTPS certificates are auto-aquired. No firewall holes, thanks to DNS challenge.
- **Zero-conf Outside-firewall Use:** Auto-public IP addr detection, DNS registration and HTTPS setup for one-liner SFU setup.
- **Simple Ingress HTTPS Signalling:** WISH compatible: Send an Offer-SDP, get an Answer-SDP, and you're publishing!
- **Simple Egress HTTPS Signalling:** WISH-like: Send an Offer-SDP, get an Answer-SDP, and you're receiving!
- **FTL Ingress:** Supply an FTL:// URL, and FTL will be the chosen ingress protocol.
- **RTP Ingress:** Supply an RTP:// URL, and RTP will be the chosen ingress protocol.
- **Multi Video Track Forwarding:** Ingress and egress of dozens or hundreds of input video tracks.
- **Selectable Video Switching:** Receivers getting one video-track can switch to any ingress-track into SFU.
- **Standard WebRTC Simulcast:** Standard simulcast can be egressed two ways: a) single switchable video b) 3-tracks of video.
- **Designed For Fault Tolerance:** Single-peer-ingress design for practical large-scale fault-tolerant containerized broadcasting.
- **Chainable SFU clusters:** SFU can ingress via dial-upstream to receive input tracks. All tracks are forwarded.
- **Docker support:** Ready to go Docker images for cloud-native broadcasting clusters.
- **Kubernetes capable:** Designed for Kubernetes broadcasting clusters.
- **HTTPS load balancer compatible:** Designed standard HTTPS load balancer compatibility on egress.
- **Dead-simple Install:** Use a one-liner curl & untar command to prepare to broadcast.
- **No Runtime Dependencies:** DeadSFU is a single binary that you can run locally or in production with a single command.

**Don't see a feature on this list?** Check the issue track to see if your feature is there, if not open a new issue. We use user input to make our roadmap, and we'd love to hear from you.
<!--
- **⚡ Blazing Fast:** Built in C++. Meticulously architected from the ground-up for low-latency (<50ms) instant searches.
- **⚡ Kubernetes Fast:** Built in C++. Meticulously architected from the ground-up for low-latency (<50ms) instant searches.
-->

## Install

Linux Intel/AMD64
```bash
curl -sL https://github.com/x186k/deadsfu/releases/latest/download/deadsfu-linux-amd64.tar.gz | tar xvz
```
Linux ARM64
```bash
curl -sL https://github.com/x186k/deadsfu/releases/latest/download/deadsfu-linux-arm64.tar.gz | tar xvz
```
macOS Intel CPU
```bash
curl -sL https://github.com/x186k/deadsfu/releases/latest/download/deadsfu-darwin-amd64.tar.gz | tar xvz
```
macOS Apple CPU
```bash
curl -sL https://github.com/x186k/deadsfu/releases/latest/download/deadsfu-darwin-arm64.tar.gz | tar xvz
```
Docker Pull
```bash
docker pull x186k/deadsfu
```
Windows
```bash
curl  https://github.com/x186k/deadsfu/releases/latest/download/deadsfu-windows-amd64.zip -sLo tmp && tar -xvf tmp && del tmp
```

## Quick Start: Browser-input Streaming

Linux/macOS
```bash
./deadsfu https://tom42.ddns5.com:8443   # change tom42 to something else
```
Windows
```
rem change tom42 to something else
.\\deadsfu.exe https://tom42.ddns5.com:8443
```
Docker
```bash
# change tom42 to something else
docker run --network host x186k/deadsfu /app/main https://tom42.ddns5.com:8443
```

<!-- ## Quick Start: OBS Streaming -->

## Tutorial: Browser-input Streaming

Tutorial on the documentation site: [https://deadsfu.com/docs/tutorials/browser-input-streaming]

<!-- ## Tutorial: OBS-in Streaming -->

<!-- ## FAQ -->

## Getting Support

Author's email is `cameron@cameronelliott.com`

Slack link: [Slack Invite Link](https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A)

## Contributing

If you have suggestions or ideas, please submit an issue or create a discussion. Your ideas are wanted!

## Getting Latest Updates

You can update by simply re-running the `curl` and `tar` commands again as in the install directions.

## Compile From Source

There are two repos you need to compile from source: `deadsfu` and `deadsfu-binaries`.
`deadsfu-binaries` must be nested inside `deadsfu` when compiling.

You don't need archane git tools like `git lfs` or `git submodules`.

You need a version of Go greater than 1.16, we recommend 1.16.5 or later.

Clone the main repo:
```bash
git clone https://github.com/x186k/deadsfu.git
```
Change dir:
```bash
cd deadsfu
```

Clone the binaries repo:
```bash
git clone https://github.com/x186k/deadsfu-binaries.git
```

Build with Go:
```bash
go build .
```





