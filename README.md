 



 <!-- model:  https://github.com/typesense/typesense -->


## Dead-simple WebRTC broadcasting.<br>From OBS, the browser, or your app.<br>Cloud-native and scalable. <!-- omit in toc -->


**DeadSFU**: dead-simple broadcasting and video transmission.

<!-- ### [Browser-input Tutorial](/README/) -->

<a style="text-decoration:none;" href="https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A" rel="nofollow">
<img src="https://img.shields.io/badge/slack%20community-join-red" alt="HTML tutorial">
</a>
<a style="text-decoration:none;" href="https://github.com/x186k/deadsfu" rel="nofollow">
<img src="https://img.shields.io/badge/github-x186k%2Fdeadsfu-orange" alt="HTML tutorial">
</a>

## Quick Links  <!-- omit in toc -->

- [Videos](#videos)
- [Feature List](#feature-list)
- [Install](#install)
- [Quick Start: Browser-input Streaming](#quick-start-browser-input-streaming)
- [Step-by-step: Browser-input Streaming](#step-by-step-browser-input-streaming)
- [Getting Support](#getting-support)
- [Email Newsletter](#email-newsletter)
- [Contributing](#contributing)
- [Getting Latest Updates](#getting-latest-updates)
- [Compile From Source](#compile-from-source)

<!--
todo, see also typesense
## Benchmarks
## Who's using this
## API Documentation
## API Clients
-->

## Videos

- [Video Tour][v1]: Launch Digital Ocean VM, Download, Run, Browser-send, Browser-receive, change 3x simulcast channels


[v1]: /binaries/video1.mp4

## Feature List

- **Dead-Simple Usage:** Meticulously crafted for ease-of-use, scalability, and performance.
- **Large Scale WebRTC Broadcasting:** SFUs can be easily cascaded to create clusters of hundreds of servers.
- **Cloud Native Docker:** Ready to go Docker images for cloud-native broadcasting clusters.
- **Auto Scaling Compatible:** HTTPS signalling is compatible with most cluster-autoscaling methods.
- **OBS Broadcasting:** Send from OBS to DeadSFU for doing WebRTC broadcasting.
- **Browser Broadcasting:** Simple HTML console for doing WebRTC broadcasting.
- **Browser Viewer:** Browser viewer enables watching broadcasts.
- **FTL Ingress:** Add an FTL:// URL to the args, and FTL will be the chosen ingress protocol.
- **RTP Ingress:** Add an RTP:// URL to the args, and RTP will be the chosen ingress protocol. (todo)
- **Firewall Ready Check:** When using a public IP address, the SFU checks if the ports is open.
- **Zero-conf Inside-firewall Use:** Auto-local IP addr detection, DNS registration and HTTPS setup for one-liner SFU setup.
- **Zero-conf Outside-firewall Use:** Auto-public IP addr detection, DNS registration and HTTPS setup for one-liner SFU setup.
- **Simple Ingress HTTPS Signalling:** WISH compatible: Send an Offer-SDP, get an Answer-SDP, and you're publishing!
- **Zero-conf HTTPS Certificates:** Just like Caddy, HTTPS certificates are auto-aquired. No firewall holes, thanks to DNS challenge.
- **Simple Egress HTTPS Signalling:** WISH-like: Send an Offer-SDP, get an Answer-SDP, and you're receiving!
- **Multi Video Track Forwarding:** Ingress and egress of dozens or hundreds of input video tracks.
- **Selectable Video Switching:** Receivers getting one video-track can switch to any ingress-track into SFU.
- **Standard WebRTC Simulcast:** WebRTC simulcast ingress means SFU ingress takes 3x track-levels from browser.
- **Designed For Fault Tolerance:** Single-peer-ingress design for practical large-scale fault-tolerant containerized broadcasting.
- **Kubernetes capable:** Designed for Kubernetes broadcasting clusters.
- **HTTPS load balancer compatible:** Designed standard HTTPS load balancer compatibility on egress.
- **Dead-simple Install:** Use a one-liner curl & untar command to prepare to broadcast.
- **No Runtime Dependencies:** DeadSFU is a single binary that you can run locally or in production with a single command.

**Don't see a feature on this list?** Check the issue track to see if your feature is there, if not open a new issue. We use user input to make our roadmap, and we'd love to hear from you.

<!--
- **⚡ Blazingy Fast:** Built in C++. Meticulously architected from the ground-up for low-latency (<50ms) instant searches.
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

## Step-by-step: Browser-input Streaming

[View the browser input tutorial.](https://deadsfu.com//tutorials/browser-in-tutorial/)

<!-- ## Tutorial: OBS-in Streaming -->

<!-- ## FAQ -->

## Getting Support

Author's email is `cameron@cameronelliott.com`

Slack link: [Slack Invite Link](https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A)

## Email Newsletter

[Get the email newletter.](/newsletter)

## Contributing

If you have an idea to share, please post it on the [Github discussions](https://github.com/x186k/deadsfu/discussions/categories/ideas) board.  
If you have found a bug, please file an issue on [Github issues](https://github.com/x186k/deadsfu/issues)
If you have suggestions or ideas, please submit an issue or create a discussion. Your ideas are wanted!

## Getting Latest Updates

You can update by simply re-running the `curl` and `tar` commands again as in the install directions.

## Compile From Source

There are two repos you need to compile from source: `deadsfu` and `deadsfu-binaries`.
`deadsfu-binaries` must be nested inside `deadsfu` when compiling.

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




