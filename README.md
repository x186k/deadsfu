 



 <!-- model:  https://github.com/typesense/typesense -->


## Dead-simple Scalable WebRTC Broadcasting  <!-- omit in toc -->


**DeadSFU**: dead-simple broadcasting and video transmission.


<!-- slack badget -->
<a style="text-decoration:none;" href="https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A" rel="nofollow">
<img src="https://img.shields.io/badge/slack%20community-join-red" alt="HTML tutorial">
</a>



## Quick Links  <!-- omit in toc -->

- [Feature List](#feature-list)
- [Install](#install)
- [Quick Start: OBS / FTL ingress](#quick-start-obs--ftl-ingress)
- [Quick Start: Browser Ingress](#quick-start-browser-ingress)
- [Getting Support](#getting-support)
- [Email Newsletter](#email-newsletter)
- [Contributing](#contributing)
- [Getting Latest Updates](#getting-latest-updates)
- [Compile From Source](#compile-from-source)
- [DeadSFU Thanks](#deadsfu-thanks)

<!--
todo, see also typesense
## Benchmarks
## Who's using this
## API Documentation
## API Clients
-->


## Feature List

- **Dead-Simple Usage:** Meticulously crafted for ease-of-use, scalability, and performance.
- **Large Scale WebRTC Broadcasting:** SFUs can be easily cascaded to create clusters of hundreds of servers.
- **Cloud Native Docker:** Ready to go Docker images for cloud-native broadcasting clusters.
- **Auto Scaling Compatible:** HTTP signalling is compatible with most cluster-autoscaling methods.
- **OBS Broadcasting:** Send from OBS to DeadSFU for doing WebRTC broadcasting.
- **Browser Viewer:** Browser viewer enables watching broadcasts.
- **Simple Ingress HTTPS Signalling:** WISH compatible: Send an Offer-SDP, get an Answer-SDP, and you're publishing!
- **Simple Egress HTTPS Signalling:** WISH-like: Send an Offer-SDP, get an Answer-SDP, and you're receiving!
- **Multi Video Track Forwarding:** Ingress and egress of dozens or hundreds of input video tracks.
- **Selectable Video Switching:** Receivers getting one video-track can switch to any ingress-track into SFU.
- **Standard WebRTC Simulcast:** WebRTC simulcast ingress means SFU ingress takes 3x track-levels from browser.
- **Designed For Fault Tolerance:** Single-peer-ingress design for practical large-scale fault-tolerant containerized broadcasting.
- **Kubernetes capable:** Designed for Kubernetes broadcasting clusters.
- **HTTP load balancer compatible:** Designed standard HTTP load balancer compatibility on egress.
- **Dead-simple Install:** Use a one-liner curl & untar command to prepare to broadcast.
- **No Runtime Dependencies:** DeadSFU is a single binary that you can run locally or in production with a single command.

**Don't see a feature on this list?** Check the issue track to see if your feature is there, if not open a new issue. We use user input to make our roadmap, and we'd love to hear from you.


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

## Quick Start: OBS / FTL ingress

Linux/macOS
```bash
./deadsfu --http :8080 --html internal --ftl-key 123-abc
```
Windows
```
.\\deadsfu --http :8080 --html internal --ftl-key 123-abc
```
Docker Forwarded Ports (Mac,Win,Linux)
```bash
docker run -p 127.0.0.1:8080:8080 -p 127.0.0.1:8084:8084/udp -p 127.0.0.1:8084:8084/tcp x186k/deadsfu /app/main --http :8080 --html internal --ftl-key 123-abc
```

Docker Host Networking Linux ONLY!
```bash
docker run --network host x186k/deadsfu /app/main --http :8080 --html internal --ftl-key 123-abc
```

## Quick Start: Browser Ingress

#### Not Yet, use the Slack channel

<!-- ## Quick Start: Digital Ocean App

[![Deploy to DO](https://www.deploytodo.com/do-btn-blue.svg)](https://cloud.digitalocean.com/apps/new?repo=https://github.com/x186k/deadsfu/tree/main) -->


## Getting Support

Author's email is `cameron@cameronelliott.com`

Slack link: [Slack Invite Link](https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A)

## Email Newsletter

[Get the email newletter.](https://docs.google.com/forms/d/e/1FAIpQLSd8rzXabvn73YC_GPRtXZb1zlKPeOEQuHDdVi4m9umJqEaJsA/viewform)

## Contributing

If you have an idea to share, please post it on the [Github discussions](https://github.com/x186k/deadsfu/discussions/categories/ideas) board.  
If you have found a bug, please file an issue on [Github issues](https://github.com/x186k/deadsfu/issues)
If you have suggestions or ideas, please submit an issue or create a discussion. Your ideas are wanted!

## Getting Latest Updates

You can update by simply re-running the `curl` and `tar` commands again as in the install directions.

## Compile From Source

There are two repos you need to compile from source: `deadsfu` and `deadsfu-binaries`.
`deadsfu-binaries` must be nested inside `deadsfu` when compiling.
If you add the `--recursive` flag seen below, you will get both
repos checked out as needed for building.
The `--recursive` flag tells Git to also checkout any [Git submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules).

You need a version of Go greater than 1.16, we recommend 1.17 or later.

Clone the main repo:
```bash
git clone --recursive https://github.com/x186k/deadsfu
```
Change dir:
```bash
cd deadsfu
```

Build with Go:
```bash
go build .
```

## DeadSFU Thanks

- [Sean Dubois](https://github.com/Sean-Der) Creator of Pion
- [Luis Orlando](https://github.com/OrlandoCo) Pion help code
- [Juliusz Chroboczek](https://github.com/jech) Pion help and code
- [Matt Holt](https://github.com/mholt) Creator of Caddy
- [Francis Lavoie](https://github.com/francislavoie) Caddy maintainer
- [Alex Williams](https://github.com/llspalex) Louper founder, inspiration.
- [Sayan Bhattacharya](https://github.com/Thunder80) Louper developer.
- [Charles Surett](https://github.com/scj643) Early user.






