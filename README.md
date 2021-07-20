 
 <!-- model:  https://github.com/typesense/typesense -->


<div align="center">
<img src="https://raw.githubusercontent.com/x186k/deadsfu/main/logotitle.svg" alt="deadsfu logo" width="150" height="75"/>
<p>A dead-simple SFU to make scalable cloud-native broadcasting systems.</p>
An Open Source Millicast Alternative.
</br></br>
<a href="https://join.slack.com/t/deadsfu/shared_invite/zt-sv23oa10-XFFYoJHPty8BtuCmBthH_A" rel="nofollow">
<img src="https://img.shields.io/badge/slack%20community-join-d90368" data-canonical-src="https://img.shields.io/badge/slack%20community-join-d90368" style="max-width:100%;"></a>
</div>

## Quick Links

- [Quick Links](#quick-links)
- [Features](#features)
- [Install](#install)

<!--
- [Benchmarks](#benchmarks)
-  
-  - [Who's using this](#whos-using-this)
- - [API Documentation](#api-documentation)
- [API Clients](#api-clients)
- [Search UI Components](#search-ui-components)
-->

## Features

- **Dead Simple Usage:** Meticulously crafted for ease of use and performance.
- **OBS Compatible:** The SFU can work as a back-end to do multi-server OBS to WebRTC broadcasting.
- **Zero-conf Inside-firewall Use:** Auto-local IP addr detection, DNS registration and HTTPS setup for one-liner SFU setup.
- **Zero-conf HTTPS Certificates:** Just like Caddy, HTTPS certificates are auto-aquired. No firewall holes, thanks to DNS challenge.
- **Zero-conf Outside-firewall Use:** Auto-public IP addr detection, DNS registration and HTTPS setup for one-liner SFU setup.
- **Simple Ingress HTTPS Signalling:** WISH compatible: Send an Offer-SDP, get an Answer-SDP, and you're publishing!
- **Simple Egress HTTPS Signalling:** WISH-like: Send an Offer-SDP, get an Answer-SDP, and you're receiving!
- **FTL Ingress:** Supply an FTL:// URL, and FTL will be the choosen ingress protocol.
- **RTP Ingress:** Supply an RTP:// URL, and RTP will be the choosen ingress protocol.
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

```bash
ls -l
```



