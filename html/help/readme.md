<!-- omit in toc -->
# DeadSFU - Console Short Help Page

<!-- omit in toc -->
## Table of Contents

- [Link for Full Help Site](#link-for-full-help-site)
- [Browser Camera Video Sending](#browser-camera-video-sending)
- [Receiving Video in Browser](#receiving-video-in-browser)
- [Navigation Bar Explainer](#navigation-bar-explainer)

DeadSFU is designed as a dead-simple SFU and video switch.  
[SFU defined here](#sfu-definition) 

## Link for Full Help Site

[DeadSFU.com] is where the full documentation can be found.  
This page is just the built-in short help.


## Browser Camera Video Sending
 
Browser camera sending *requires* HTTPS access to the SFU.  
Without HTTPS access to the SFU, camera capture and send will *not* be possible.

HTTPS access can be setup directly in DeadSFU using the `--https-*` flags,
or by using an HTTPS terminating proxy.
[Caddy], [nginx], and [Traefik] are a few examples of HTTPS terminating proxys.

<https:/send?room=main> can be used to send to the room named 'main'.  
<https:/send> the default room is 'main', so this also sends to 'main'. 

## Receiving Video in Browser

<http:/?room=main> can be used to view the room: 'main'.  
<http:/> the default room is 'main', so this also views the room: 'main'.  
 
## Navigation Bar Explainer

<style>
    .xicon,
    .xtext {
    vertical-align: middle;
    display: inline-block;
    }
</style>
<ul>
<li>

<span class="cardSpan">
  <span >
  <!-- <svg class="xicon" fill="#0053fa" style="width:24px;height:24px" viewBox="0 0 36 36">
<path d="m 10,16 2,0 0,-4 4,0 0,-2 L 10,10 l 0,6 0,0 z"></path>
<path d="m 20,10 0,2 4,0 0,4 2,0 L 26,10 l -6,0 0,0 z"></path>
<path d="m 24,24 -4,0 0,2 L 26,26 l 0,-6 -2,0 0,4 0,0 z"></path>
<path d="M 12,20 10,20 10,26 l 6,0 0,-2 -4,0 0,-4 0,0 z"></path></svg> -->

<svg class="xicon" fill="#0053fa" height="18px" width="18px" aria-hidden="true" focusable="false" data-prefix="fas" data-icon="expand" class="svg-inline--fa fa-expand fa-w-14" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 448 512">
<path  d="M0 180V56c0-13.3 10.7-24 24-24h124c6.6 0 12 5.4 12 12v40c0 6.6-5.4 12-12 12H64v84c0 6.6-5.4 12-12 12H12c-6.6 0-12-5.4-12-12zM288 44v40c0 6.6 5.4 12 12 12h84v84c0 6.6 5.4 12 12 12h40c6.6 0 12-5.4 12-12V56c0-13.3-10.7-24-24-24H300c-6.6 0-12 5.4-12 12zm148 276h-40c-6.6 0-12 5.4-12 12v84h-84c-6.6 0-12 5.4-12 12v40c0 6.6 5.4 12 12 12h124c13.3 0 24-10.7 24-24V332c0-6.6-5.4-12-12-12zM160 468v-40c0-6.6-5.4-12-12-12H64v-84c0-6.6-5.4-12-12-12H12c-6.6 0-12 5.4-12 12v124c0 13.3 10.7 24 24 24h124c6.6 0 12-5.4 12-12z">
</path>
</svg>

</span>
  <span class="xtext"> - clickable button to go fullscreen</span>
</span>
</li>
<li><code>0/1500 rx/tx kbps</code> - indicates you are sending at 1.5mbps</li>
<li><code>1000/0 rx/tx kbps</code> - indicates you are receiving at 1mbps</li>
<li><code>connected</code> - indicates the connection state</li>
<li>All 2nd line links are clickable room names</li>
</ul>



<!-- omit in toc -->
## SFU Definition
*SFU* - `Selective Forwarding Unit`.  
A WebRTC SFU is a basic building block of WebRTC systems. An SFU acts as an digital amplifier of sorts.  
An SFU will receive a media stream, and forward that stream to down-stream receivers. This forwarding/repeating operation may be duplicated and performed for many incoming streams. 



[DeadSFU]: https://deadsfu.com
[DeadSFU.com]: https://deadsfu.com
[Markdown]: http://daringfireball.net/projects/markdown/
[Caddy]: https://caddyserver.com/
[nginx]: https://www.nginx.com/
[Traefik]: https://traefik.io/