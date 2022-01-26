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
  <span>
    <svg class="xicon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="#0053fa" class="bi bi-fullscreen" viewBox="0 0 16 16">
    <path stroke="#0053fa" stroke-width="1.5" d="M1.5 1a.5.5 0 0 0-.5.5v4a.5.5 0 0 1-1 0v-4A1.5 1.5 0 0 1 1.5 0h4a.5.5 0 0 1 0 1h-4zM10 .5a.5.5 0 0 1 .5-.5h4A1.5 1.5 0 0 1 16 1.5v4a.5.5 0 0 1-1 0v-4a.5.5 0 0 0-.5-.5h-4a.5.5 0 0 1-.5-.5zM.5 10a.5.5 0 0 1 .5.5v4a.5.5 0 0 0 .5.5h4a.5.5 0 0 1 0 1h-4A1.5 1.5 0 0 1 0 14.5v-4a.5.5 0 0 1 .5-.5zm15 0a.5.5 0 0 1 .5.5v4a1.5 1.5 0 0 1-1.5 1.5h-4a.5.5 0 0 1 0-1h4a.5.5 0 0 0 .5-.5v-4a.5.5 0 0 1 .5-.5z"></path>
    </svg>
    <span class="xtext">- clickable button to go fullscreen</span>
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