<!-- omit in toc -->
## DeadSFU - Console Short Help Page 

- [Full Help Link](#full-help-link)
- [Basic Operations](#basic-operations)
  - [Sending Video from Browser](#sending-video-from-browser)
  - [Receiving Video in Browser](#receiving-video-in-browser)
- [Navigation Bar Explainer](#navigation-bar-explainer)

[DeadSFU] wants to be your dead-simple WebRTC [SFU](#sfu-definition) and video switch.

## Full Help Link

[DeadSFU] is where the full documentation can be found.  
This page is just the built-in short help.

## Basic Operations

### Sending Video from Browser

#### HTTP Enabled: Camera Send Not-Possible

`HTTP` can be used _only on Chrome_ to send a warning message video stream from the browser to the SFU. Non-Chrome browsers will not send a video stream.  
These two links *will not work* when you are *not* running with `HTTP`.

<http:/?send&room=main> can be used to send to the room named 'main'.  
<http:/?send> the default room is 'main', so this also sends to 'main'. 

#### HTTPS Enabled: Camera Send Possible

`HTTPS` is required by _the browser_ to capture from your video camera.  
These two links *will not work* when you are *not* running with `HTTPS`.

<https:/?send&room=main> can be used to send to the room named 'main'.  
<https:/?send> the default room is 'main', so this also sends to 'main'. 



### Receiving Video in Browser

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
<li><code>0/1500 rx/tx kbps</code> - indicates you are receiving at 1.5mbps</li>
<li><code>connected</code> - indicates the connection state</li>
<li>All 2nd line words are clickable room names</li>
</ul>


[DeadSFU]: https://deadsfu.com
[Markdown]: http://daringfireball.net/projects/markdown/



<!-- omit in toc -->
## SFU Definition
*SFU* - `Selective Forwarding Unit`.  
A WebRTC SFU is a basic building block of WebRTC systems. An SFU acts as an digital amplifier of sorts.  
An SFU will receive a media stream, and forward that stream to down-stream receivers. This forwarding/repeating operation may be duplicated and performed for many incoming streams. 
