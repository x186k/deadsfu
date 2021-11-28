# URL Guide

## DeadSFU URL Summary

| URL          | Purpose                                         |
|--------------|-------------------------------------------------|
| /whip        | send video to SFU using WHIP, ?room required    |
| /whap        | recv video from SFU using WHAP, ?room required  |
| /*           | serve index.html in 'viewer'-mode               |
| /*?send      | serve index.html in 'sender'-mode               |
| /favicon.ico | serve the DeadSFU favicon                       |

## DeadSFU URL Examples

| URL                 | Purpose                                       |
|---------------------|-----------------------------------------------|
| /whip?room=/foo/bar | send video to SFU using WHIP ?room required   |
| /whap?room=/foo/bar | recv video from SFU using WHAP ?room required |
| /foo/bar            | serve index.html in 'viewer'-mode             |
| /foo/bar?send       | serve index.html in 'sender'-mode                   |
| /favicon.ico        | serve the DeadSFU favicon                     |

## Discussion should WHIP and WHAP be indicated by URL path or query params? (QP)

If we use QP, not path, then 'rooms' then whip and whap would look like:
xsfu.com/live/stream200?whip
xsfu.com/live/stream200?whap
and HTML access happens like:
xsfu.com/index.html or xsfu.com/

If we use Path, not QP, then rooms are accessed like this:
xsfu.com/whip?room=/live/stream200
xsfu.com/whap?room=/live/stream200
and HTML access happens like:
xsfu.com/index.html or xsfu.com/

*In either case, we want the /index.html file to be served for all /.../ paths*
This is so if a user goes to xsfu.com/live/stream200, they get a view-page, and maybe send-page link.


## Decision on Path vs Query Params for whip/whap indication

*DECISION: use /whip and /whap and indicate room using query path: room=/foo/bar*
*Decision this means we are not supporting /room200?whip*

Reasons: 
- It may be a  smidge conceptually easier for new devs to do /whip?room=feedxyz
- It is certainly easier to write the Go muxer setup for /whip vs /feedxyz?whip

After thinking about this twice.


## /whip and /whap explained

/whip takes WHIP protocol, and uses 


