#!/bin/bash

# steps :
# 1. create y4m from png
# 2. start chrome, which you use the y4m as a fake camera with
# 3. start the sfu, and use 'log-packets' which gives text2pcap compatible output
# 4. capture the moz.log file to a  pcap
# 5. hand edit the pcap to isolate the IDR including SPS and PPS
# 6. save it inside of x186k-sfu-assets
# 7. commit it
# 8. cd x186k-sfu
# 9. go generate
# 10. go build

ffmpeg -y -i x186k.idle.screen.1080.png -pix_fmt yuv420p x186k.idle.screen.1080.y4m

CWD=$(pwd)

open -a "Google Chrome" --args \
  --disable-gpu \
  --use-fake-device-for-media-stream \
  --use-file-for-fake-video-capture="$CWD/x186k.idle.screen.1080.y4m"

# then 
# run the sfu
# go run . -debug -https-hostname foo.deadsfu.com -log-packets > moz.log
# egrep '(RTP_PACKET)' moz.log | text2pcap -D -n -l 1 -i 17 -u 1234,1235 -t '%H:%M:%S.' - rtp.pcap
# chop away on rtp.pcap with wireshark
# using the wireshark display filter: 'h264.seq_parameter_set_id' can be helpful
#


