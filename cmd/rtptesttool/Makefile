



# FFPROBE=tshark -r $< -w - -Y 'rtp.ssrc == $(basename $@)' |\
# 	pcapngplay -send-udp |\
# 	ffprobe -i h264.sdp -protocol_whitelist rtp,file,udp -select_streams v -show_frames -show_entries frame=pict_type -of csv |\
# 	cat >$@


COUNTSPS=tshark -F pcap -r $< -w - -Y 'rtp.ssrc == $@' |\
	gst-launch-1.0 -q fdsrc fd=0 ! pcapparse caps = "application/x-rtp, media=video, clock-rate=90000, encoding-name=H264, payload=102" ! rtph264depay !"video/x-h264,stream-format=byte-stream" ! filesink location=/tmp/xyzzy314.263 ; \
	h264_analyze /tmp/xyzzy314.263 | grep -c '= SPS =' 

# $< first item in deps
# $@ left side
# $^ right side

all:  0x84A6D47C 0x58F98CC5 

0x58F98CC5 0x84A6D47C: h264.012021.pcapng
	@echo h264_analyze sps count $@ / $<
	@$(COUNTSPS)
	cat $< | pcapngplay -sps-count -ssrc $@

 



