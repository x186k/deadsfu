package main

import (
	_ "io"
	//"net/http/httputil"
	//"github.com/davecgh/go-spew/spew"
	//"github.com/digitalocean/godo"
	"github.com/pion/webrtc/v3"
)

func  RegisterH264AndOpusCodecs(m *webrtc.MediaEngine) error {
	// Default Pion Audio Codecs
	for _, codec := range []webrtc.RTPCodecParameters{
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeOpus, 48000, 2, "minptime=10;useinbandfec=1", nil},
			PayloadType:        111,
		},
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeG722, 8000, 0, "", nil},
		// 	PayloadType:        9,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypePCMU, 8000, 0, "", nil},
		// 	PayloadType:        0,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypePCMA, 8000, 0, "", nil},
		// 	PayloadType:        8,
		// },
	} {
		if err := m.RegisterCodec(codec, webrtc.RTPCodecTypeAudio); err != nil {
			return err
		}
	}

	// Default Pion Audio Header Extensions
	for _, extension := range []string{
		"urn:ietf:params:rtp-hdrext:sdes:mid",
		"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
		"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
	} {
		if err := m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{extension}, webrtc.RTPCodecTypeAudio); err != nil {
			return err
		}
	}

	videoRTCPFeedback := []webrtc.RTCPFeedback{{"goog-remb", ""}, {"ccm", "fir"}, {"nack", ""}, {"nack", "pli"}}
	for _, codec := range []webrtc.RTPCodecParameters{
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeVP8, 90000, 0, "", videoRTCPFeedback},
		// 	PayloadType:        96,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=96", nil},
		// 	PayloadType:        97,
		// },

		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeVP9, 90000, 0, "profile-id=0", videoRTCPFeedback},
		// 	PayloadType:        98,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=98", nil},
		// 	PayloadType:        99,
		// },

		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeVP9, 90000, 0, "profile-id=1", videoRTCPFeedback},
		// 	PayloadType:        100,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=100", nil},
		// 	PayloadType:        101,
		// },

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f", videoRTCPFeedback},
			PayloadType:        102,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=102", nil},
			PayloadType:        121,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f", videoRTCPFeedback},
			PayloadType:        127,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=127", nil},
			PayloadType:        120,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", videoRTCPFeedback},
			PayloadType:        125,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=125", nil},
			PayloadType:        107,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f", videoRTCPFeedback},
			PayloadType:        108,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=108", nil},
			PayloadType:        109,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f", videoRTCPFeedback},
			PayloadType:        127,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=127", nil},
			PayloadType:        120,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{webrtc.MimeTypeH264, 90000, 0, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032", videoRTCPFeedback},
			PayloadType:        123,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/rtx", 90000, 0, "apt=123", nil},
			PayloadType:        118,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{"video/ulpfec", 90000, 0, "", nil},
			PayloadType:        116,
		},
	} {
		if err := m.RegisterCodec(codec, webrtc.RTPCodecTypeVideo); err != nil {
			return err
		}
	}

	// Default Pion Video Header Extensions
	for _, extension := range []string{
		"urn:ietf:params:rtp-hdrext:sdes:mid",
		"urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
		"urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
	} {
		if err := m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{extension}, webrtc.RTPCodecTypeVideo); err != nil {
			return err
		}
	}

	return nil
}