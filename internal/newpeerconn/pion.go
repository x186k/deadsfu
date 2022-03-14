package newpeerconn

import (
	_ "io"
	//"net/http/httputil"
	//"github.com/davecgh/go-spew/spew"
	//"github.com/digitalocean/godo"
	"github.com/pion/webrtc/v3"
)

//how I fixed structs
// RTPCodecCapability\{([^,]*),([^,]*),([^,]*),([^,]*),([^,]*)\}
// RTPCodecCapability{MimeType:$1,ClockRate:$2,Channels:$3,SDPFmtpLine:$4,RTCPFeedback:$5}

func RegisterH264AndOpusCodecs(m *webrtc.MediaEngine) error {
	// Default Pion Audio Codecs

	for _, codec := range []webrtc.RTPCodecParameters{
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeOpus, ClockRate: 48000, Channels: 2, SDPFmtpLine: "minptime=10;useinbandfec=1", RTCPFeedback: nil},
			PayloadType:        111,
		},
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypeG722,ClockRate: 8000,Channels: 0,SDPFmtpLine: "",RTCPFeedback: nil},
		// 	PayloadType:        9,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypePCMU,ClockRate: 8000,Channels: 0,SDPFmtpLine: "",RTCPFeedback: nil},
		// 	PayloadType:        0,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypePCMA,ClockRate: 8000,Channels: 0,SDPFmtpLine: "",RTCPFeedback: nil},
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
		if err := m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: extension}, webrtc.RTPCodecTypeAudio); err != nil {
			return err
		}
	}

	videoRTCPFeedback := []webrtc.RTCPFeedback{{Type: "goog-remb", Parameter: ""}, {Type: "ccm", Parameter: "fir"}, {Type: "nack", Parameter: ""}, {Type: "nack", Parameter: "pli"}}
	for _, codec := range []webrtc.RTPCodecParameters{
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypeVP8,ClockRate: 90000,Channels: 0,SDPFmtpLine: "",RTCPFeedback: videoRTCPFeedback},
		// 	PayloadType:        96,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:"video/rtx",ClockRate: 90000,Channels: 0,SDPFmtpLine: "apt=96",RTCPFeedback: nil},
		// 	PayloadType:        97,
		// },

		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypeVP9,ClockRate: 90000,Channels: 0,SDPFmtpLine: "profile-id=0",RTCPFeedback: videoRTCPFeedback},
		// 	PayloadType:        98,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:"video/rtx",ClockRate: 90000,Channels: 0,SDPFmtpLine: "apt=98",RTCPFeedback: nil},
		// 	PayloadType:        99,
		// },

		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:webrtc.MimeTypeVP9,ClockRate: 90000,Channels: 0,SDPFmtpLine: "profile-id=1",RTCPFeedback: videoRTCPFeedback},
		// 	PayloadType:        100,
		// },
		// {
		// 	RTPCodecCapability: webrtc.RTPCodecCapability{MimeType:"video/rtx",ClockRate: 90000,Channels: 0,SDPFmtpLine: "apt=100",RTCPFeedback: nil},
		// 	PayloadType:        101,
		// },

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, Channels: 0, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        102,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/rtx", ClockRate: 90000, Channels: 0, SDPFmtpLine: "apt=102", RTCPFeedback: nil},
			PayloadType:        121,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, Channels: 0, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        127,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/rtx", ClockRate: 90000, Channels: 0, SDPFmtpLine: "apt=127", RTCPFeedback: nil},
			PayloadType:        120,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, Channels: 0, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        125,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/rtx", ClockRate: 90000, Channels: 0, SDPFmtpLine: "apt=125", RTCPFeedback: nil},
			PayloadType:        107,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, Channels: 0, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        108,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/rtx", ClockRate: 90000, Channels: 0, SDPFmtpLine: "apt=108", RTCPFeedback: nil},
			PayloadType:        109,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, Channels: 0, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        127,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/rtx", ClockRate: 90000, Channels: 0, SDPFmtpLine: "apt=127", RTCPFeedback: nil},
			PayloadType:        120,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeH264, ClockRate: 90000, Channels: 0, SDPFmtpLine: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032", RTCPFeedback: videoRTCPFeedback},
			PayloadType:        123,
		},
		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/rtx", ClockRate: 90000, Channels: 0, SDPFmtpLine: "apt=123", RTCPFeedback: nil},
			PayloadType:        118,
		},

		{
			RTPCodecCapability: webrtc.RTPCodecCapability{MimeType: "video/ulpfec", ClockRate: 90000, Channels: 0, SDPFmtpLine: "", RTCPFeedback: nil},
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
		if err := m.RegisterHeaderExtension(webrtc.RTPHeaderExtensionCapability{URI: extension}, webrtc.RTPCodecTypeVideo); err != nil {
			return err
		}
	}

	return nil
}
