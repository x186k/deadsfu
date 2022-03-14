// This file
// MIT License
// Copyright (c) 2021 CREAM Lab @ IRCAM & FEMTO-ST
// Copyright (c) 2021 x186k developers

package newpeerconn

import (
	//"github.com/pion/ice"
	//"github.com/pion/webrtc/v3"

	//"github.com/creamlab/ducksoup/helpers"
	"github.com/pion/interceptor"
	"github.com/pion/interceptor/pkg/nack"
	"github.com/pion/interceptor/pkg/report"
	"github.com/pion/interceptor/pkg/twcc"
	"github.com/pion/sdp/v3"
	"github.com/pion/webrtc/v3"
)

var videoRTCPFeedback = []webrtc.RTCPFeedback{
	{Type: "goog-remb", Parameter: ""},
	{Type: "ccm", Parameter: "fir"},
	{Type: "nack", Parameter: ""},
	{Type: "nack", Parameter: "pli"},
	{Type: "transport-cc", Parameter: ""},
}

var OpusCodecs = []webrtc.RTPCodecParameters{
	{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     "audio/opus",
			ClockRate:    48000,
			Channels:     2,
			SDPFmtpLine:  "minptime=10;useinbandfec=1;stereo=0",
			RTCPFeedback: nil},
		PayloadType: 111,
	},
}
var H264Codecs = []webrtc.RTPCodecParameters{
	{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     "video/H264",
			ClockRate:    90000,
			Channels:     0,
			SDPFmtpLine:  "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42001f",
			RTCPFeedback: videoRTCPFeedback},
		PayloadType: 102,
	},
	{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     "video/H264",
			ClockRate:    90000,
			Channels:     0,
			SDPFmtpLine:  "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42001f",
			RTCPFeedback: videoRTCPFeedback},
		PayloadType: 127,
	},
	{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     "video/H264",
			ClockRate:    90000,
			Channels:     0,
			SDPFmtpLine:  "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
			RTCPFeedback: videoRTCPFeedback},
		PayloadType: 125,
	},
	{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     "video/H264",
			ClockRate:    90000,
			Channels:     0,
			SDPFmtpLine:  "level-asymmetry-allowed=1;packetization-mode=0;profile-level-id=42e01f",
			RTCPFeedback: videoRTCPFeedback},
		PayloadType: 108,
	},
	{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:     "video/H264",
			ClockRate:    90000,
			Channels:     0,
			SDPFmtpLine:  "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=640032",
			RTCPFeedback: videoRTCPFeedback},
		PayloadType: 123,
	},
}

func NewWebRTCAPI() (*webrtc.API, error) {
	s := webrtc.SettingEngine{}
	//s.SetSRTPReplayProtectionWindow(512)
	//s.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	m := &webrtc.MediaEngine{}

	// always include opus
	for _, c := range OpusCodecs {
		if err := m.RegisterCodec(c, webrtc.RTPCodecTypeAudio); err != nil {
			return nil, err
		}
	}

	// select video codecs
	// for _, c := range VP8Codecs {
	// 	if err := m.RegisterCodec(c, webrtc.RTPCodecTypeVideo); err != nil {
	// 		return nil, err
	// 	}
	// }
	for _, c := range H264Codecs {
		if err := m.RegisterCodec(c, webrtc.RTPCodecTypeVideo); err != nil {
			return nil, err
		}
	}

	i := &interceptor.Registry{}

	if err := registerInterceptors(m, i); err != nil {
		return nil, err
	}

	return webrtc.NewAPI(
		webrtc.WithSettingEngine(s),
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(i),
	), nil
}

// adapted from https://github.com/pion/webrtc/blob/v3.1.2/interceptor.go
func registerInterceptors(mediaEngine *webrtc.MediaEngine, interceptorRegistry *interceptor.Registry) error {
	if err := configureNack(mediaEngine, interceptorRegistry); err != nil {
		return err
	}

	if err := configureRTCPReports(interceptorRegistry); err != nil {
		return err
	}

	if true {
		if err := configureTWCCHeaderExtension(mediaEngine, interceptorRegistry); err != nil {
			return err
		}

		if err := configureTWCCSender(mediaEngine, interceptorRegistry); err != nil {
			return err
		}
	}

	// if err := configureAbsSendTimeHeaderExtension(mediaEngine, interceptorRegistry); err != nil {
	// 	return err
	// }

	// if err := configureSDESHeaderExtension(mediaEngine, interceptorRegistry); err != nil {
	// 	return err
	// }

	return nil
}

// ConfigureRTCPReports will setup everything necessary for generating Sender and Receiver Reports
func configureRTCPReports(interceptorRegistry *interceptor.Registry) error {
	receiver, err := report.NewReceiverInterceptor()
	if err != nil {
		return err
	}

	sender, err := report.NewSenderInterceptor()
	if err != nil {
		return err
	}

	interceptorRegistry.Add(receiver)
	interceptorRegistry.Add(sender)
	return nil
}

// ConfigureNack will setup everything necessary for handling generating/responding to nack messages.
func configureNack(mediaEngine *webrtc.MediaEngine, interceptorRegistry *interceptor.Registry) error {
	generator, err := nack.NewGeneratorInterceptor()
	if err != nil {
		return err
	}

	responder, err := nack.NewResponderInterceptor()
	if err != nil {
		return err
	}

	mediaEngine.RegisterFeedback(webrtc.RTCPFeedback{Type: "nack"}, webrtc.RTPCodecTypeVideo)
	mediaEngine.RegisterFeedback(webrtc.RTCPFeedback{Type: "nack", Parameter: "pli"}, webrtc.RTPCodecTypeVideo)
	interceptorRegistry.Add(responder)
	interceptorRegistry.Add(generator)
	return nil
}

// ConfigureTWCCHeaderExtensionSender will setup everything necessary for adding
// a TWCC header extension to outgoing RTP packets. This will allow the remote peer to generate TWCC reports.
func configureTWCCHeaderExtension(mediaEngine *webrtc.MediaEngine, interceptorRegistry *interceptor.Registry) error {
	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.TransportCCURI}, webrtc.RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.TransportCCURI}, webrtc.RTPCodecTypeAudio,
	); err != nil {
		return err
	}

	i, err := twcc.NewHeaderExtensionInterceptor()
	if err != nil {
		return err
	}

	interceptorRegistry.Add(i)
	return nil
}

// ConfigureTWCCSender will setup everything necessary for generating TWCC reports.
func configureTWCCSender(mediaEngine *webrtc.MediaEngine, interceptorRegistry *interceptor.Registry) error {
	mediaEngine.RegisterFeedback(webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBTransportCC}, webrtc.RTPCodecTypeVideo)
	mediaEngine.RegisterFeedback(webrtc.RTCPFeedback{Type: webrtc.TypeRTCPFBTransportCC}, webrtc.RTPCodecTypeAudio)

	generator, err := twcc.NewSenderInterceptor()
	if err != nil {
		return err
	}

	interceptorRegistry.Add(generator)
	return nil
}

// For more accurante REMB reports
func configureAbsSendTimeHeaderExtension(mediaEngine *webrtc.MediaEngine, interceptorRegistry *interceptor.Registry) error {

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.ABSSendTimeURI}, webrtc.RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.ABSSendTimeURI}, webrtc.RTPCodecTypeAudio,
	); err != nil {
		return err
	}

	return nil
}

func configureSDESHeaderExtension(mediaEngine *webrtc.MediaEngine, interceptorRegistry *interceptor.Registry) error {

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.SDESMidURI},
		webrtc.RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.SDESRTPStreamIDURI},
		webrtc.RTPCodecTypeVideo,
	); err != nil {
		return err
	}

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.SDESMidURI},
		webrtc.RTPCodecTypeAudio,
	); err != nil {
		return err
	}

	if err := mediaEngine.RegisterHeaderExtension(
		webrtc.RTPHeaderExtensionCapability{URI: sdp.SDESRTPStreamIDURI},
		webrtc.RTPCodecTypeAudio,
	); err != nil {
		return err
	}

	return nil
}
