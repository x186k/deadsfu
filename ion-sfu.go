// MIT License  The Ion Sfu developers

// Copyright (c) 2019

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"encoding/binary"
	"errors"
)

// VP8Helper is a helper to get temporal data from VP8 packet header
/*
	VP8Helper Payload Descriptor
			0 1 2 3 4 5 6 7                      0 1 2 3 4 5 6 7
			+-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
			|X|R|N|S|R| PID | (REQUIRED)        |X|R|N|S|R| PID | (REQUIRED)
			+-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
		X:  |I|L|T|K| RSV   | (OPTIONAL)   X:   |I|L|T|K| RSV   | (OPTIONAL)
			+-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
		I:  |M| PictureID   | (OPTIONAL)   I:   |M| PictureID   | (OPTIONAL)
			+-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
		L:  |   TL0PICIDX   | (OPTIONAL)        |   PictureID   |
			+-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
		T/K:|TID|Y| KEYIDX  | (OPTIONAL)   L:   |   TL0PICIDX   | (OPTIONAL)
			+-+-+-+-+-+-+-+-+                   +-+-+-+-+-+-+-+-+
		T/K:|TID|Y| KEYIDX  | (OPTIONAL)
			+-+-+-+-+-+-+-+-+
*/
type VP8Helper struct {
	TemporalSupported bool
	// Optional Header
	PictureID uint16 /* 8 or 16 bits, picture ID */
	picIDIdx  uint8
	mBit      bool
	TL0PICIDX uint8 /* 8 bits temporal level zero index */
	tlzIdx    uint8

	// Optional Header If either of the T or K bits are set to 1,
	// the TID/Y/KEYIDX extension field MUST be present.
	TID uint8 /* 2 bits temporal layer idx*/
	// IsKeyFrame is a helper to detect if current packet is a keyframe
	IsKeyFrame bool
}

// Unmarshal parses the passed byte slice and stores the result in the VP8Helper this method is called upon
func (p *VP8Helper) Unmarshal(payload []byte) error {
	if payload == nil {
		return errors.New("empty pkt")
	}

	payloadLen := len(payload)

	if payloadLen < 4 {
		return errors.New("short pkt")
	}

	var idx uint8
	S := payload[idx]&0x10 > 0
	// Check for extended bit control
	if payload[idx]&0x80 > 0 {
		idx++
		// Check if T is present, if not, no temporal layer is available
		p.TemporalSupported = payload[idx]&0x20 > 0
		K := payload[idx]&0x10 > 0
		L := payload[idx]&0x40 > 0
		// Check for PictureID
		if payload[idx]&0x80 > 0 {
			idx++
			p.picIDIdx = idx
			pid := payload[idx] & 0x7f
			// Check if m is 1, then Picture ID is 15 bits
			if payload[idx]&0x80 > 0 {
				idx++
				p.mBit = true
				p.PictureID = binary.BigEndian.Uint16([]byte{pid, payload[idx]})
			} else {
				p.PictureID = uint16(pid)
			}
		}
		// Check if TL0PICIDX is present
		if L {
			idx++
			p.tlzIdx = idx
			p.TL0PICIDX = payload[idx]
		}
		if p.TemporalSupported || K {
			idx++
			p.TID = (payload[idx] & 0xc0) >> 6
		}
		if int(idx) >= payloadLen {
			return errors.New("short pkt2")
		}
		idx++
		// Check is packet is a keyframe by looking at P bit in vp8 payload
		p.IsKeyFrame = payload[idx]&0x01 == 0 && S
	} else {
		idx++
		// Check is packet is a keyframe by looking at P bit in vp8 payload
		p.IsKeyFrame = payload[idx]&0x01 == 0 && S
	}
	return nil
}
