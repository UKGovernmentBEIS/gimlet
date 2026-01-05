package protocol

import (
	"encoding/binary"
	"fmt"
)

// Frame types for binary streaming protocol
const (
	FrameTypeStart  byte = 0x01
	FrameTypeData   byte = 0x02
	FrameTypeEnd    byte = 0x03
	FrameTypeCancel byte = 0x04
)

// FrameTypeToString converts a frame type byte to its string representation
func FrameTypeToString(frameType byte) string {
	switch frameType {
	case FrameTypeStart:
		return "start"
	case FrameTypeData:
		return "data"
	case FrameTypeEnd:
		return "end"
	case FrameTypeCancel:
		return "cancel"
	default:
		return "unknown"
	}
}

// EncodeFrame creates a binary frame: [type][requestID_len][requestID][payload]
func EncodeFrame(frameType byte, requestID string, payload []byte) []byte {
	requestIDBytes := []byte(requestID)
	requestIDLen := uint32(len(requestIDBytes))

	frame := make([]byte, 1+4+len(requestIDBytes)+len(payload))
	frame[0] = frameType

	binary.BigEndian.PutUint32(frame[1:5], requestIDLen)
	copy(frame[5:5+requestIDLen], requestIDBytes)
	copy(frame[5+requestIDLen:], payload)

	return frame
}

// DecodeFrame parses a binary frame and returns frame type, requestID, and payload
func DecodeFrame(frame []byte) (frameType byte, requestID string, payload []byte, err error) {
	if len(frame) < 5 {
		return 0, "", nil, fmt.Errorf("frame too short: %d bytes", len(frame))
	}

	frameType = frame[0]
	requestIDLen := binary.BigEndian.Uint32(frame[1:5])

	if len(frame) < int(5+requestIDLen) {
		return 0, "", nil, fmt.Errorf("frame truncated: expected %d bytes, got %d", 5+requestIDLen, len(frame))
	}

	requestID = string(frame[5 : 5+requestIDLen])
	payload = frame[5+requestIDLen:]

	return frameType, requestID, payload, nil
}
