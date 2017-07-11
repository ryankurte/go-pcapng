package types

import (
	"io"
)

func writePacked(w io.Writer, data []byte) error {
	for len(data)%4 != 0 {
		data = append(data, 0x00)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func readPacked(r io.Reader, length uint) ([]byte, error) {
	paddingLength := uint(0)
	if length%4 != 0 {
		paddingLength = 4 - length%4
	}

	data := make([]byte, length+paddingLength)
	if _, err := r.Read(data); err != nil {
		return nil, err
	}
	return data[0:length], nil
}

type EnhancedPacketBlock struct {
	InterfaceID    uint32
	TimestampHigh  uint32
	TimestampLow   uint32
	CaptureLength  uint32
	OriginalLength uint32
	PacketData     []byte
	//Options []Block
}

type InterfaceDescriptionBlock struct {
	LinkType       uint16
	Reserved       uint16
	SnapshotLength uint32
	//Options []Block
}
