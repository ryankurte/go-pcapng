package pcapng

import (
	"encoding/binary"
	"io"
)

const (
	Magic                uint32 = 0x1A2B3C4D
	MajorVersion         uint16 = 1
	MinorVersion         uint16 = 0
	SectionLengthDefault uint64 = 0xFFFFFFFFFFFFFFFF
)

const (
	BlockTypeSectionHeader  uint32 = 0x0A0D0D0A
	BlockTypeEnhancedPacket uint32 = 0x00000006
)

type SectionHeaderBlock struct {
	Magic         uint32
	VersionMajor  uint16
	VersionMinor  uint16
	SectionLength uint64
	//Options       []Block
}

func (shb *SectionHeaderBlock) MarshalBinary(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, shb.Magic); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, shb.VersionMajor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, shb.VersionMinor); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, shb.SectionLength); err != nil {
		return err
	}

	return nil
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
