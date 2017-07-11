package types

import (
	"bytes"
	"encoding/binary"
)

// SectionHeaderHeader is the static header component of a section header
type SectionHeaderHeader struct {
	Magic         uint32
	VersionMajor  uint16
	VersionMinor  uint16
	SectionLength uint64
}

// SectionHeader is the internals of a section header block
type SectionHeader struct {
	SectionHeaderHeader
	Options Options
}

// NewSectionHeader creates a section header with the provided options
func NewSectionHeader(options Options) *SectionHeader {
	return &SectionHeader{
		SectionHeaderHeader: SectionHeaderHeader{
			Magic:         Magic,
			VersionMajor:  MajorVersion,
			VersionMinor:  MinorVersion,
			SectionLength: SectionLengthDefault,
		},
		Options: options,
	}
}

// MarshalBinary encodes a SectionHeader to a byte array
func (shb *SectionHeader) MarshalBinary() ([]byte, error) {
	buff := bytes.NewBuffer(nil)

	opts, err := shb.Options.MarshalBinary()
	if err != nil {
		return nil, err
	}

	shb.SectionLength = uint64(len(opts))

	if err := binary.Write(buff, binary.LittleEndian, &shb.SectionHeaderHeader); err != nil {
		return nil, err
	}

	if _, err := buff.Write(opts); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// UnmarshalBinary decodes a SectionHeader from a byte array
func (shb *SectionHeader) UnmarshalBinary(d []byte) error {
	buff := bytes.NewBuffer(d)

	if err := binary.Read(buff, binary.LittleEndian, &shb.SectionHeaderHeader); err != nil {
		return err
	}

	optd := make([]byte, uint(shb.SectionLength))
	if _, err := buff.Read(optd); err != nil {
		return err
	}
	if err := shb.Options.UnmarshalBinary(optd); err != nil {
		return err
	}

	return nil
}
