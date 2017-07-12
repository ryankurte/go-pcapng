package pcapng

import (
	"bufio"
	"io"
	"os"
	"time"

	"github.com/ryankurte/go-pcapng/types"
)

// FileWriter is a PCAP-NG file writer
type FileWriter struct {
	f *os.File
	w io.Writer
}

// NewFileWriter creates a new PCAP-NG file writing instanew
func NewFileWriter(fileName string) (*FileWriter, error) {
	// Open capture file
	f, err := os.OpenFile(fileName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return nil, err
	}
	w := bufio.NewWriter(f)

	return &FileWriter{f: f, w: w}, nil
}

// WriteSectionHeader writes a pcap-ng section header
// This is required at the start of a file, and optional to start new sections
func (fw *FileWriter) WriteSectionHeader(options types.SectionHeaderOptions) error {
	return writeSectionHeaderBlock(fw.w, options)
}

// WriteInterfaceDescription writes an interface description block
// This creates an interface which should be referenced by order created in enhanced packets
func (fw *FileWriter) WriteInterfaceDescription(linkType uint16, options types.InterfaceOptions) error {
	return writeInterfaceDescriptionBlock(fw.w, linkType, options)
}

// WriteEnhancedPacketBlock writes an enhanced packet block
// InterfaceID must be the index of a previously created interface description
func (fw *FileWriter) WriteEnhancedPacketBlock(interfaceID uint32, timestamp time.Time, data []byte, options types.EnhancedPacketOptions) error {
	return writeEnhancedPacketBlock(fw.w, interfaceID, timestamp, data, options)
}

func writeSectionHeaderBlock(w io.Writer, options types.SectionHeaderOptions) error {
	sh := types.NewSectionHeader(options)
	shd, err := sh.MarshalBinary()
	if err != nil {
		return err
	}
	b := types.NewBlock(types.BlockTypeSectionHeader, shd)
	bd, err := b.MarshalBinary()
	if err != nil {
		return err
	}
	w.Write(bd)
	return nil
}

func writeInterfaceDescriptionBlock(w io.Writer, linkType uint16, options types.InterfaceOptions) error {
	sh, err := types.NewInterfaceDescription(linkType, options)
	if err != nil {
		return err
	}

	shd, err := sh.MarshalBinary()
	if err != nil {
		return err
	}
	b := types.NewBlock(types.BlockTypeInterfaceDescription, shd)
	bd, err := b.MarshalBinary()
	if err != nil {
		return err
	}
	w.Write(bd)
	return nil
}

func writeEnhancedPacketBlock(w io.Writer, interfaceID uint32, timestamp time.Time, data []byte, options types.EnhancedPacketOptions) error {
	ep, err := types.NewEnhancedPacket(interfaceID, timestamp, data, options)
	if err != nil {
		return err
	}

	epd, err := ep.MarshalBinary()
	if err != nil {
		return err
	}
	b := types.NewBlock(types.BlockTypeEnhancedPacket, epd)
	bd, err := b.MarshalBinary()
	if err != nil {
		return err
	}
	w.Write(bd)
	return nil
}
