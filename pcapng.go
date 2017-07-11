package pcapng

import (
	"bufio"
	"io"
	"os"

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

	// Write section header

	return &FileWriter{f: f, w: w}, nil
}

func writeSectionHeaderBlock(w io.Writer, options types.Options) error {
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
