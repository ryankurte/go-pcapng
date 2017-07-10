package pcapng

import (
	"bytes"
	"encoding/binary"
	"io"
)

func writeSectionHeader(w io.Writer, options []Block) error {
	sectionBuff := bytes.NewBuffer(nil)
	sectionHeader := SectionHeaderBlock{
		Magic:         Magic,
		VersionMajor:  MajorVersion,
		VersionMinor:  MinorVersion,
		SectionLength: SectionLengthDefault,
		//Options:       options,
	}
	err := binary.Write(sectionBuff, binary.LittleEndian, sectionHeader)
	if err != nil {
		return err
	}

	return writeBlock(w, BlockTypeSectionHeader, sectionBuff.Bytes())
}

func writeBlock(w io.Writer, blockType uint32, data []byte) error {
	length := uint32(len(data)) + 12
	if err := binary.Write(w, binary.LittleEndian, &BlockHeader{Type: blockType, Length: length}); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := binary.Write(w, binary.LittleEndian, &BlockTrailer{Length: length}); err != nil {
		return err
	}
	return nil
}
