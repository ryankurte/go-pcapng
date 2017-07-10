package pcapng

import (
	"encoding/binary"
	"io"
	"log"
)

type BlockHeader struct {
	Type   uint32
	Length uint32
}

type BlockTrailer struct {
	Length uint32
}

type Block struct {
	BlockHeader
	Data []byte
	BlockTrailer
}

func NewBlock(blockType uint32, data []byte) *Block {
	length := uint32(len(data) + 12)
	return &Block{
		BlockHeader:  BlockHeader{Type: blockType, Length: length},
		Data:         data,
		BlockTrailer: BlockTrailer{Length: length},
	}
}

func (b *Block) MarshalBinary(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, b.BlockHeader); err != nil {
		return err
	}

	// Pad up to multiple of 4 bytes (32 bit words) for struct alignment
	data := b.Data
	for len(data)%4 != 0 {
		data = append(data, 0x00)
	}

	if _, err := w.Write(data); err != nil {
		return err
	}

	if err := binary.Write(w, binary.LittleEndian, b.BlockTrailer); err != nil {
		return err
	}
	return nil
}

func (b *Block) UnmarshalBinary(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &b.BlockHeader); err != nil {
		return err
	}

	dataLength := b.BlockHeader.Length - 12
	paddingLength := 4 - dataLength%4

	b.Data = make([]byte, dataLength)
	if _, err := r.Read(b.Data); err != nil {
		return err
	}

	// Remove padding if required by data length
	if paddingLength != 0 {
		padding := make([]byte, paddingLength)
		if _, err := r.Read(padding); err != nil {
			return err
		}
	}

	if err := binary.Read(r, binary.LittleEndian, &b.BlockTrailer); err != nil {
		return err
	}

	return nil
}
