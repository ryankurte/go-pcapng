package pcapng

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"encoding/binary"
	"github.com/ryankurte/go-pcapng/types"
)

func timeToSplitArr(now time.Time) []byte {
	buf := bytes.NewBuffer(nil)
	micros := now.UnixNano() / 1e3
	binary.Write(buf, binary.LittleEndian, uint32(micros>>32))
	binary.Write(buf, binary.LittleEndian, uint32(micros))
	return buf.Bytes()
}

func TestPCAPNG(t *testing.T) {

	t.Run("Encodes and decodes blocks", func(t *testing.T) {
		b1 := types.NewBlock(uint32(1337), []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee})
		data, err := b1.MarshalBinary()
		assert.Nil(t, err)

		b2 := &types.Block{}
		err = b2.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.EqualValues(t, b1, b2)
	})

	t.Run("Encodes section header blocks", func(t *testing.T) {
		b := bytes.NewBuffer(nil)

		opts := types.SectionHeaderOptions{}
		err := writeSectionHeaderBlock(b, opts)
		assert.Nil(t, err)

		expected := []byte{
			0x0A, 0x0D, 0x0D, 0x0A,
			0x1C, 0x00, 0x00, 0x00,
			0x4d, 0x3c, 0x2b, 0x1a,
			0x01, 0x00,
			0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0x1C, 0x00, 0x00, 0x00,
		}
		assert.EqualValues(t, expected, b.Bytes())
	})

	t.Run("Encodes interface description blocks", func(t *testing.T) {
		b := bytes.NewBuffer(nil)

		opts := types.InterfaceOptions{}
		err := writeInterfaceDescriptionBlock(b, 1, opts)
		assert.Nil(t, err)

		expected := []byte{
			0x01, 0x00, 0x00, 0x00,
			0x14, 0x00, 0x00, 0x00,
			0x01, 0x00,
			0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF,
			0x14, 0x00, 0x00, 0x00,
		}
		assert.EqualValues(t, expected, b.Bytes())
	})

	t.Run("Encodes enhanced packet blocks", func(t *testing.T) {
		b := bytes.NewBuffer(nil)

		data := []byte{0xaa, 0xbb, 0xcc, 0xdd}
		opts := types.EnhancedPacketOptions{}
		now := time.Now()

		err := writeEnhancedPacketBlock(b, 1, now, data, opts)
		assert.Nil(t, err)

		base := []byte{
			0x06, 0x00, 0x00, 0x00,
			0x24, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00,
			0xaa, 0xbb, 0xcc, 0xdd,
			0x24, 0x00, 0x00, 0x00,
		}
		expected := append(base[0:12], timeToSplitArr(now)...)
		expected = append(expected, base[20:]...)

		assert.EqualValues(t, expected, b.Bytes())
	})

	t.Run("Creates valid pcap files", func(t *testing.T) {
		pw, err := NewFileWriter("./test.pcapng")
		assert.Nil(t, err)

		so := types.SectionHeaderOptions{
			Comment:     "Test go-pcapng output file",
			Application: "go-pcapng",
		}
		pw.WriteSectionHeader(so)

		io := types.InterfaceOptions{
			Name:        "Test interface",
			Description: "Totally fake",
		}
		pw.WriteInterfaceDescription(types.LinkTypePrivate, io)

	})

}
