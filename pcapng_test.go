package pcapng

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPCAPNG(t *testing.T) {

	t.Run("Encodes and decodes blocks", func(t *testing.T) {
		buff := bytes.NewBuffer(nil)

		b1 := NewBlock(uint32(1337), []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee})
		err := b1.MarshalBinary(buff)
		assert.Nil(t, err)

		b2 := &Block{}
		err = b2.UnmarshalBinary(buff)
		assert.Nil(t, err)

		assert.EqualValues(t, b1, b2)
	})

	t.Run("Encodes section header blocks", func(t *testing.T) {
		b := bytes.NewBuffer(nil)

		err := writeSectionHeader(b, nil)
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

}
