package pcapng

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/ryankurte/go-pcapng/types"
)

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

		err := writeSectionHeaderBlock(b, nil)
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
