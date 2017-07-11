package types

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTypes(t *testing.T) {

	t.Run("Encodes and decodes blocks", func(t *testing.T) {
		b1 := NewBlock(uint32(1337), []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee})
		data, err := b1.MarshalBinary()
		assert.Nil(t, err)

		b2 := &Block{}
		err = b2.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.EqualValues(t, b1, b2)
	})

	t.Run("Fails parsing invalid blocks", func(t *testing.T) {
		b1 := NewBlock(uint32(1337), []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee})
		b1.BlockTrailer.Length = 30
		data, err := b1.MarshalBinary()
		assert.Nil(t, err)

		b2 := &Block{}
		err = b2.UnmarshalBinary(data)
		assert.NotNil(t, err)
	})

	t.Run("Reads blocks from streams", func(t *testing.T) {
		t.SkipNow()
	})

	t.Run("Encodes and decodes options", func(t *testing.T) {
		opts1 := Options{*NewCommentOption("Test Comment")}
		data, err := opts1.MarshalBinary()
		assert.Nil(t, err)

		opts2 := Options{}
		err = opts2.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.EqualValues(t, opts1, opts2)
	})

	t.Run("Encodes and decodes SectionHeaders", func(t *testing.T) {
		opts1 := Options{*NewCommentOption("Test Comment")}
		sh1 := NewSectionHeader(opts1)
		data, err := sh1.MarshalBinary()

		sh2 := &SectionHeader{}
		err = sh2.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.EqualValues(t, sh1, sh2)
	})

}
