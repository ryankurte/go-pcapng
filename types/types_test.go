package types

import (
	"github.com/stretchr/testify/assert"
	"net"
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
		assert.Nil(t, err)

		sh2 := &SectionHeader{}
		err = sh2.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.EqualValues(t, sh1, sh2)
	})

	t.Run("Encodes and decodes InterfaceDescriptions", func(t *testing.T) {
		name := "Test Name"
		desc := "Test Description"
		mac, _ := net.ParseMAC("00:01:02:03:04:05")
		eui, _ := net.ParseMAC("02:34:56:FF:FE:78:9A:BC")
		v4, v4mask := net.ParseIP("192.168.1.1"), net.IPv4Mask(255, 255, 255, 0)
		v6 := net.ParseIP("2001:0db8:85a3:08d3:1319:8a2e:0370:7344")

		opts := InterfaceOptions{
			Name:        name,
			Description: desc,
			MAC:         mac,
			EUI:         eui,
			IPs: []net.IPNet{
				net.IPNet{IP: v4, Mask: v4mask},
				net.IPNet{IP: v6, Mask: net.CIDRMask(64, 128)},
			},
			Speed: 52000,
		}

		idb1, err := NewInterfaceDescription(1, opts)
		assert.Nil(t, err)
		data, err := idb1.MarshalBinary()
		assert.Nil(t, err)

		idb2 := &InterfaceDescription{}
		err = idb2.UnmarshalBinary(data)
		assert.Nil(t, err)

		assert.EqualValues(t, idb1, idb2)
		assert.EqualValues(t, 7, len(idb2.Options))

		options := []string{
			name,
			desc,
			"00 01 02 03 04 05",
			"02 34 56 ff fe 78 9a bc",
			"192 168 1 1 255 255 255 0",
			"20 01 0d b8 85 a3 08 d3 13 19 8a 2e 03 70 73 44 40",
			"52000",
		}

		for i, o := range options {
			assert.EqualValues(t, o, string(idb2.Options[i].Value), "Option %d error", i)
		}

	})

}
