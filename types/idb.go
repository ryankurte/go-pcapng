package types

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// BlockTypeInterfaceDescription is the type code for an interface description block
	BlockTypeInterfaceDescription uint32 = 0x00000001
	// SnapshotLengthDefault default snapshot length
	SnapshotLengthDefault uint32 = 0xFFFFFFFF
)

// Interface block option codes
const (
	OptionCodeInterfaceName        uint16 = 2
	OptionCodeInterfaceDescription uint16 = 3
	OptionCodeInterfaceV4Addr      uint16 = 4
	OptionCodeInterfaceV6Addr      uint16 = 5
	OptionCodeInterfaceMACAddr     uint16 = 6
	OptionCodeInterfaceEUIAddr     uint16 = 7
	OptionCodeInterfaceSpeed       uint16 = 8
	OptionCodeInterfaceTSResol     uint16 = 9
	OptionCodeInterfaceTSZone      uint16 = 10
	OptionCodeInterfaceFilter      uint16 = 11
	OptionCodeInterfaceOS          uint16 = 12
	OptionCodeInterfaceFCSLen      uint16 = 13
	OptionCodeInterfaceTSOffset    uint16 = 14
)

// InterfaceDescriptionHeader statically sized header portion of an InterfaceDescription
type InterfaceDescriptionHeader struct {
	LinkType       uint16
	Reserved       uint16
	SnapshotLength uint32
}

// InterfaceDescription is the container for information describing an interface on which packet data is captured.
type InterfaceDescription struct {
	InterfaceDescriptionHeader
	Options Options
}

// InterfaceOptions options that can be set for an interface
type InterfaceOptions struct {
	Name        string
	Description string
	IPs         []struct {
		net.IP
		net.IPMask
	}
	MAC net.HardwareAddr
	EUI net.HardwareAddr
}

// NewInterfaceDescription creates an interface description with the provided options
func NewInterfaceDescription(linkType uint16, options InterfaceOptions) (*InterfaceDescription, error) {
	opts := Options{}

	if options.Name != "" {
		opts = append(opts, *NewOption(OptionCodeInterfaceName, []byte(options.Name)))
	}

	if options.Description != "" {
		opts = append(opts, *NewOption(OptionCodeInterfaceName, []byte(options.Description)))
	}

	if options.MAC.String() != "" {
		opts = append(opts, *NewOption(OptionCodeInterfaceMACAddr, []byte(options.MAC.String())))
	}

	if options.EUI.String() != "" {
		opts = append(opts, *NewOption(OptionCodeInterfaceEUIAddr, []byte(options.EUI.String())))
	}

	for _, ip := range options.IPs {
		str := ""
		for i := range ip.IP {
			str += fmt.Sprintf("%d ", ip.IP[i])
		}
		for i := range ip.IPMask {
			str += fmt.Sprintf("%d ", ip.IPMask[i])
		}

		if len(ip.IP) == 4 {
			opts = append(opts, *NewOption(OptionCodeInterfaceV4Addr, []byte(str)))
		} else if len(ip.IP) == 16 {
			opts = append(opts, *NewOption(OptionCodeInterfaceV6Addr, []byte(str)))
		} else {
			return nil, fmt.Errorf("Malformed IP address: %+v", ip)
		}
	}

	return &InterfaceDescription{
		InterfaceDescriptionHeader: InterfaceDescriptionHeader{
			LinkType:       linkType,
			Reserved:       0,
			SnapshotLength: SnapshotLengthDefault,
		},
		Options: opts,
	}, nil
}

// MarshalBinary encodes a InterfaceDescription to a byte array
func (idb *InterfaceDescription) MarshalBinary() ([]byte, error) {
	buff := bytes.NewBuffer(nil)

	opts, err := idb.Options.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if err := binary.Write(buff, binary.LittleEndian, &idb.InterfaceDescriptionHeader); err != nil {
		return nil, err
	}

	if _, err := buff.Write(opts); err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}

// UnmarshalBinary decodes a SectionHeader from a byte array
func (idb *InterfaceDescription) UnmarshalBinary(d []byte) error {
	buff := bytes.NewBuffer(d)

	if err := binary.Read(buff, binary.LittleEndian, &idb.InterfaceDescriptionHeader); err != nil {
		return err
	}

	if buff.Len() > 0 {
		optd := make([]byte, buff.Len())
		if _, err := buff.Read(optd); err != nil {
			return err
		}
		if err := idb.Options.UnmarshalBinary(optd); err != nil {
			return err
		}
	}

	return nil
}
