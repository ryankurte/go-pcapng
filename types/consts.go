package types

const (
	Magic                uint32 = 0x1A2B3C4D
	MajorVersion         uint16 = 1
	MinorVersion         uint16 = 0
	SectionLengthDefault uint64 = 0xFFFFFFFFFFFFFFFF
)

const (
	BlockTypeSectionHeader  uint32 = 0x0A0D0D0A
	BlockTypeEnhancedPacket uint32 = 0x00000006
)
