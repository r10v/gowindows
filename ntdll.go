package gowindows

const (
	ProcessBasicInformation = 0

	PROCESS_VM_READ = 0x0010
)

// The self-adaptive version supports 32-bit reading 32-bit, 64-bit reading 64-bit, but does not support 32-bit reading 64-bit.
type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uint
	PebBaseAddress  uint
	Reserved2       [2]uint
	UniqueProcessId uint
	Reserved3       uint
}

// 64-bit version, support 32-bit read 64-bit, 64-bit read 64-bit
type PROCESS_BASIC_INFORMATION64 struct {
	Reserved1       uint64
	PebBaseAddress  uint64
	Reserved2       [2]uint64
	UniqueProcessId uint64
	Reserved3       uint64
}
