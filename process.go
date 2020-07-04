package gowindows

// Standard PEB structure
// 32-bit program @32-bit system or 64-bit program @64-bit system
// https://docs.microsoft.com/zh-cn/windows/desktop/api/winternl/ns-winternl-_peb
// http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
//typedef struct _PEB {
//BYTE                          Reserved1[2];
//BYTE                          BeingDebugged;
//BYTE                          Reserved2[1];
//PVOID                         Reserved3[2];
//PPEB_LDR_DATA                 Ldr;
//PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
//PVOID                         Reserved4[3];
//PVOID                         AtlThunkSListPtr;
//PVOID                         Reserved5;
//ULONG                         Reserved6;
//PVOID                         Reserved7;
//ULONG                         Reserved8;
//ULONG                         AtlThunkSListPtr32;
//PVOID                         Reserved9[45];
//BYTE                          Reserved10[96];
//PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//BYTE                          Reserved11[128];
//PVOID                         Reserved12[1];
//ULONG                         SessionId;
//} PEB, *PPEB;
type PEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              [1]byte
	Reserved3              [2]uint
	Ldr                    uint
	ProcessParameters      uint
	Reserved4              [3]uint
	AtlThunkSListPtr       uint
	Reserved5              uint
	Reserved6              uint32
	Reserved7              uint
	Reserved8              uint32
	AtlThunkSListPtr32     uint32
	Reserved9              [45]uint
	Reserved10             [96]byte
	PostProcessInitRoutine uint
	Reserved11             [128]byte
	Reserved12             [1]uint
	SessionId              uint32
}

// 64-bit PEB structure
// Under the 32-bit program, it can also be consistent with the 64-bit PEB structure, which solves the problem of inconsistent 32-bit and 64-bit alignment.
// https://docs.microsoft.com/zh-cn/windows/desktop/api/winternl/ns-winternl-_peb
// http://terminus.rewolf.pl/terminus/structures/ntdll/_PEB_combined.html
//typedef struct _PEB {
//BYTE Reserved1[2];
//BYTE BeingDebugged;
//BYTE Reserved2[21];
//PPEB_LDR_DATA LoaderData;
//PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
//BYTE Reserved3[520];
//PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
//BYTE Reserved4[136];
//ULONG SessionId;
//} PEB;
type PEB64 struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              [21]byte
	Ldr                    uint64
	ProcessParameters      uint64
	Reserved3              [520]byte
	PostProcessInitRoutine uint64
	Reserved4              [136]byte
	SessionId              uint32
	_                      uint32 // 保证 32 位下长度和64位一致，64位最后会有个 uint32 的空白用于对齐
}

// https://docs.microsoft.com/zh-cn/windows/desktop/api/winternl/ns-winternl-_rtl_user_process_parameters
//typedef struct _RTL_USER_PROCESS_PARAMETERS {
//BYTE           Reserved1[16];
//PVOID          Reserved2[10];
//UNICODE_STRING ImagePathName;
//UNICODE_STRING CommandLine;
//} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
type RTL_USER_PROCESS_PARAMETERS struct {
	Reserved1     [16]byte
	Reserved2     [10]uint
	ImagePathName UNICODE_STRING
	CommandLine   UNICODE_STRING
}
type RTL_USER_PROCESS_PARAMETERS64 struct {
	Reserved1     [16]byte
	Reserved2     [10]uint64
	ImagePathName UNICODE_STRING64
	CommandLine   UNICODE_STRING64
}

// https://docs.microsoft.com/en-us/windows/desktop/winprog/windows-data-types
//typedef struct _UNICODE_STRING {
//USHORT  Length;
//USHORT  MaximumLength;
//PWSTR  Buffer;
//} UNICODE_STRING;
type UNICODE_STRING struct {
	Length        uint16 // The byte length of the buffer, excluding the terminator "NULL"
	MaximumLength uint16

	// Pointer to a 16-bit Unicode string ending in null. For more information, see [Character Set Used by Fonts] (https://msdn.microsoft.com/library/windows/desktop/dd183415).
	Buffer uint
}
type UNICODE_STRING64 struct {
	Length        uint16 // The byte length of the buffer, excluding the terminator "NULL"
	MaximumLength uint16
	_             [4]byte // Force 64-bit alignment under 32-bit

	// Pointer to a 16-bit Unicode string ending in null. For more information, see [Character Set Used by Fonts] (https://msdn.microsoft.com/library/windows/desktop/dd183415).
	Buffer uint64
}
