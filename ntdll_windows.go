package gowindows

import (
	"fmt"

	"unsafe"

	"syscall"

	"golang.org/x/sys/windows"
)

const STATUS_SUCCESS = 0

var (
	ntdll                            *windows.DLL
	ntWow64QueryInformationProcess64 *windows.Proc
	ntWow64ReadVirtualMemory64       *windows.Proc
	ntQueryInformationProcess        *windows.Proc
	ntReadVirtualMemory              *windows.Proc
	ntRtlGetVersion                  *windows.Proc
)

func init() {
	var err error
	ntdll, err = windows.LoadDLL("ntdll.dll")
	if err == nil {
		// These need to be judged for existence, so lazy loading cannot be used
		ntWow64QueryInformationProcess64, _ = ntdll.FindProc("NtWow64QueryInformationProcess64")
		ntWow64ReadVirtualMemory64, _ = ntdll.FindProc("NtWow64ReadVirtualMemory64")
		ntQueryInformationProcess, _ = ntdll.FindProc("NtQueryInformationProcess")
		ntReadVirtualMemory, _ = ntdll.FindProc("NtReadVirtualMemory")

		ntRtlGetVersion, _ = ntdll.FindProc("RtlGetVersion")
	}
}

// Can only be used on 32-bit programs and 64-bit systems
func NtWow64QueryInformationProcess64(processHandle Handle, processInformationClass int32,
	processInformation windows.Pointer, processInformationLength uint32, returnLength *uint32) error {

	if ntWow64QueryInformationProcess64 == nil {
		return fmt.Errorf("ntWow64QueryInformationProcess64==nil")
	}

	r1, _, err := ntWow64QueryInformationProcess64.Call(uintptr(processHandle), uintptr(processInformationClass),
		uintptr(unsafe.Pointer(processInformation)), uintptr(processInformationLength),
		uintptr(unsafe.Pointer(returnLength)))

	if int(r1) < 0 {
		// If a space mismatch is found inside the function, r1 will be equal to STATUS_INFO_LENGTH_MISMATCH(0xC0000004),
		// indicates that the space does not match.
		if err != ERROR_SUCCESS {
			return err
		} else {
			return syscall.EINVAL
		}
	}

	return nil
}

//__kernel_entry NTSTATUS NtQueryInformationProcess(
//IN HANDLE               ProcessHandle,
//IN PROCESSINFOCLASS     ProcessInformationClass,
//OUT PVOID               ProcessInformation,
//IN ULONG                ProcessInformationLength,
//OUT PULONG ReturnLength OPTIONAL
//);
func NtQueryInformationProcess(processHandle Handle, processInformationClass int32,
	processInformation windows.Pointer, processInformationLength uint32, returnLength *uint32) error {

	if ntQueryInformationProcess == nil {
		return fmt.Errorf("ntQueryInformationProcess==nil")
	}

	r1, _, err := ntQueryInformationProcess.Call(uintptr(processHandle), uintptr(processInformationClass),
		uintptr(unsafe.Pointer(processInformation)), uintptr(processInformationLength),
		uintptr(unsafe.Pointer(returnLength)))

	if int(r1) < 0 {
		// If a space mismatch is found inside the function, r1 will be equal to STATUS_INFO_LENGTH_MISMATCH(0xC0000004),
		// indicates that the space does not match.

		if err != ERROR_SUCCESS {
			return err
		} else {
			return syscall.EINVAL
		}
	}

	return nil
}

//NTSTATUS (__stdcall *NtWow64ReadVirtualMemory64)(
//HANDLE ProcessHandle,
//PVOID64 BaseAddress,
//PVOID Buffer,
//ULONGLONG BufferSize,
//PULONGLONG NumberOfBytesRead
//);
func NtWow64ReadVirtualMemory64(processHandle Handle, baseAddress uint64,
	bufferData windows.Pointer, bufferSize uint64, returnSize *uint64) error {

	if ntWow64ReadVirtualMemory64 == nil {
		return fmt.Errorf("ntWow64ReadVirtualMemory64==nil")
	}

	var r1 uintptr
	var err error

	if ptrSize == 8 {
		// 64-bit program, although the theory should not be the case
		r1, _, err = ntWow64ReadVirtualMemory64.Call(uintptr(processHandle), uintptr(baseAddress),
			uintptr(unsafe.Pointer(bufferData)), uintptr(bufferSize), uintptr(unsafe.Pointer(returnSize)))
	} else {
		// 32-bit program
		r1, _, err = ntWow64ReadVirtualMemory64.Call(uintptr(processHandle),
			uintptr(baseAddress), uintptr(baseAddress>>32), uintptr(unsafe.Pointer(bufferData)),
			uintptr(bufferSize), uintptr(bufferSize>>32),
			uintptr(unsafe.Pointer(returnSize)))
	}

	if int(r1) < 0 {
		// If the read operation crosses an inaccessible area, it will fail.

		if err != ERROR_SUCCESS {
			return err
		} else {
			return syscall.EINVAL
		}
	}

	return nil
}

func ReadVirtualMemory(processHandle Handle, baseAddress uint,
	bufferData windows.Pointer, bufferSize uint, returnSize *uint) error {

	if ntReadVirtualMemory == nil {
		return fmt.Errorf("ntReadVirtualMemory==nil")
	}

	var r1 uintptr
	var err error

	// 64-bit program, although the theory should not be the case
	r1, _, err = ntReadVirtualMemory.Call(uintptr(processHandle), uintptr(baseAddress),
		uintptr(unsafe.Pointer(bufferData)), uintptr(bufferSize), uintptr(unsafe.Pointer(returnSize)))

	if int(r1) < 0 {
		// If the read operation crosses an inaccessible area, it will fail.

		if err != ERROR_SUCCESS {
			return err
		} else {
			return syscall.EINVAL
		}
	}

	return nil
}

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_osversioninfow
// Version number reference: https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ns-wdm-_osversioninfoexw
//typedef struct _OSVERSIONINFOW {
//  ULONG dwOSVersionInfoSize;
//  ULONG dwMajorVersion;
//  ULONG dwMinorVersion;
//  ULONG dwBuildNumber;
//  ULONG dwPlatformId;
//  WCHAR szCSDVersion[128];
//} OSVERSIONINFOW, *POSVERSIONINFOW, *LPOSVERSIONINFOW, RTL_OSVERSIONINFOW, *PRTL_OSVERSIONINFOW;
type OsVsersionInfow struct {
	OSVersionInfoSize ULong
	MajorVersion      ULong
	MinorVersion      ULong
	BuildNumber       ULong
	PlatformId        ULong
	CSDVersion        [128]WCHAR
}

func (v *OsVsersionInfow) GetCSDVersion() string {
	return windows.UTF16ToString(v.CSDVersion[:])
}

func (v *OsVsersionInfow) IsWindows2000OrGreater() bool {
	// win2k
	// 5.0
	if v.MajorVersion >= 5 {
		return true
	}
	return false
}
func (v *OsVsersionInfow) IsWindowsXPOrGreater() bool {
	// winxp
	// 5.1
	if v.MajorVersion > 5 || (v.MajorVersion == 5 && v.MinorVersion >= 1) {
		return true
	}
	return false
}
func (v *OsVsersionInfow) IsWindowsVistaOrGreater() bool {
	// win vista
	// 6.0
	if v.MajorVersion >= 6 {
		return true
	}
	return false
}
func (v *OsVsersionInfow) IsWindows7OrGreater() bool {
	// win 7
	// 6.1
	if v.MajorVersion > 6 || (v.MajorVersion == 6 && v.MinorVersion >= 1) {
		return true
	}
	return false
}
func (v *OsVsersionInfow) IsWindows8OrGreater() bool {
	// win 8
	// 6.2
	if v.MajorVersion > 6 || (v.MajorVersion == 6 && v.MinorVersion >= 2) {
		return true
	}
	return false
}
func (v *OsVsersionInfow) IsWindows8Point1OrGreater() bool {
	// win 8.1
	// 6.3
	if v.MajorVersion > 6 || (v.MajorVersion == 6 && v.MinorVersion >= 3) {
		return true
	}
	return false
}
func (v *OsVsersionInfow) IsWindows10OrGreater() bool {
	// win 10
	// 10
	if v.MajorVersion >= 10 {
		return true
	}
	return false
}

func (v *OsVsersionInfow) GetString() string {
	return fmt.Sprintf("%v.%v", v.MajorVersion, v.MinorVersion)
}

// This function can get the correct version number after win8
// But the behavior of RtlGetVersion before Windows 2003 is not consistent with GetVersionExW in compatibility mode,
// After Vista, in compatibility mode, its behavior and GetVersionExW return the system version of the compatible target version.
// Windows system version determines those things https://blog.csdn.net/magictong/article/details/40753519
// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-rtlgetversion
func RtlGetVersion() (*OsVsersionInfow, error) {
	if ntRtlGetVersion == nil {
		return nil, fmt.Errorf("ntRtlGetVersion==nil")
	}

	version := new(OsVsersionInfow)
	version.OSVersionInfoSize = ULong(unsafe.Sizeof(OsVsersionInfow{}))

	r1, _, e1 := ntRtlGetVersion.Call(uintptr(unsafe.Pointer(version)))
	if r1 != STATUS_SUCCESS {
		if e1 != ERROR_SUCCESS {
			return nil, e1
		} else {
			return nil, syscall.EINVAL
		}
	}
	return version, nil
}
