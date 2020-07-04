package gowindows

import (
	"syscall"
	"unicode/utf16"
	"unsafe"

	"fmt"

	"golang.org/x/sys/windows"
)

var (
	kernel32            = windows.NewLazyDLL("kernel32.dll")
	readProcessMemory   = kernel32.NewProc("ReadProcessMemory")
	isWow64Process      = kernel32.NewProc("IsWow64Process")
	createMutexW        = kernel32.NewProc("CreateMutexW")
	openMutexW          = kernel32.NewProc("OpenMutexW")
	releaseMutex        = kernel32.NewProc("ReleaseMutex")
	localFree           = kernel32.NewProc("LocalFree")
	openFileMappingW    = kernel32.NewProc("OpenFileMappingW")
	getModuleFileName   = kernel32.NewProc("GetModuleFileNameW")
	wideCharToMultiByte = kernel32.NewProc("WideCharToMultiByte")
)

//BOOL WINAPI ReadProcessMemory(
//_In_  HANDLE  hProcess,
//_In_  LPCVOID lpBaseAddress,
//_Out_ LPVOID  lpBuffer,
//_In_  SIZE_T  nSize,
//_Out_ SIZE_T  *lpNumberOfBytesRead
//);
func ReadProcessMemory(processHandle Handle, baseAddress uint,
	bufferData windows.Pointer, bufferSize uint, returnSize *uint) error {

	r1, _, err := readProcessMemory.Call(uintptr(processHandle), uintptr(baseAddress),
		uintptr(unsafe.Pointer(bufferData)), uintptr(bufferSize), uintptr(unsafe.Pointer(returnSize)))
	if r1 == 0 {
		if err != ERROR_SUCCESS {
			return err
		} else {
			return syscall.EINVAL
		}
		return err
	}
	return nil
}

// BOOL IsWow64Process(
// HANDLE hProcess,
// PBOOL  Wow64Process
// );
func IsWow64Process(hProcess Handle) (bool, error) {
	// 不存在 IsWow64Process 函数的操作系统绝对不是64位系统，那么不会是 wow64进程
	if isWow64Process.Find() != nil {
		return false, nil
	}

	is64 := 0

	r1, _, err := isWow64Process.Call(uintptr(hProcess), uintptr(unsafe.Pointer(&is64)))
	if r1 == 0 {
		return false, err
	}

	switch is64 {
	case 0:
		return false, nil
	default:
		return true, nil
	}
}

// Whether it is a 64-bit system
func Is64System() (bool, error) {
	if ptrSize == 8 {
		// 当前程序是 64 位，系统就是64位
		return true, nil
	}

	h, err := windows.GetCurrentProcess()
	if err != nil {
		return false, fmt.Errorf("windows.GetCurrentProcess, %v", err)
	}
	defer windows.CloseHandle(h)

	is64, err := IsWow64Process(Handle(h))
	if err != nil {
		return false, fmt.Errorf("IsWow64Process, %v", err)
	}

	return is64, nil
}

// Release the specified local memory object and invalidate its handle.
// https://docs.microsoft.com/zh-cn/windows/desktop/api/winbase/nf-winbase-localfree
// parameter：
// h     The handle of the local memory object. This handle is returned by the LocalAlloc or LocalReAlloc function. It is not safe to free memory allocated using GlobalAlloc.
//HLOCAL
//WINAPI
//LocalFree(
//    _Frees_ptr_opt_ HLOCAL hMem
//    );
// typedef HANDLE              HLOCAL;
func LocalFree(h windows.Pointer) error {
	r1, _, e1 := localFree.Call(uintptr(unsafe.Pointer(h)))
	if r1 != 0 {
		if e1 != ERROR_SUCCESS {
			return e1
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

//https://docs.microsoft.com/en-us/windows/desktop/api/winbase/nf-winbase-openfilemappinga
//HANDLE OpenFileMappingA(
//  DWORD  dwDesiredAccess,
//  BOOL   bInheritHandle,
//  LPCSTR lpName
//);
// windows.FILE_MAP_COPY    = 0x01
// windows.FILE_MAP_WRITE   = 0x02
// windows.FILE_MAP_READ    = 0x04
// windows.FILE_MAP_EXECUTE = 0x20
func OpenFileMapping(desiredAccess DWord, inheritHandle bool, name string) (Handle, error) {
	var _inheritHandle Bool
	switch inheritHandle {
	case true:
		_inheritHandle = 1
	case false:
		_inheritHandle = 0
	}

	_name, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}

	r1, _, e1 := openFileMappingW.Call(uintptr(desiredAccess), uintptr(_inheritHandle), uintptr(unsafe.Pointer(_name)))
	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return 0, e1
		} else {
			return 0, syscall.EINVAL
		}
	}

	return Handle(r1), nil
}

func GetModuleFileName(module HMODULE) (string, error) {
	size := DWord(syscall.MAX_PATH * 2)

	for i := 0; i < 10; i++ {
		buf := make([]uint16, size)
		r1, _, e1 := getModuleFileName.Call(uintptr(module),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(size))

		// Return 0 means function failed
		if r1 == 0 {
			if e1 != ERROR_SUCCESS {
				return "", e1
			} else {
				return "", syscall.EINVAL
			}
		}

		// Maybe there is not enough space, execute again
		if DWord(r1) >= size {
			size = size * 2
			continue
		}

		return syscall.UTF16ToString(buf), nil
	}
	return "", fmt.Errorf("there is still insufficient space for multiple expansions")
}

//TODO: The following need to be carefully checked

// The second parameter, TRUE means that the establishment holds the right to use Mutex, FALSE means that the creator does not hold the right to use Mutex
func CreateMutex(lpSecurityAttributes uintptr, bInitalOwner bool, name string) (handle Handle, err error) {
	mutexName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var _p0 uint32
	if bInitalOwner {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, e1 := syscall.Syscall(createMutexW.Addr(), 3, uintptr(lpSecurityAttributes), uintptr(_p0), uintptr(unsafe.Pointer(mutexName)))
	handle = Handle(r0)
	if handle == InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// Open an existing named mutex.
// dwDesiredAccess	Access to mutex objects. The use of mutex locks only requires SYNCHRONIZE access; to change the security of mutex locks, specify MUTEX_ALL_ACCESS. If the security descriptor of the specified object does not allow access to the calling process, the function will fail. For a list of access rights, please refer to [Synchronization Object Security and Access Rights] (https://docs.microsoft.com/zh-cn/windows/win32/sync/synchronization-object-security-and-access-rights) .
// bInitalOwner		If this value is TRUE, the process created by this process will inherit the handle. Otherwise, the process will not inherit this handle.
// name				The name of the mutex to be opened. The name comparison is case sensitive.
// https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-openmutexw
// https://msdn.microsoft.com/en-us/windows/desktop/ms684315
func OpenMutex(dwDesiredAccess DWord, bInitalOwner bool, name string) (handle Handle, err error) {
	mutexName, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var _p0 uint32
	if bInitalOwner {
		_p0 = 1
	} else {
		_p0 = 0
	}
	r0, _, e1 := syscall.Syscall(openMutexW.Addr(), 3, uintptr(dwDesiredAccess), uintptr(_p0), uintptr(unsafe.Pointer(mutexName)))
	handle = Handle(r0)
	if handle == InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

func ReleaseMutex(handle Handle) (err error) {
	releaseMutex.Call(uintptr(handle))
	return nil
}

//     syscall.WaitForSingleObject(mu,syscall.INFINITE)

// Returns nil only once, or err if it already exists
func One(name string) (handle Handle, rerr error) {
	h, err := CreateMutex(0, false, name)
	if err != nil {
		return 0, fmt.Errorf("failed to create semaphore, %v", err)
	}
	lasterr := syscall.GetLastError()
	if lasterr == syscall.ERROR_ALREADY_EXISTS {
		syscall.CloseHandle(Handle(h))
		return 0, fmt.Errorf("an instance has been run")
	}

	event, err := syscall.WaitForSingleObject(Handle(h), 0)
	// WAIT_OBJECT_0   	mutex is not held or released safely
	// WAIT_ABANDONED	The last thread or process holding mutex terminated abnormally
	if err == nil && (event == syscall.WAIT_OBJECT_0 || event == syscall.WAIT_ABANDONED) {
		// 持有信号量成功
		return h, nil
	}

	syscall.CloseHandle(Handle(h))
	return 0, fmt.Errorf("the semaphore is already held by other programs")
}

func OneDefer(h Handle) {
	ReleaseMutex(h)
	syscall.CloseHandle(Handle(h))
}

// https://docs.microsoft.com/en-us/windows/desktop/api/stringapiset/nf-stringapiset-widechartomultibyte
// int WideCharToMultiByte(
//  UINT                               CodePage,
//  DWORD                              dwFlags,
//  _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
//  int                                cchWideChar,
//  LPSTR                              lpMultiByteStr,
//  int                                cbMultiByte,
//  LPCCH                              lpDefaultChar,
//  LPBOOL                             lpUsedDefaultChar
//);
func WideCharToMultiByte(codePage uint32, dwFlags DWord, wchar *uint16, nwchar int32, str *byte, nstr int32, lpDefaultChar *byte, pfUsedDefaultChar *bool) (nwrite int32, err error) {
	r1, _, e1 := wideCharToMultiByte.Call(
		uintptr(codePage),
		uintptr(dwFlags),
		uintptr(unsafe.Pointer(wchar)),
		uintptr(nwchar),
		uintptr(unsafe.Pointer(str)),
		uintptr(nstr),
		uintptr(unsafe.Pointer(lpDefaultChar)),
		uintptr(unsafe.Pointer(pfUsedDefaultChar)),
	)

	if r1 == 0 {
		if e1 != ERROR_SUCCESS {
			return 0, e1
		} else {
			return 0, syscall.EINVAL
		}
	}

	return int32(r1), nil
}

type CodePage uint32

const (
	//  Code Page Default Values.
	//
	CP_ACP        CodePage = 0  // default to ANSI code page
	CP_OEMCP      CodePage = 1  // default to OEM  code page
	CP_MACCP      CodePage = 2  // default to MAC  code page
	CP_THREAD_ACP CodePage = 3  // current thread's ANSI code page
	CP_SYMBOL     CodePage = 42 // SYMBOL translations

	CP_UTF7 CodePage = 65000 // UTF-7 translation
	CP_UTF8 CodePage = 65001 // UTF-8 translation
)

type WideChar2MultiByteFlags DWord

const (
	WC_COMPOSITECHECK WideChar2MultiByteFlags = 0x00000200 // convert composite to precomposed
	WC_DISCARDNS      WideChar2MultiByteFlags = 0x00000010 // discard non-spacing chars
	WC_SEPCHARS       WideChar2MultiByteFlags = 0x00000020 // generate separate chars
	WC_DEFAULTCHAR    WideChar2MultiByteFlags = 0x00000040 // replace w/ default char
	//#if (WINVER >= 0x0600)
	// 	Windows Vista and later: If an invalid input character is encountered, it fails (by returning 0 and setting the last error code to ERROR_NO_UNICODE_TRANSLATION). You can retrieve the last error code by calling GetLastError. If this flag is not set, the function replaces the illegal sequence (coded according to the specified code page) with U + FFFD, and succeeds by returning the length of the converted string. Please note that this flag only applies when the code page is specified as CP_UTF8 or 54936. It cannot be used with other code page values.
	WC_ERR_INVALID_CHARS WideChar2MultiByteFlags = 0x00000080 // error for invalid chars
	//#endif

	//#if(WINVER >= 0x0500)
	// Convert Unicode characters that cannot be directly converted into corresponding multibyte characters into the default characters specified by lpDefaultChar. In other words, if you convert Unicode to multibyte characters and then convert back, you may not necessarily get the same Unicode character, because the default character may be used during this period. This option can be used alone or with other options.
	// For strings that require authentication, such as files, resources, and user names, applications should always use the WC_NO_BEST_FIT_CHARS flag. This flag prevents the function from mapping characters to characters that look similar but have very different semantics. In some cases, semantic changes may be extreme. For example, the "∞" (infinity) symbol is mapped to 8 (8) in some code pages.
	WC_NO_BEST_FIT_CHARS WideChar2MultiByteFlags = 0x00000400 // do not use best fit chars
	//#endif /* WINVER >= 0x0500 */
)

// wchar(UTF-16LE) converts to char
// If the input does not contain \0, the output will not.
func WideChar2MultiByte(codePage CodePage, dwFlags WideChar2MultiByteFlags, wchar []uint16, lpDefaultChar *byte, pfUsedDefaultChar *bool) ([]byte, error) {
	if len(wchar) == 0 {
		return nil, nil
	}

	n, err := WideCharToMultiByte(uint32(codePage), DWord(dwFlags), &wchar[0], int32(len(wchar)), nil, 0, lpDefaultChar, pfUsedDefaultChar)
	if err != nil {
		return nil, err
	}

	out := make([]byte, n)

	n, err = WideCharToMultiByte(uint32(codePage), DWord(dwFlags), &wchar[0], int32(len(wchar)), &out[0], int32(len(out)), lpDefaultChar, pfUsedDefaultChar)
	if err != nil {
		return nil, err
	}

	return out[:n], nil
}

type MultiByteToWideCharFlags DWord

const (
	//
	//  MBCS and Unicode Translation Flags.
	//

	// Default; do not use with MB_COMPOSITE. Always use pre-combined characters, that is, characters with a single character value as basic characters or non-spacing character combinations. For example, in the character è, e is a basic character, and accented characters are non-sliding characters. If a single Unicode code point is defined for a character, the application should use it instead of separate basic and non-spacing characters. For example, Ä is represented by a single Unicode code point LATIN CAPITAL LETTER A WITH DIAERESIS (U + 00C4).
	MB_PRECOMPOSED MultiByteToWideCharFlags = 0x00000001 // use precomposed chars

	// Always use decomposed characters, that is, characters that have different code point values for the base character and one or more non-spacing characters. For example, Ä is represented by A +¨: LATIN CAPITAL LETTER A (U + 0041) + COMBINING DIAERESIS (U + 0308). Please note that this flag cannot be used with MB_PRECOMPOSED.
	MB_COMPOSITE MultiByteToWideCharFlags = 0x00000002 // use composite chars

	// Use glyph characters instead of control characters.
	MB_USEGLYPHCHARS MultiByteToWideCharFlags = 0x00000004 // use glyph chars, not ctrl chars

	// If an invalid input character is encountered, it fails.
	//Starting from Windows Vista, if the application does not set this flag, the function will not delete the illegal code point, but use U + FFFD to replace the illegal sequence (according to the specified code page encoding).
	//
	//Windows 2000 with SP4 and higher, Windows XP: If this flag is not set, the function will silently delete illegal code points. The call to GetLastError returns ERROR_NO_UNICODE_TRANSLATION.
	MB_ERR_INVALID_CHARS MultiByteToWideCharFlags = 0x00000008 // error for invalid chars
)

// convert char to wchar(UTF-16LE)
// If the input does not contain \0, the output will not.
// https://docs.microsoft.com/en-us/windows/desktop/api/stringapiset/nf-stringapiset-multibytetowidechar
func MultiByte2WideChar(codePage CodePage, dwFlags MultiByteToWideCharFlags, str []byte) ([]uint16, error) {
	if len(str) == 0 {
		return nil, nil
	}

	n, err := windows.MultiByteToWideChar(uint32(codePage), uint32(dwFlags), &str[0], int32(len(str)), nil, 0)
	if err != nil {
		return nil, err
	}

	out := make([]uint16, n)
	n, err = windows.MultiByteToWideChar(uint32(codePage), uint32(dwFlags), &str[0], int32(len(str)), &out[0], int32(len(out)))
	if err != nil {
		return nil, err
	}

	return out[:n], nil
}

// Internally implemented using windows api
// The main purpose is actually to convert go string to windows local encoding
func Str2MultiByte(codePage CodePage, dwFlags WideChar2MultiByteFlags, str string, lpDefaultChar *byte, pfUsedDefaultChar *bool) ([]byte, error) {
	utf16Data := utf16.Encode([]rune(str))

	return WideChar2MultiByte(codePage, dwFlags, utf16Data, lpDefaultChar, pfUsedDefaultChar)
}

// Internally implemented using windows api
// The main purpose is actually to convert Windows local encoding to go string
func MultiByte2Str(codePage CodePage, dwFlags MultiByteToWideCharFlags, str []byte) (string, error) {
	utf16Data, err := MultiByte2WideChar(codePage, dwFlags, str)
	if err != nil {
		return "", err
	}

	return string(utf16.Decode(utf16Data)), nil
}

var WaitForSingleObject = windows.WaitForSingleObject
