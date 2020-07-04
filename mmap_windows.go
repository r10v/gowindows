package gowindows

import "C"
import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Create no-file named memory share
func CreateMmap(name string, size uint32, write bool) (*Mmap, error) {
	return CreateMmapWithSecurityDescriptor(name, size, write, "")
}

// Create with specified permissions
// The main purpose is service creation, ordinary users have the right to access, and UAC is no problem.
// securityDescriptor "D:P(A;OICI;GWGR;;;SY)(A;OICI;GWGR;;;BA)(A;OICI;GWGR;;;IU)(A;OICI;GWGR;;;RC )"
//"D: P (A; OICI; GA;;; SY) (A; OICI; GA;;; BA) (A; OICI; GR;;; IU)" specifies DACL. D: P indicates that this is a DACL (not SACL...you rarely use SACL), followed by several ACE strings that control who can access. Each one is A (allowed) and allows objects and contains inheritance (OICI). The first grants all access rights (GA-grant all) to the system (SY) and the administrator (BA, built-in administrator). The last time read (GR) is granted to interactive users (IU), these users actually log into the session.
// https://blog.csdn.net/qinlicang/article/details/5538307
// https://stackoverflow.com/questions/898683/how-to-share-memory-between-services-and-user-processes
func CreateMmapWithSecurityDescriptor(name string, size uint32, write bool, securityDescriptor string) (*Mmap, error) {
	if size == 0 {
		return nil, fmt.Errorf("size==0")
	}

	cancel := false

	namePtr, _ := windows.UTF16PtrFromString(name)

	prot := uint32(syscall.PAGE_READONLY)
	if write {
		prot = syscall.PAGE_READWRITE
	}

	var security *windows.SecurityAttributes
	if len(securityDescriptor) != 0 {
		security = new(windows.SecurityAttributes)
		err := ConvertStringSecurityDescriptorToSecurityDescriptor(securityDescriptor, SDDL_REVISION_1, (*SecurityDescriptor)(unsafe.Pointer(&security.SecurityDescriptor)), nil)
		if err != nil {
			return nil, fmt.Errorf("ConvertStringSecurityDescriptorToSecurityDescriptor, %v", err)
		}
		defer func() {
			LocalFree(windows.Pointer(unsafe.Pointer(security.SecurityDescriptor)))
		}()
	}

	fileHandle, err := windows.CreateFileMapping(windows.Handle(INVALID_HANDLE_VALUE),
		security, prot, 0, uint32(size), namePtr)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping, %v", err)
	}
	defer func() {
		if cancel {
			windows.CloseHandle(fileHandle)
		}
	}()

	access := uint32(windows.FILE_MAP_READ)
	if write {
		access = windows.FILE_MAP_WRITE
	}
	addr, err := windows.MapViewOfFile(fileHandle, access, 0,
		0, uintptr(size))
	if err != nil {
		cancel = true
		return nil, fmt.Errorf("MapViewOfFile, %v", err)
	}

	m := &Mmap{fileHandle: Handle(fileHandle), addr: addr, size: int(size)}

	runtime.SetFinalizer(m, (*Mmap).Close)

	return m, nil
}

// Turn on no-name memory sharing
// Although the MapViewOfFile function allows 0, it cannot be converted to []byte when size==0, so size == 0 is not supported.
func OpenMmap(name string, size uint32, write bool) (*Mmap, error) {
	if size == 0 {
		return nil, fmt.Errorf("size==0")
	}

	cancel := false

	access := uint32(windows.FILE_MAP_READ)
	if write {
		access = windows.FILE_MAP_WRITE
	}
	fileHandle, err := OpenFileMapping(DWord(access), false, name)
	if err != nil {
		return nil, fmt.Errorf("OpenFileMapping, %v", err)
	}
	defer func() {
		if cancel {
			windows.CloseHandle(windows.Handle(fileHandle))
		}
	}()

	addr, err := windows.MapViewOfFile(windows.Handle(fileHandle), uint32(access), 0,
		0, uintptr(size))
	if err != nil {
		cancel = true
		return nil, fmt.Errorf("MapViewOfFile, %v", err)
	}

	m := &Mmap{fileHandle: fileHandle, addr: addr, size: int(size)}

	runtime.SetFinalizer(m, (*Mmap).Close)

	return m, nil
}

// close and release
func (m *Mmap) Close() error {
	if m.addr != uintptr(0) {
		err := windows.UnmapViewOfFile(uintptr(m.addr))
		if err != nil {
			return fmt.Errorf("UnmapViewOfFile, %v", err)
		}
		m.size = 0
		m.addr = uintptr(0)
	}

	if m.fileHandle != 0 {
		err := windows.CloseHandle(windows.Handle(m.fileHandle))
		if err != nil {
			return fmt.Errorf("CloseHandle, %v", err)
		}
		m.size = 0
		m.fileHandle = 0
	}

	runtime.KeepAlive(m)

	// Test to ensure that runtime.SetFinalizer is working properly
	// fmt.Println("mmap.close()")
	return nil
}
