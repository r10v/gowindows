package gowindows

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"reflect"
)

const ptrSize = unsafe.Sizeof(uintptr(0))

const ERROR_SUCCESS syscall.Errno = 0

const INVALID_HANDLE_VALUE Handle = Handle(^uintptr(0))

const NO_ERROR = 0

const ERROR_IO_PENDING = 997

const INFINITE = syscall.INFINITE

// Convert to []byte slice
// Note, please ensure that the memory reference, according to the documentation, reflect.SliceHeader will not save the data pointer, may be garbage collected.
// This implementation of C.GoBytes is in the cgo C library, but C.GoBytes is an implementation of copying memory, and memory sharing cannot be used.
func ToBytes(data uintptr, len, cap int) []byte {
	var o []byte
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&o)))
	sliceHeader.Cap = cap
	sliceHeader.Len = len
	sliceHeader.Data = data
	return o
}

// Change the slice size
// The length of the array in some windows structures is uncertain, this function can force the conversion of the slice of the specified length
// Input value: v must be a pointer to slice
func ChangeSliceSize(v interface{}, Len, Cap int) error {
	if reflect.TypeOf(v).Kind() != reflect.Ptr {
		return fmt.Errorf("v必须是切片的指针。")
	}

	elem := reflect.ValueOf(v).Elem()
	if elem.Kind() != reflect.Slice {
		return fmt.Errorf("v必须是切片的指针。")
	}

	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(elem.UnsafeAddr())))
	sliceHeader.Cap = Cap
	sliceHeader.Len = Len
	return nil
}

type Word = uint16

type Bool = int32

type DWord = uint32
type ULong = uint32

type HMODULE = Handle

type WCHAR = wchar_t
type wchar_t = uint16

type Overlapped = windows.Overlapped

// https://blog.csdn.net/ixsea/article/details/7272909
type HRESULT uint32

func (h HRESULT) IsSucceeded() bool {
	return uint32(h)&(uint32(1)<<31) == 0
}

type CallError struct {
	r1 DWord
}

func newCallError(r1 DWord) error {
	return &CallError{r1: r1}
}

func (e *CallError) Error() string {
	return fmt.Sprintf("r1:%X", e.r1)
}
