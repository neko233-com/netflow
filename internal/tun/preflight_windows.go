//go:build windows

package tun

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func checkHost() error {
	size := uint32(15000)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, 0, 0, head, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return fmt.Errorf("无法检查现有网络适配器: %w", err)
		}
		for a := head; a != nil; a = a.Next {
			if conflictsWithTUN(windows.UTF16PtrToString(a.FriendlyName), windows.UTF16PtrToString(a.Description), a.OperStatus == windows.IfOperStatusUp) {
				return errors.New("检测到其他正在使用的虚拟网卡，请先关闭其 TUN 后重试")
			}
		}
		return nil
	}
	return errors.New("网络适配器列表正在变化，请稍后重试")
}
