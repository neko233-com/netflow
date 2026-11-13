//go:build windows

package sysinfo

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

func Current() (string, string) {
	v := windows.RtlGetVersion()
	name := "Windows"
	if v.ProductType == 1 && v.MajorVersion == 10 {
		if v.BuildNumber >= 22000 {
			name = "Windows 11"
		} else {
			name = "Windows 10"
		}
	}
	if v.ProductType != 1 {
		name = "Windows Server"
	}
	return name, fmt.Sprintf("%d.%d (Build %d) · %s", v.MajorVersion, v.MinorVersion, v.BuildNumber, runtime.GOARCH)
}
