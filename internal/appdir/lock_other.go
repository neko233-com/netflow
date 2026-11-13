//go:build !windows && !unix

package appdir

import (
	"errors"
	"os"
)

func tryLock(*os.File) error { return errors.New("此平台不支持配置目录进程锁") }
func unlock(*os.File) error  { return nil }
