package appdir

import (
	"errors"
	"os"

	"github.com/neko233-com/netflow/internal/safepath"
)

var ErrAlreadyRunning = errors.New("此配置目录已有运行中的 NetFlow")

// Lock owns a process-wide operating-system lock; closing the file or process
// releases it, so an interrupted run cannot leave a stale lock behind.
type Lock struct{ file *os.File }

func Acquire(dir string) (*Lock, error) {
	if dir == "" {
		return nil, errors.New("配置目录为空")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	file, err := safepath.OpenLock(dir, ".netflow.lock")
	if err != nil {
		return nil, err
	}
	return lockFile(file)
}

// AcquireRoot locks an already pinned directory without resolving its path again.
func AcquireRoot(root *os.Root) (*Lock, error) {
	file, err := safepath.OpenLockAt(root, ".netflow.lock")
	if err != nil {
		return nil, err
	}
	return lockFile(file)
}

func lockFile(file *os.File) (*Lock, error) {
	if err := tryLock(file); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Lock{file: file}, nil
}

func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unlock(l.file)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(err, closeErr)
}
