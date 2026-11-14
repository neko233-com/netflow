package backup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
)

// Native backups have at most 4097 entries and do not require ZIP64. Check
// the central directory before archive/zip allocates one object per entry.
func validateZipDirectory(ctx context.Context, file *os.File, size int64) error {
	const maxDirectoryBytes = 32 << 20
	const maxArchiveBytes = maxTotal + maxDirectoryBytes
	if size < 22 || size > maxArchiveBytes {
		return errors.New("backup archive size is invalid")
	}
	tailSize := int64(22 + 65535)
	if size < tailSize {
		tailSize = size
	}
	tail := make([]byte, tailSize)
	if _, err := file.ReadAt(tail, size-tailSize); err != nil {
		return err
	}
	index := -1
	for i := len(tail) - 22; i >= 0; i-- {
		if bytes.Equal(tail[i:i+4], []byte{'P', 'K', 5, 6}) && i+22+int(binary.LittleEndian.Uint16(tail[i+20:i+22])) == len(tail) {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("backup ZIP directory is missing")
	}
	end := tail[index:]
	disk, dirDisk := binary.LittleEndian.Uint16(end[4:6]), binary.LittleEndian.Uint16(end[6:8])
	onDisk, count := binary.LittleEndian.Uint16(end[8:10]), binary.LittleEndian.Uint16(end[10:12])
	dirSize, offset := binary.LittleEndian.Uint32(end[12:16]), binary.LittleEndian.Uint32(end[16:20])
	endOffset := size - tailSize + int64(index)
	if disk != 0 || dirDisk != 0 || onDisk != count || count > maxFiles+1 || count == 0xffff || dirSize == 0xffffffff || offset == 0xffffffff || dirSize > maxDirectoryBytes || int64(offset)+int64(dirSize) != endOffset {
		return errors.New("backup ZIP directory exceeds limits or uses an unsupported format")
	}
	section := io.NewSectionReader(file, int64(offset), int64(dirSize))
	var header [46]byte
	for i := 0; i < int(count); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := io.ReadFull(section, header[:]); err != nil || !bytes.Equal(header[:4], []byte{'P', 'K', 1, 2}) {
			return errors.New("backup ZIP directory is invalid")
		}
		length := int64(binary.LittleEndian.Uint16(header[28:30])) + int64(binary.LittleEndian.Uint16(header[30:32])) + int64(binary.LittleEndian.Uint16(header[32:34]))
		if _, err := io.CopyN(io.Discard, section, length); err != nil {
			return errors.New("backup ZIP directory is truncated")
		}
	}
	if current, err := section.Seek(0, io.SeekCurrent); err != nil || current != int64(dirSize) {
		return errors.New("backup ZIP directory entry count is invalid")
	}
	return nil
}
