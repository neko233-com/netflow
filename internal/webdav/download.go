package webdav

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// Limit downloads to the exact names produced by Upload; this rejects path
// traversal and prevents a caller from selecting arbitrary server resources.
var remoteNamePattern = regexp.MustCompile(`^netflow-[0-9]{8}-[0-9]{6}-[0-9a-f]{32}\.zip$`)

func ValidRemoteName(name string) bool { return remoteNamePattern.MatchString(name) }

// Download streams at most MaxArchiveBytes to the caller's private file.
// The caller must validate the complete archive before restoring it.
func (c Client) Download(ctx context.Context, credentials Credentials, name string, destination io.Writer) error {
	if ctx == nil || destination == nil || !ValidRemoteName(name) {
		return errors.New("invalid WebDAV backup name")
	}
	u, user, password, err := validate(credentials)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resourceURL(u, name), nil)
	if err != nil {
		return errors.New("invalid WebDAV request")
	}
	if user != "" || password != "" {
		req.SetBasicAuth(user, password)
	}
	client, closeIdle := c.httpClient()
	defer closeIdle()
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("WebDAV download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("WebDAV download failed (HTTP %d)", resp.StatusCode)
	}
	if resp.ContentLength > MaxArchiveBytes {
		return errors.New("remote backup exceeds size limit")
	}
	n, err := io.Copy(destination, io.LimitReader(resp.Body, MaxArchiveBytes+1))
	if err != nil || n <= 0 || n > MaxArchiveBytes || (resp.ContentLength >= 0 && resp.ContentLength != n) {
		return errors.New("WebDAV download was incomplete or too large")
	}
	return nil
}
