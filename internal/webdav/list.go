package webdav

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

const maxListBytes = 4 << 20
const maxListResponses = 4096
const maxListNames = 512

type davResponse struct {
	Href      string `xml:"DAV: href"`
	PropStats []struct {
		Status string `xml:"DAV: status"`
		Prop   struct {
			ResourceType struct {
				Collection *struct{} `xml:"DAV: collection"`
			} `xml:"DAV: resourcetype"`
		} `xml:"DAV: prop"`
	} `xml:"DAV: propstat"`
}

// List returns only generated backup filenames from the requested collection.
// Untrusted hrefs are never fetched and cross-origin or nested hrefs are ignored.
func (c Client) List(ctx context.Context, credentials Credentials) ([]string, error) {
	if ctx == nil {
		return nil, errors.New("invalid WebDAV request")
	}
	u, user, password, err := validate(credentials)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(u.Path, "/") {
		escaped := u.EscapedPath() + "/"
		u.Path += "/"
		u.RawPath = escaped
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body := strings.NewReader(`<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>`)
	req, err := http.NewRequestWithContext(ctx, "PROPFIND", u.String(), body)
	if err != nil {
		return nil, errors.New("invalid WebDAV request")
	}
	req.Header.Set("Depth", "1")
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")
	if user != "" || password != "" {
		req.SetBasicAuth(user, password)
	}
	client, closeIdle := c.httpClient()
	defer closeIdle()
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("WebDAV listing failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		return nil, fmt.Errorf("WebDAV listing failed (HTTP %d)", resp.StatusCode)
	}
	if resp.ContentLength > maxListBytes {
		return nil, errors.New("WebDAV listing exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil || len(data) > maxListBytes {
		return nil, errors.New("WebDAV listing is incomplete or too large")
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	seen := make(map[string]bool)
	var names []string
	responses := 0
	rootOpened, rootClosed := false, false
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("WebDAV listing is invalid")
		}
		if end, ok := token.(xml.EndElement); ok && end.Name.Space == "DAV:" && end.Name.Local == "multistatus" {
			if !rootOpened || rootClosed {
				return nil, errors.New("WebDAV listing is invalid")
			}
			rootClosed = true
			continue
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if !rootOpened {
			if start.Name.Space != "DAV:" || start.Name.Local != "multistatus" {
				return nil, errors.New("WebDAV listing is invalid")
			}
			rootOpened = true
			continue
		}
		if rootClosed {
			return nil, errors.New("WebDAV listing is invalid")
		}
		if start.Name.Space != "DAV:" || start.Name.Local != "response" {
			if err := decoder.Skip(); err != nil {
				return nil, errors.New("WebDAV listing is invalid")
			}
			continue
		}
		responses++
		if responses > maxListResponses {
			return nil, errors.New("WebDAV listing has too many entries")
		}
		var entry davResponse
		if err := decoder.DecodeElement(&entry, &start); err != nil {
			return nil, errors.New("WebDAV listing is invalid")
		}
		if len(entry.Href) == 0 || len(entry.Href) > 8192 {
			continue
		}
		href, err := url.Parse(entry.Href)
		if err != nil || href.User != nil || href.Fragment != "" {
			continue
		}
		resolved := u.ResolveReference(href)
		if resolved.Scheme != u.Scheme || !strings.EqualFold(resolved.Host, u.Host) || path.Clean(path.Dir(resolved.Path)) != path.Clean(u.Path) {
			continue
		}
		name := path.Base(resolved.Path)
		if !ValidRemoteName(name) || seen[name] {
			continue
		}
		collection, success := false, false
		for _, prop := range entry.PropStats {
			if strings.Contains(prop.Status, " 200 ") {
				success = true
				if prop.Prop.ResourceType.Collection != nil {
					collection = true
				}
			}
		}
		if !success || collection {
			continue
		}
		seen[name] = true
		names = append(names, name)
		if len(names) > maxListNames {
			return nil, errors.New("WebDAV listing has too many backups")
		}
	}
	if !rootOpened || !rootClosed {
		return nil, errors.New("WebDAV listing is invalid")
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}
