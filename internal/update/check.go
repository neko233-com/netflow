// Package update checks published versions without installing software.
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const ReleasesAPI = "https://api.github.com/repos/neko233-com/netflow/releases?per_page=30"
const ReleaseBase = "https://github.com/neko233-com/netflow/releases/tag/"

type Result struct {
	Current, Latest, URL string
	Available            bool
}

func Check(ctx context.Context, client *http.Client, endpoint, current string) (Result, error) {
	current = "v" + strings.TrimPrefix(current, "v")
	if !semver.IsValid(current) {
		return Result{}, errors.New("当前版本格式无效")
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if endpoint == "" {
		endpoint = ReleasesAPI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "NetFlow/"+strings.TrimPrefix(current, "v"))
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("更新服务返回 HTTP %d", resp.StatusCode)
	}
	var releases []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return Result{}, err
	}
	if len(data) > 1<<20 {
		return Result{}, errors.New("更新响应过大")
	}
	if err = json.Unmarshal(data, &releases); err != nil {
		return Result{}, fmt.Errorf("更新响应无效: %w", err)
	}
	includePrerelease := semver.Prerelease(current) != ""
	latest := ""
	for _, release := range releases {
		tag := release.Tag
		if release.Draft || !semver.IsValid(tag) || (!includePrerelease && (release.Prerelease || semver.Prerelease(tag) != "")) {
			continue
		}
		if latest == "" || semver.Compare(tag, latest) > 0 {
			latest = tag
		}
	}
	if latest == "" {
		return Result{}, errors.New("没有可用的版本信息")
	}
	return Result{Current: current, Latest: latest, URL: ReleaseBase + url.PathEscape(latest), Available: semver.Compare(latest, current) > 0}, nil
}
