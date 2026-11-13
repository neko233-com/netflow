// Package ipinfo retrieves the proxy's public exit address on explicit request.
package ipinfo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
)

const Endpoint = "https://api.ip.sb/geoip"

type Result struct{ IP, Country, Code, ASN, ISP, Org, Location, Timezone, Lon, Lat string }

// Fetch requires an explicit client so callers cannot accidentally fall back
// from the local proxy to a direct request and expose the user's real IP.
func Fetch(ctx context.Context, client *http.Client, endpoint string) (Result, error) {
	if client == nil {
		return Result{}, errors.New("未配置代理客户端")
	}
	if endpoint == "" {
		endpoint = Endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, err
	}
	requestClient := *client
	requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := requestClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("IP 查询服务返回 HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil {
		return Result{}, err
	}
	if len(data) > 64<<10 {
		return Result{}, errors.New("IP 查询响应过大")
	}
	var raw struct {
		IP       string   `json:"ip"`
		Country  string   `json:"country"`
		Code     string   `json:"country_code"`
		ASN      int64    `json:"asn"`
		ISP      string   `json:"isp"`
		Org      string   `json:"organization"`
		Region   string   `json:"region"`
		City     string   `json:"city"`
		Timezone string   `json:"timezone"`
		Lat      *float64 `json:"latitude"`
		Lon      *float64 `json:"longitude"`
	}
	if err = json.Unmarshal(data, &raw); err != nil {
		return Result{}, err
	}
	if _, err = netip.ParseAddr(raw.IP); err != nil {
		return Result{}, errors.New("IP 查询结果无效")
	}
	out := Result{IP: raw.IP, Country: raw.Country, Code: raw.Code, ISP: raw.ISP, Org: raw.Org, Timezone: raw.Timezone}
	parts := []string{}
	if raw.Region != "" {
		parts = append(parts, raw.Region)
	}
	if raw.City != "" && raw.City != raw.Region {
		parts = append(parts, raw.City)
	}
	out.Location = strings.Join(parts, ", ")
	if raw.ASN > 0 {
		out.ASN = "AS" + strconv.FormatInt(raw.ASN, 10)
	}
	if raw.Lat != nil {
		out.Lat = strconv.FormatFloat(*raw.Lat, 'f', -1, 64)
	}
	if raw.Lon != nil {
		out.Lon = strconv.FormatFloat(*raw.Lon, 'f', -1, 64)
	}
	return out, nil
}
