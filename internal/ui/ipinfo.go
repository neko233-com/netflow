package ui

import "github.com/neko233-com/netflow/internal/ipinfo"

func (m *Model) refreshIP() {
	if m.IPBusy {
		return
	}
	if m.Hooks.QueryIPAsync == nil {
		m.Notice = "IP 查询不可用"
		return
	}
	m.IPBusy = true
	m.IP.Failed = ""
	m.Hooks.QueryIPAsync(func(r ipinfo.Result, err error) {
		m.IPBusy = false
		if err != nil {
			m.IP.Failed = err.Error()
			return
		}
		m.IP = IPView{Loaded: true, IP: r.IP, Country: r.Country, Code: r.Code, ASN: r.ASN, ISP: r.ISP, Org: r.Org, Location: r.Location, Timezone: r.Timezone, Lon: r.Lon, Lat: r.Lat}
	})
}

// TickIP is called on the UI thread once a second while the app is running.
func (m *Model) TickIP() {
	if !m.IPAuto {
		return
	}
	if m.IPLeft > 0 {
		m.IPLeft--
	}
	if m.IPLeft <= 0 {
		m.IPLeft = 30
		m.refreshIP()
	}
}
