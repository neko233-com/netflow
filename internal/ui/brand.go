package ui

import (
	_ "embed"

	mygoui "github.com/egoist/mygo/ui"
)

//go:embed assets/netflow.png
var netflowBrandPNG []byte

// Use the same generated artwork as the application and notification area.
var brandMark = func() mygoui.ImageSource {
	image, err := mygoui.DecodeImage(netflowBrandPNG)
	if err != nil {
		panic(err)
	}
	return image
}()

// Sidebar and logo slot, matching Clash Verge's layout-sidebar.
const (
	sidebarExpandedWidth  float32 = 200
	sidebarCollapsedWidth float32 = 72
	// Expanded logo row: ~58px tall, 20px horizontal padding.
	logoRowHeight   float32 = 58
	logoRowPaddingX float32 = 20
	// The mark is 36×36. Verge's icon uses marginTop/marginLeft -3px and
	// marginRight 5px inside a 27px row. The wordmark is 「NetFlow」.
	brandMarkSize   float32 = 36
	brandMarkMargin float32 = 5
	brandMarkNudge  float32 = -3
	logoInnerHeight float32 = 27
	// Collapsed logo area is 56×56. The mark stays 36×36, centered, and the wordmark is hidden.
	logoCollapsedBox float32 = 56
)
