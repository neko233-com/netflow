package ui

import mygoui "github.com/egoist/mygo/ui"

// Small Material-style outlines used where Verge uses an icon instead of a word.
var (
	iconHelp  = mustNav(iconStroke + `<circle cx="12" cy="12" r="8"/><path d="M9.5 9.5 A2.5 2.5 0 1 1 12.8 12 C12 13 12 13.2 12 14.2"/><circle cx="12" cy="17" r="0.8" fill="#000" stroke="none"/></svg>`)
	iconGear  = mustNav(iconStroke + `<circle cx="12" cy="12" r="3"/><path d="M12 4 V6.2"/><path d="M12 17.8 V20"/><path d="M4 12 H6.2"/><path d="M17.8 12 H20"/><path d="M6.3 6.3 L7.9 7.9"/><path d="M16.1 16.1 L17.7 17.7"/><path d="M17.7 6.3 L16.1 7.9"/><path d="M7.9 16.1 L6.3 17.7"/></svg>`)
	iconWarn  = mustNav(iconStroke + `<path d="M12 4 L21 20 H3 Z"/><path d="M12 10 V14"/><circle cx="12" cy="17" r="0.8" fill="#000" stroke="none"/></svg>`)
	iconCols  = mustNav(iconStroke + `<rect x="4" y="5" width="4" height="14" rx="0.5"/><rect x="10" y="5" width="4" height="14" rx="0.5"/><rect x="16" y="5" width="4" height="14" rx="0.5"/></svg>`)
	iconSort  = mustNav(iconStroke + `<path d="M8 6 V18"/><path d="M5 9 L8 6 L11 9"/><path d="M16 18 V6"/><path d="M13 15 L16 18 L19 15"/></svg>`)
	iconCase  = mustNav(iconStroke + `<path d="M7 16 L10 8 H12 L15 16"/><path d="M8.2 13 H13.8"/><path d="M16 8 V16"/><path d="M16 12 H19 A2 2 0 0 0 19 8 H16"/></svg>`)
	iconWord  = mustNav(iconStroke + `<path d="M5 16 L8 8 H10 L13 16"/><path d="M6.2 13 H11.8"/><path d="M15 16 V8 H19 A3 3 0 0 1 19 14 H15"/></svg>`)
	iconRegex = mustNav(iconStroke + `<circle cx="8" cy="12" r="2.2"/><path d="M10.2 12 H14"/><path d="M14 8 V16"/><path d="M17 9 V15"/><path d="M17 9 H20"/><path d="M17 15 H20"/></svg>`)
)

const iconStroke = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#000" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round">`

func iconButton(c *mygoui.Context, pal Palette, svg *mygoui.SVG, tip, id string) bool {
	return iconButtonBox(c, pal, svg, tip, id, "", 28, 18, 6)
}

// iconButtonBox is an IconButton. box and glyph are DIPs. A radius of
// box/2 is the round MUI hit target. iconID labels the glyph for tests.
func iconButtonBox(c *mygoui.Context, pal Palette, svg *mygoui.SVG, tip, id, iconID string, box, glyph, radius float32) bool {
	b := mygoui.ButtonBase(c.Key(id)).Size(box, box).Radius(radius).Label(id).Tooltip(tip)
	b.Background(mygoui.Transparent)
	b.Children(func() {
		ic := mygoui.Icon(c, svg).Size(glyph, glyph).TextColor(pal.Text).Shrink(0)
		if iconID != "" {
			ic.Label(iconID)
		}
	})
	return b.Clicked()
}

func helpMark(c *mygoui.Context, pal Palette, id, tip string) {
	mygoui.Icon(c.Key(id), iconHelp).Size(16, 16).TextColor(pal.TextMuted).Tooltip(tip).Label(id)
}

func gearButton(c *mygoui.Context, pal Palette, tip, id string) bool {
	return iconButton(c, pal, iconGear, tip, id)
}
