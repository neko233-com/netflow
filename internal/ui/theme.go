package ui

import mygoui "github.com/egoist/mygo/ui"

// FontStack is the Clash Verge Rev v2.5.9 family list. mygo's theme takes
// one family and falls back through the system, so the window draws with
// the system UI font. The stack is still the token the spec names,
// including Microsoft YaHei UI.
const FontStack = `-apple-system, BlinkMacSystemFont, "Microsoft YaHei UI", "Microsoft YaHei", Roboto, "Helvetica Neue", Arial, sans-serif, "Apple Color Emoji"`

// Breakpoints match use-custom-theme.ts (sm 650, md 900), not MUI's defaults.
const (
	BreakpointSM float32 = 650
	BreakpointMD float32 = 900
)

// Palette is the Verge surface and status colors for one appearance.
// Background paper does not follow a custom theme; it is the mode default.
type Palette struct {
	Dark      bool
	Primary   mygoui.Color
	Secondary mygoui.Color
	Text      mygoui.Color
	TextMuted mygoui.Color
	Info      mygoui.Color
	Error     mygoui.Color
	Warning   mygoui.Color
	Success   mygoui.Color
	Paper     mygoui.Color
	Content   mygoui.Color
	Card      mygoui.Color
	Node      mygoui.Color
	Divider   mygoui.Color
	OnPrimary mygoui.Color
	Dialog    mygoui.Color
	SidebarOn mygoui.Color
}

// PaletteFor returns the v2.5.9 defaults. dark chooses the dark column.
func PaletteFor(dark bool) Palette {
	if dark {
		return Palette{
			Dark:      true,
			Primary:   mygoui.Hex("#0A84FF"),
			Secondary: mygoui.Hex("#FF9F0A"),
			Text:      mygoui.Hex("#FFFFFF"),
			TextMuted: mygoui.Hex("#EBEBF599"),
			Info:      mygoui.Hex("#0A84FF"),
			Error:     mygoui.Hex("#FF453A"),
			Warning:   mygoui.Hex("#FF9F0A"),
			Success:   mygoui.Hex("#30D158"),
			Paper:     mygoui.Hex("#2E303D"),
			Content:   mygoui.Hex("#1E1F27"),
			Card:      mygoui.Hex("#282A36"),
			Node:      mygoui.Hex("#24252F"),
			Divider:   mygoui.RGBA(255, 255, 255, 0.06),
			OnPrimary: mygoui.Hex("#FFFFFF"),
			Dialog:    mygoui.Hex("#2E303D"),
			SidebarOn: mygoui.Hex("#FFFFFF"),
		}
	}
	return Palette{
		Primary:   mygoui.Hex("#007AFF"),
		Secondary: mygoui.Hex("#FC9B76"),
		Text:      mygoui.Hex("#000000"),
		TextMuted: mygoui.Hex("#3C3C4399"),
		Info:      mygoui.Hex("#007AFF"),
		Error:     mygoui.Hex("#FF3B30"),
		Warning:   mygoui.Hex("#FF9500"),
		Success:   mygoui.Hex("#06943D"),
		Paper:     mygoui.Hex("#F5F5F5"),
		Content:   mygoui.Hex("#ECECEC"),
		Card:      mygoui.Hex("#FFFFFF"),
		Node:      mygoui.Hex("#FFFFFF"),
		Divider:   mygoui.RGBA(0, 0, 0, 0.06),
		OnPrimary: mygoui.Hex("#FFFFFF"),
		Dialog:    mygoui.Hex("#FFFFFF"),
		SidebarOn: mygoui.Hex("#1F1F1F"),
	}
}

// Theme builds a mygo theme from the palette. Spacing is 4 so 8px is two
// units, matching MUI's 8px step. Cards use an 8px radius. Scrollbars are
// 8px. Shadows stay off; sticky group headers set their own.
func (p Palette) Theme() *mygoui.Theme {
	t := mygoui.LightTheme()
	if p.Dark {
		t = mygoui.DarkTheme()
	}
	t.Dark = p.Dark
	t.Background = p.Paper
	t.Surface = p.Card
	t.SurfaceHover = p.Card.Mix(p.Text, 0.06)
	t.SurfacePressed = p.Card.Mix(p.Text, 0.10)
	t.Border = p.Divider
	t.Text = p.Text
	t.TextMuted = p.TextMuted
	t.Accent = p.Primary
	t.AccentHover = p.Primary.Mix(mygoui.Hex("#000000"), 0.12)
	t.AccentPressed = p.Primary.Mix(mygoui.Hex("#000000"), 0.2)
	t.AccentText = p.OnPrimary
	t.Danger = p.Error
	t.Warning = p.Warning
	t.Success = p.Success
	t.Selection = p.Primary.Alpha(0.28)
	t.Focus = p.Primary.Alpha(0.55)
	if p.Dark {
		t.Scrollbar = mygoui.Hex("#555555")
	} else {
		t.Scrollbar = mygoui.Hex("#C1C1C1")
	}
	t.ScrollbarWidth = 8
	t.Radius = 8
	t.Spacing = 4
	t.FontSize = 14
	// System UI font. FontStack records the Verge family list; a single
	// missing family name would drop CJK glyphs on machines without it.
	t.Font = ""
	return t
}

// SelectedFill is the sidebar and node selection wash: primary at 15% in
// light and 35% in dark.
func (p Palette) SelectedFill() mygoui.Color {
	if p.Dark {
		return p.Primary.Alpha(0.35)
	}
	return p.Primary.Alpha(0.15)
}

// NodeBar is the 3px selection mark. Dark uses a lighter primary, as
// MUI's primary.light does.
func (p Palette) NodeBar() mygoui.Color {
	if p.Dark {
		return p.Primary.Mix(mygoui.Hex("#FFFFFF"), 0.35)
	}
	return p.Primary
}

// Tone is a named status color from the palette.
type Tone uint8

const (
	ToneNone Tone = iota
	TonePrimary
	ToneSecondary
	ToneInfo
	ToneSuccess
	ToneWarning
	ToneError
	ToneMuted
)

// Color resolves a tone against the palette.
func (p Palette) Color(t Tone) mygoui.Color {
	switch t {
	case TonePrimary, ToneInfo:
		return p.Primary
	case ToneSecondary:
		return p.Secondary
	case ToneSuccess:
		return p.Success
	case ToneWarning:
		return p.Warning
	case ToneError:
		return p.Error
	case ToneMuted:
		return p.TextMuted
	default:
		return p.Text
	}
}

// Default primary placeholders for the theme dialog, by mode.
func DefaultPrimary(dark bool) string {
	if dark {
		return "#0A84FF"
	}
	return "#007AFF"
}

func DefaultSecondary(dark bool) string {
	if dark {
		return "#FF9F0A"
	}
	return "#FC9B76"
}

func DefaultPrimaryText(dark bool) string {
	if dark {
		return "#FFFFFF"
	}
	return "#000000"
}

func DefaultSecondaryText(dark bool) string {
	if dark {
		return "#EBEBF599"
	}
	return "#3C3C4399"
}

func DefaultInfo(dark bool) string { return DefaultPrimary(dark) }

func DefaultError(dark bool) string {
	if dark {
		return "#FF453A"
	}
	return "#FF3B30"
}

func DefaultWarning(dark bool) string {
	if dark {
		return "#FF9F0A"
	}
	return "#FF9500"
}

func DefaultSuccess(dark bool) string {
	if dark {
		return "#30D158"
	}
	return "#06943D"
}
