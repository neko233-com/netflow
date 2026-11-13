package ui

import (
	mygoui "github.com/egoist/mygo/ui"

	"github.com/neko233-com/netflow/internal/query"
)

// searchBox is the shared filter row: text plus match-case, whole word, and regex.
func searchBox(c *mygoui.Context, pal Palette, q *query.Options, id string) {
	mygoui.Row(c).Grow(1).Height(32).Gap(4).AlignItems(mygoui.Center).Children(func() {
		field := mygoui.TextInput(c, &q.Text).Placeholder("过滤条件").Grow(1).Label(id + "-search")
		if pal.Dark {
			field.Background(mygoui.Transparent)
		} else {
			field.Background(pal.Card)
		}
		searchToggle(c, pal, iconCase, "区分大小写", id+"-case", &q.MatchCase)
		searchToggle(c, pal, iconWord, "全字匹配", id+"-word", &q.Whole)
		searchToggle(c, pal, iconRegex, "使用正则表达式", id+"-regex", &q.Regex)
		if q.Text != "" && textButton(c, pal, "×", "清空输入框", id+"-clear") {
			q.Text = ""
		}
	})
}

func searchToggle(c *mygoui.Context, pal Palette, svg *mygoui.SVG, tip, id string, on *bool) {
	b := mygoui.ButtonBase(c.Key(id)).Size(28, 28).Radius(4).Label(id).Tooltip(tip)
	if *on {
		b.Background(pal.Primary.Alpha(0.15)).TextColor(pal.Primary)
	} else {
		b.Background(mygoui.Transparent).TextColor(pal.TextMuted)
	}
	b.Children(func() { mygoui.Icon(c, svg).Size(16, 16) })
	if b.Clicked() {
		*on = !*on
	}
}

func emptyState(c *mygoui.Context, pal Palette) {
	mygoui.Column(c).FillWidth().Padding(48).AlignItems(mygoui.Center).Gap(12).Children(func() {
		mygoui.Column(c).Size(64, 48).Radius(8).Border(2, pal.TextMuted)
		mygoui.Text(c, "空空如也").FontSize(14).TextColor(pal.TextMuted)
	})
}
