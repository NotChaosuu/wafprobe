package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type fieldKind int

const (
	fText   fieldKind = iota
	fChoice           // one of options, cycled with ←/→
	fMulti            // any of options, toggled with space
	fButton           // the submit row
)

type field struct {
	id, label string
	kind      fieldKind
	input     textinput.Model
	options   []string
	hints     []string // per-option description, shown dim
	sel       int      // fChoice
	checked   []bool   // fMulti
	cur       int      // fMulti cursor
	hidden    func() bool
	err       string
}

// form is a vertical list of fields. Enter submits from anywhere, so the fast
// path is "type a URL, press enter"; tab and the arrows are for changing
// defaults.
type form struct {
	fields []*field
	focus  int // index into visible()
}

func newText(id, label, placeholder string) *field {
	ti := textinput.New()
	ti.Prompt = ""
	ti.Placeholder = placeholder
	ti.CharLimit = 2048
	ti.TextStyle = sText
	ti.PlaceholderStyle = sFaint
	ti.Cursor.Style = sAccent
	// A static cursor needs no blink messages routed through the model.
	ti.Cursor.SetMode(cursor.CursorStatic)
	return &field{id: id, label: label, kind: fText, input: ti}
}

func newChoice(id, label string, options, hints []string) *field {
	return &field{id: id, label: label, kind: fChoice, options: options, hints: hints}
}

func newMulti(id, label string, options, hints []string) *field {
	checked := make([]bool, len(options))
	for i := range checked {
		checked[i] = true
	}
	return &field{id: id, label: label, kind: fMulti, options: options, hints: hints, checked: checked}
}

func newButton(label string) *field {
	return &field{id: "run", label: label, kind: fButton}
}

func (f *form) visible() []*field {
	out := make([]*field, 0, len(f.fields))
	for _, fl := range f.fields {
		if fl.hidden == nil || !fl.hidden() {
			out = append(out, fl)
		}
	}
	return out
}

func (f *form) get(id string) *field {
	for _, fl := range f.fields {
		if fl.id == id {
			return fl
		}
	}
	return nil
}

func (f *form) current() *field {
	vis := f.visible()
	if f.focus >= len(vis) {
		f.focus = len(vis) - 1
	}
	return vis[f.focus]
}

func (f *form) setFocus(i int) {
	vis := f.visible()
	if i < 0 {
		i = 0
	}
	if i >= len(vis) {
		i = len(vis) - 1
	}
	f.focus = i
	for j, fl := range vis {
		if fl.kind != fText {
			continue
		}
		if j == i {
			fl.input.Focus()
		} else {
			fl.input.Blur()
		}
	}
}

func (f *form) focusID(id string) {
	for i, fl := range f.visible() {
		if fl.id == id {
			f.setFocus(i)
			return
		}
	}
}

// value returns the selected option of a choice field.
func (fl *field) value() string {
	if fl.kind == fText {
		return strings.TrimSpace(fl.input.Value())
	}
	return fl.options[fl.sel]
}

func (fl *field) selected() []string {
	var out []string
	for i, on := range fl.checked {
		if on {
			out = append(out, fl.options[i])
		}
	}
	return out
}

// update applies a key and reports whether the form was submitted.
func (f *form) update(msg tea.KeyMsg) bool {
	cur := f.current()
	key := msg.String()
	switch key {
	case "enter":
		return true
	case "tab":
		f.setFocus(f.focus + 1)
		return false
	case "shift+tab":
		f.setFocus(f.focus - 1)
		return false
	case "down":
		if cur.kind == fMulti && cur.cur < len(cur.options)-1 {
			cur.cur++
		} else {
			f.setFocus(f.focus + 1)
		}
		return false
	case "up":
		if cur.kind == fMulti && cur.cur > 0 {
			cur.cur--
		} else {
			f.setFocus(f.focus - 1)
		}
		return false
	}

	switch cur.kind {
	case fText:
		cur.err = ""
		cur.input, _ = cur.input.Update(msg)
	case fChoice:
		n := len(cur.options)
		switch key {
		case "left", "h":
			cur.sel = (cur.sel + n - 1) % n
		case "right", "l", " ":
			cur.sel = (cur.sel + 1) % n
		}
	case fMulti:
		cur.err = ""
		switch key {
		case " ", "x":
			cur.checked[cur.cur] = !cur.checked[cur.cur]
		case "a":
			all := len(cur.selected()) == len(cur.options)
			for i := range cur.checked {
				cur.checked[i] = !all
			}
		}
	}
	return false
}

const labelW = 12

func (f *form) view(width int) string {
	var b strings.Builder
	for i, fl := range f.visible() {
		focused := i == f.focus
		marker, labelSt := "  ", sDim
		if focused {
			marker, labelSt = sAccent.Render("▎ "), sHead
		}
		indent := strings.Repeat(" ", 2+labelW)

		if fl.kind == fButton {
			b.WriteString("\n" + indent)
			if focused {
				b.WriteString(pill(fl.label+" ↵", cAccent))
			} else {
				b.WriteString(sDim.Render("[ " + fl.label + " ↵ ]"))
			}
			b.WriteString("\n")
			continue
		}

		b.WriteString(marker + labelSt.Render(padRight(fl.label, labelW)))
		switch fl.kind {
		case fText:
			fl.input.Width = width - labelW - 6
			b.WriteString(fl.input.View())
		case fChoice:
			val := fl.options[fl.sel]
			hint := ""
			if fl.sel < len(fl.hints) && fl.hints[fl.sel] != "" {
				hint = "  " + sDim.Render(fl.hints[fl.sel])
			}
			if focused {
				b.WriteString(sAccent.Render("‹ ") + sBold.Render(val) + sAccent.Render(" ›") + hint)
			} else {
				b.WriteString(sText.Render(val) + hint)
			}
		case fMulti:
			sel := fl.selected()
			summary := fmt.Sprintf("%d of %d", len(sel), len(fl.options))
			if len(sel) == len(fl.options) {
				summary = fmt.Sprintf("all %d", len(sel))
			}
			if !focused {
				b.WriteString(sText.Render(summary))
				if len(sel) > 0 && len(sel) < len(fl.options) {
					b.WriteString("  " + sDim.Render(trunc(strings.Join(sel, ", "), width-labelW-16)))
				}
				break
			}
			b.WriteString(sBold.Render(summary) + "  " + sDim.Render("space toggle · a all/none"))
			for j, opt := range fl.options {
				box, name := sFaint.Render("[ ]"), sDim.Render(padRight(opt, 17))
				if fl.checked[j] {
					box, name = sPass.Render("[✓]"), sText.Render(padRight(opt, 17))
				}
				ptr := "  "
				if j == fl.cur {
					ptr = sAccent.Render("❯ ")
				}
				hint := ""
				if j < len(fl.hints) {
					hint = sDim.Render(fl.hints[j])
				}
				b.WriteString("\n" + indent + ptr + box + " " + name + hint)
			}
		}
		b.WriteString("\n")
		if fl.err != "" {
			b.WriteString(indent + sBlock.Render(fl.err) + "\n")
		}
	}
	return b.String()
}
