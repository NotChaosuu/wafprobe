package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// adaptive colours; lipgloss drops them under NO_COLOR
var (
	cAccent = lipgloss.AdaptiveColor{Light: "#0E7490", Dark: "#22D3EE"}
	cText   = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#E5E7EB"}
	cDim    = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#8B93A1"}
	cFaint  = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#3A414C"}
	cPass   = lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#4ADE80"}
	cBlock  = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#F87171"}
	cWarn   = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FBBF24"}
	cInk    = lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#0B1220"}

	sText   = lipgloss.NewStyle().Foreground(cText)
	sBold   = lipgloss.NewStyle().Foreground(cText).Bold(true)
	sDim    = lipgloss.NewStyle().Foreground(cDim)
	sFaint  = lipgloss.NewStyle().Foreground(cFaint)
	sAccent = lipgloss.NewStyle().Foreground(cAccent)
	sHead   = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sPass   = lipgloss.NewStyle().Foreground(cPass)
	sBlock  = lipgloss.NewStyle().Foreground(cBlock)
	sWarn   = lipgloss.NewStyle().Foreground(cWarn)
)

// pill is a filled label: used for verdict chips and the focused button.
func pill(text string, bg lipgloss.TerminalColor) string {
	return lipgloss.NewStyle().Foreground(cInk).Background(bg).Bold(true).Padding(0, 1).Render(text)
}

// card draws a rounded box of the given outer width around content.
func card(content string, width int, border lipgloss.TerminalColor) string {
	return lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(border).
		Padding(0, 2).
		Width(width - 2).
		Render(content)
}

// keys renders a footer hint line from key/description pairs.
func keys(pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		parts = append(parts, sText.Render(pairs[i])+" "+sDim.Render(pairs[i+1]))
	}
	return strings.Join(parts, sFaint.Render("  ·  "))
}

// padRight pads a possibly-styled string to n visible cells.
func padRight(s string, n int) string {
	if w := lipgloss.Width(s); w < n {
		return s + strings.Repeat(" ", n-w)
	}
	return s
}

// trunc shortens plain text to n cells with an ellipsis.
func trunc(s string, n int) string {
	r := []rune(s)
	if n < 1 || len(r) <= n {
		return s
	}
	if n == 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func wrap(s string, width int) string {
	return lipgloss.NewStyle().Width(width).Render(s)
}

func clock(d time.Duration) string {
	s := int(d.Seconds())
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

// bar is a fixed-width progress bar.
func bar(done, total, width int) string {
	if total <= 0 {
		total = 1
	}
	fill := done * width / total
	if fill > width {
		fill = width
	}
	return sAccent.Render(strings.Repeat("█", fill)) + sFaint.Render(strings.Repeat("░", width-fill))
}
