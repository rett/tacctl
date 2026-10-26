package blocks

// The banners of an IOS system block (0.2.19): the login banner (shown before
// the login prompt), the message of the day (motd, shown on every connection)
// and the exec banner (shown after the login). Each is a heredoc of the block
// and is typed as IOS's multi-line banner, 'banner <kind> <d>', the text and
// '<d>' alone on a line. They differ by the word only: the limits, the
// delimiter and the reading of a device's banner are the same.

import "strings"

// BannerKinds are the banners a block takes, in the order they are rendered.
var BannerKinds = []string{"login", "motd", "exec"}

// IOSBannerStartOf is the line that opens the heredoc of a banner.
func IOSBannerStartOf(kind string) string { return "banner " + kind + " <<'EOF'" }

// IOSBannerHeadOf is the head of the rendered banner's first line.
func IOSBannerHeadOf(kind string) string { return "banner " + kind + " " }

// IOSBannerLinesOf is the banner of a kind as it is typed ('banner motd <d>',
// the text lines, '<d>' alone on a line); nil when no delimiter fits the text.
func IOSBannerLinesOf(kind, body string) []string {
	d, ok := BannerDelimiter(body)
	if !ok {
		return nil
	}
	out := []string{IOSBannerHeadOf(kind) + d}
	out = append(out, strings.Split(body, "\n")...)
	return append(out, d)
}

// BannerKindOf is the kind of the banner a line begins ('banner motd ^C'),
// "" when it is none.
func BannerKindOf(line string) string {
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "banner" {
		return ""
	}
	for _, k := range BannerKinds {
		if f[1] == k {
			return k
		}
	}
	return ""
}

// BannerOf is the text of the banner of a kind, nil for none.
func (b *IOSSystemBlock) BannerOf(kind string) *LoginMessage {
	if p := b.bannerField(kind); p != nil && b != nil {
		return *p
	}
	return nil
}

// BannerBodyOf is the text of the banner of a kind, "" for none.
func (b *IOSSystemBlock) BannerBodyOf(kind string) string {
	if m := b.BannerOf(kind); m != nil {
		return m.Body
	}
	return ""
}

// BannerFieldOf is the place of the banner of a kind in the block (nil for a
// kind that is none), for a caller that builds a block of one banner.
func (b *IOSSystemBlock) BannerFieldOf(kind string) **LoginMessage { return b.bannerField(kind) }

func (b *IOSSystemBlock) bannerField(kind string) **LoginMessage {
	if b == nil {
		return nil
	}
	switch kind {
	case "login":
		return &b.Banner
	case "motd":
		return &b.BannerMOTD
	case "exec":
		return &b.BannerExec
	}
	return nil
}

// noBanners reports a block with no banner.
func (b *IOSSystemBlock) noBanners() bool {
	return b.Banner == nil && b.BannerMOTD == nil && b.BannerExec == nil
}

// DeviceBannerOf is DeviceBanner for the banner of a kind.
func DeviceBannerOf(kind string, lines []string) (body string, took int, ok bool) {
	if len(lines) == 0 || kind == "login" {
		return DeviceBanner(lines)
	}
	cp := append([]string(nil), lines...)
	first := strings.TrimSpace(cp[0])
	rest, found := strings.CutPrefix(first, "banner "+kind)
	if !found || (rest != "" && rest[0] != ' ') {
		return "", 1, false
	}
	cp[0] = "banner login" + rest
	return DeviceBanner(cp)
}
