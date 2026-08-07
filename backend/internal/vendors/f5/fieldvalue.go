package f5

import "strings"

// parseFieldValuePairs parses BIG-IP ASM's "Field-Value Pairs" storage format.
//
//	support_id="1827399",date_time="2026-08-07 07:09:00",violations="Illegal length,SQLi"
//
// This is what a BIG-IP Logging Profile actually emits, and it is NOT the CEF extension
// format parseCEFExtension handles. The differences are the whole problem: pairs are
// separated by COMMAS rather than spaces, and values are QUOTED — so they legitimately
// contain both spaces and commas. `violations` routinely holds several comma-separated
// names, and `date_time` always holds a space. Splitting on whitespace turns one field
// into several fragments and loses the rest, which is why an ASM line arrived with a
// date_time the parser then reported as absent.
//
// A leading syslog header (`<134>Aug  7 07:09:00 bigip1 ASM:`) is tolerated: scanning
// starts at the first well-formed `key="` and anything before it is ignored, so the same
// parser works whether the shipper preserved the header or stripped it.
func parseFieldValuePairs(line string) map[string]string {
	fields := map[string]string{}

	for i := 0; i < len(line); {
		key, next, ok := readKey(line, i)
		if !ok {
			// Not a pair boundary — step forward and keep looking. This is what skips a
			// syslog header without needing to recognise its shape.
			i++
			continue
		}

		value, after := readValue(line, next)
		fields[key] = value
		i = after
	}

	return fields
}

// readKey reads an identifier immediately followed by '=', starting at i.
func readKey(line string, i int) (key string, next int, ok bool) {
	start := i
	for i < len(line) && isIdentifierByte(line[i]) {
		i++
	}
	if i == start || i >= len(line) || line[i] != '=' {
		return "", start, false
	}
	// A key must start a pair, not sit inside a value: the character before it has to be
	// a separator. Without this, a '=' inside an unquoted value would split it in two.
	if start > 0 && !isSeparator(line[start-1]) {
		return "", start, false
	}
	return line[start:i], i + 1, true
}

// readValue reads a value, quoted or bare, returning the index just past it.
func readValue(line string, i int) (value string, next int) {
	if i < len(line) && line[i] == '"' {
		return readQuoted(line, i+1)
	}

	start := i
	for i < len(line) && line[i] != ',' {
		i++
	}
	return strings.TrimSpace(line[start:i]), i
}

// readQuoted reads until the closing quote, honouring both escaping conventions.
func readQuoted(line string, i int) (value string, next int) {
	var out strings.Builder

	for i < len(line) {
		switch {
		case line[i] == '\\' && i+1 < len(line) && line[i+1] == '"':
			// Backslash-escaped quote.
			out.WriteByte('"')
			i += 2
		case line[i] == '"' && i+1 < len(line) && line[i+1] == '"':
			// Doubled quote, the other common convention.
			out.WriteByte('"')
			i += 2
		case line[i] == '"':
			// Closing quote. Step past a following separator so the next key starts clean.
			i++
			if i < len(line) && line[i] == ',' {
				i++
			}
			return out.String(), i
		default:
			out.WriteByte(line[i])
			i++
		}
	}

	// Unterminated quote: return what was read rather than discarding the whole line. A
	// truncated event still carries a support id and a timestamp, and a partial record
	// beats none at all.
	return out.String(), i
}

func isIdentifierByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
		b >= '0' && b <= '9' || b == '_' || b == '-' || b == '.'
}

// isSeparator reports whether b can precede the start of a key.
func isSeparator(b byte) bool {
	return b == ',' || b == ' ' || b == '\t' || b == ';' || b == ':'
}
