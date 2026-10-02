package endpoint

import (
	"fmt"
	"strings"
)

func parseWindowsCommandLine(input string) (string, []string, error) {
	args, err := splitWindowsCommandLine(input)
	if err != nil {
		return "", nil, err
	}
	if len(args) == 0 || args[0] == "" {
		return "", nil, fmt.Errorf("command is empty")
	}
	return args[0], args[1:], nil
}

// splitWindowsCommandLine follows the Windows argv quoting rules for double
// quotes and also accepts single-quoted groups as a convenient address syntax.
func splitWindowsCommandLine(input string) ([]string, error) {
	var args []string
	for i := 0; i < len(input); {
		for i < len(input) && isCommandSpace(input[i]) {
			i++
		}
		if i == len(input) {
			break
		}

		var arg strings.Builder
		var quote byte
		started := false
		for i < len(input) {
			if quote == 0 && isCommandSpace(input[i]) {
				break
			}
			if input[i] == '\\' {
				start := i
				for i < len(input) && input[i] == '\\' {
					i++
				}
				count := i - start
				if i < len(input) && input[i] == '"' && quote != '\'' {
					arg.WriteString(strings.Repeat("\\", count/2))
					if count%2 == 1 {
						arg.WriteByte('"')
						i++
					} else if quote == '"' && i+1 < len(input) && input[i+1] == '"' {
						arg.WriteByte('"')
						i += 2
					} else {
						quote = toggleQuote(quote, '"')
						i++
					}
				} else {
					arg.WriteString(strings.Repeat("\\", count))
				}
				started = true
				continue
			}

			ch := input[i]
			if ch == '"' || ch == '\'' {
				if quote == 0 {
					quote = ch
				} else if quote == ch {
					if ch == '"' && i+1 < len(input) && input[i+1] == '"' {
						arg.WriteByte('"')
						i += 2
						started = true
						continue
					}
					quote = 0
				} else {
					arg.WriteByte(ch)
				}
				i++
				started = true
				continue
			}
			arg.WriteByte(ch)
			i++
			started = true
		}

		if quote != 0 {
			return nil, fmt.Errorf("unterminated %q quote in command", quote)
		}
		if started {
			args = append(args, arg.String())
		}
		for i < len(input) && isCommandSpace(input[i]) {
			i++
		}
	}
	return args, nil
}

func toggleQuote(current, quote byte) byte {
	if current == 0 {
		return quote
	}
	return 0
}

func isCommandSpace(ch byte) bool {
	return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'
}
