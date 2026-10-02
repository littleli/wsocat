package address

import (
	"fmt"
	"strings"
)

// Address is the parsed tag, endpoint-specific value, and comma options from
// one wsocat address argument.
type Address struct {
	Tag     string
	Value   string
	Options map[string]string
}

// Parse parses a single address expression. Quotes protect commas in values;
// quote characters remain in Value so endpoint-specific parsers can interpret
// command lines according to Windows rules.
func Parse(input string) (Address, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Address{}, fmt.Errorf("address is empty")
	}

	delim := strings.IndexAny(input, ":,")
	if delim < 0 {
		return Address{Tag: strings.ToUpper(input), Options: map[string]string{}}, nil
	}

	tag := strings.TrimSpace(input[:delim])
	if tag == "" {
		return Address{}, fmt.Errorf("address %q has an empty tag", input)
	}
	if strings.ContainsAny(tag, " \t\r\n") {
		return Address{}, fmt.Errorf("address %q has whitespace in its tag", input)
	}

	if input[delim] == ',' {
		options, err := parseOptions(input[delim+1:])
		if err != nil {
			return Address{}, fmt.Errorf("address %q: %w", input, err)
		}
		return Address{Tag: strings.ToUpper(tag), Options: options}, nil
	}

	parts, err := splitOutsideQuotes(input[delim+1:], ',')
	if err != nil {
		return Address{}, fmt.Errorf("address %q: %w", input, err)
	}
	value := strings.TrimSpace(parts[0])
	options := map[string]string{}
	if len(parts) > 1 {
		options, err = parseOptions(strings.Join(parts[1:], ","))
		if err != nil {
			return Address{}, fmt.Errorf("address %q: %w", input, err)
		}
	}
	return Address{Tag: strings.ToUpper(tag), Value: value, Options: options}, nil
}

func parseOptions(input string) (map[string]string, error) {
	options := make(map[string]string)
	if strings.TrimSpace(input) == "" {
		return options, nil
	}

	parts, err := splitOutsideQuotes(input, ',')
	if err != nil {
		return nil, err
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, hasValue := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			return nil, fmt.Errorf("empty option name")
		}
		if _, exists := options[key]; exists {
			return nil, fmt.Errorf("duplicate option %q", key)
		}
		if !hasValue {
			value = ""
		}
		options[key] = unquote(strings.TrimSpace(value))
	}
	return options, nil
}

func splitOutsideQuotes(input string, separator byte) ([]string, error) {
	var parts []string
	start := 0
	var quotes []byte
	backslashes := 0

	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch == '\\' {
			backslashes++
			continue
		}

		if ch == '"' || ch == '\'' {
			escapedDoubleQuote := ch == '"' && backslashes%2 == 1
			if !escapedDoubleQuote {
				if len(quotes) == 0 {
					quotes = append(quotes, ch)
				} else if quotes[len(quotes)-1] == ch {
					quotes = quotes[:len(quotes)-1]
				} else {
					quotes = append(quotes, ch)
				}
			}
			backslashes = 0
			continue
		}

		if ch == separator && len(quotes) == 0 {
			parts = append(parts, input[start:i])
			start = i + 1
		}
		backslashes = 0
	}

	if len(quotes) != 0 {
		return nil, fmt.Errorf("unterminated %q quote", quotes[len(quotes)-1])
	}
	return append(parts, input[start:]), nil
}

func unquote(value string) string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return value[1 : len(value)-1]
	}
	return value
}
