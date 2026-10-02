package address

import "testing"

func TestParseAddressForms(t *testing.T) {
	tests := []struct {
		input   string
		tag     string
		value   string
		options map[string]string
	}{
		{input: "STDIO", tag: "STDIO", options: map[string]string{}},
		{input: "TCP:localhost:80", tag: "TCP", value: "localhost:80", options: map[string]string{}},
		{input: "tcp-listen:127.0.0.1:80", tag: "TCP-LISTEN", value: "127.0.0.1:80", options: map[string]string{}},
		{input: "NPIPE::fooPipe", tag: "NPIPE", value: ":fooPipe", options: map[string]string{}},
		{input: `EXEC:"C:\Program Files\tool.exe" --flag`, tag: "EXEC", value: `"C:\Program Files\tool.exe" --flag`, options: map[string]string{}},
		{input: `WSL:'echo "Hello, World"',distribution=Ubuntu,user=root`, tag: "WSL", value: `'echo "Hello, World"'`, options: map[string]string{"distribution": "Ubuntu", "user": "root"}},
		{input: `SP:COM1,baudrate=12500,parity=1`, tag: "SP", value: "COM1", options: map[string]string{"baudrate": "12500", "parity": "1"}},
		{input: `STDIO,token="a,b"`, tag: "STDIO", options: map[string]string{"token": "a,b"}},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := Parse(tt.input)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got.Tag != tt.tag || got.Value != tt.value {
				t.Fatalf("Parse() = {%q %q}, want {%q %q}", got.Tag, got.Value, tt.tag, tt.value)
			}
			if len(got.Options) != len(tt.options) {
				t.Fatalf("options = %#v, want %#v", got.Options, tt.options)
			}
			for key, want := range tt.options {
				if got.Options[key] != want {
					t.Errorf("option %q = %q, want %q", key, got.Options[key], want)
				}
			}
		})
	}
}

func TestParseRejectsMalformedAddresses(t *testing.T) {
	for _, input := range []string{
		"",
		":value",
		"tag with space:value",
		`WSL:'unterminated`,
		`WSL:"unterminated`,
		"STDIO,=value",
		"TCP:host:80,mode=a,MODE=b",
	} {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(input); err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", input)
			}
		})
	}
}
