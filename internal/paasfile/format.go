package paasfile

import "fmt"

// Format is the type of the Paas file; json, yaml, unknown
type Format uint

// File formats supported by this package
const (
	UnknownFormat Format = iota
	AutoFormat
	PreserveFormat
	JSONFormat
	YAMLFormat
)

var fileFormatString = map[Format]string{
	AutoFormat:     "auto",
	JSONFormat:     "json",
	YAMLFormat:     "yaml",
	PreserveFormat: "preserve",
	UnknownFormat:  "unknown",
}

// Returns a string representation of fileFormat, if known.
func (ff Format) String() string {
	if s, exists := fileFormatString[ff]; exists {
		return s
	}
	return UnknownFormat.String()
}

// FormatFromString can be used to get the corresponding format for a string value
func FormatFromString(sFormat string) (Format, error) {
	for f, s := range fileFormatString {
		if s == sFormat {
			return f, nil
		}
	}
	return UnknownFormat, fmt.Errorf("unknown file format %s", sFormat)
}
