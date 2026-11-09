package test

import (
	"encoding/binary"
	"testing"

	"github.com/klauspost/compress/s2"
)

func TestCompressS2DictionaryValidation(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		repeat uint64
		valid  bool
	}{
		{name: "zero repeat", repeat: 0, valid: true},
		{name: "last byte", repeat: s2.MinDictSize - 1, valid: true},
		{name: "end of dictionary", repeat: s2.MinDictSize, valid: true},
		{name: "past dictionary", repeat: s2.MinDictSize + 1},
		{name: "32-bit signed overflow", repeat: 1 << 31},
		{name: "64-bit signed overflow", repeat: 1 << 63},
		{name: "maximum unsigned value", repeat: ^uint64(0)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			data := make([]byte, binary.MaxVarintLen64+s2.MinDictSize)
			n := binary.PutUvarint(data, testCase.repeat)
			data = data[:n+s2.MinDictSize]

			// Only validate parsing; never encode with an invalid dictionary.
			dict := s2.NewDict(data)
			if gotValid := dict != nil; gotValid != testCase.valid {
				t.Fatalf("NewDict repeat %d valid = %v, want %v", testCase.repeat, gotValid, testCase.valid)
			}
		})
	}
}
