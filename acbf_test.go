package main

import (
	"bytes"
	"testing"
)

func TestCalculateChecksum(t *testing.T) {
	// 1CEB00DA
	input := []byte{28, 235, 0, 218}
	// 7b19e237cd6eef8770b30a93fe165070ab199e54
	checksum := []byte{123, 25, 226, 55, 205, 110, 239, 135, 112, 179, 10, 147, 254, 22, 80, 112, 171, 25, 158, 84}
	result := calculateChecksum(input)
	if !bytes.Equal(result, checksum) {
		t.Errorf("expected: %x, got: %x", checksum, result)
	}
}
