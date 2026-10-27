// Package encryptor provides streaming OpenPGP (GPG) and age encryption for
// backup pipelines: dump -> compress -> encrypt -> upload without buffering
// whole files in memory.
//
// Encryption wraps a destination writer (see [Encrypter]); decryption detects
// the format of a stream by its magic bytes and returns a plaintext reader
// (see [Detect] and [Decrypt]).
package encryptor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Format identifies an encryption format.
type Format int

const (
	// FormatNone means the data is not encrypted (or not in a recognised format).
	FormatNone Format = iota
	// FormatGPG is an OpenPGP message (binary or ASCII armored).
	FormatGPG
	// FormatAge is an age file (binary or ASCII armored).
	FormatAge
)

// String returns "none", "gpg" or "age".
func (f Format) String() string {
	switch f {
	case FormatGPG:
		return "gpg"
	case FormatAge:
		return "age"
	default:
		return "none"
	}
}

// Ext returns the conventional file extension: "", ".gpg" or ".age".
func (f Format) Ext() string {
	switch f {
	case FormatGPG:
		return ".gpg"
	case FormatAge:
		return ".age"
	default:
		return ""
	}
}

// ParseFormat parses a format name, case-insensitively: none (or empty),
// gpg, pgp, openpgp or age.
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none":
		return FormatNone, nil
	case "gpg", "pgp", "openpgp":
		return FormatGPG, nil
	case "age":
		return FormatAge, nil
	}
	return FormatNone, fmt.Errorf("encryptor: unknown encryption format %q (want none, gpg or age)", s)
}

const (
	ageMagic        = "age-encryption.org/v1\n"
	ageArmorHeader  = "-----BEGIN AGE ENCRYPTED FILE-----"
	pgpArmorHeader  = "-----BEGIN PGP MESSAGE-----"
	detectPeekBytes = 64
)

// Detect peeks at the start of r and returns the detected format plus a reader
// that replays the peeked bytes followed by the rest of r.
//
// Recognised: age binary ("age-encryption.org/v1"), age armor, PGP armor
// ("-----BEGIN PGP MESSAGE-----"), and binary OpenPGP messages starting with a
// PKESK (tag 1), SKESK (tag 3), SEIPD (tag 18) or AEAD (tag 20) packet, in old
// or new packet format. Anything else is FormatNone.
func Detect(r io.Reader) (Format, io.Reader, error) {
	f, br, _, err := peekFormat(r)
	return f, br, err
}

func peekFormat(r io.Reader) (Format, *bufio.Reader, []byte, error) {
	br, ok := r.(*bufio.Reader)
	if !ok || br.Size() < detectPeekBytes {
		br = bufio.NewReader(r)
	}
	head, err := br.Peek(detectPeekBytes)
	if err != nil && !errors.Is(err, io.EOF) {
		return FormatNone, br, head, err
	}
	return detectBytes(head), br, head, nil
}

func detectBytes(head []byte) Format {
	if bytes.HasPrefix(head, []byte(ageMagic)) {
		return FormatAge
	}
	trimmed := bytes.TrimLeft(head, " \t\r\n")
	if bytes.HasPrefix(trimmed, []byte(ageArmorHeader)) {
		return FormatAge
	}
	if bytes.HasPrefix(trimmed, []byte(pgpArmorHeader)) {
		return FormatGPG
	}
	if isBinaryPGP(head) {
		return FormatGPG
	}
	return FormatNone
}

// isBinaryPGP reports whether head starts with an OpenPGP packet that can begin
// an encrypted message, checking the packet version byte as well to keep false
// positives on arbitrary binary data low.
func isBinaryPGP(head []byte) bool {
	if len(head) < 2 || head[0]&0x80 == 0 {
		return false
	}
	var tag byte
	var lenBytes int
	if head[0]&0x40 != 0 { // new format
		tag = head[0] & 0x3f
		switch l := head[1]; {
		case l < 192:
			lenBytes = 1
		case l < 224:
			lenBytes = 2
		case l == 255:
			lenBytes = 5
		default: // partial body length
			lenBytes = 1
		}
	} else { // old format
		tag = (head[0] >> 2) & 0x0f
		switch head[0] & 0x03 {
		case 0:
			lenBytes = 1
		case 1:
			lenBytes = 2
		case 2:
			lenBytes = 4
		default:
			lenBytes = 0
		}
	}
	vi := 1 + lenBytes
	if vi >= len(head) {
		return false
	}
	version := head[vi]
	switch tag {
	case 1: // PKESK
		return version == 3 || version == 6
	case 3: // SKESK
		return version == 4 || version == 5 || version == 6
	case 18: // SEIPD
		return version == 1 || version == 2
	case 20: // AEAD encrypted data (OCB, legacy draft)
		return version == 1
	}
	return false
}
