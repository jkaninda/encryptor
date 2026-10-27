package encryptor

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Keys is everything available for decryption. Decrypt tries whichever
// entries fit the detected format.
type Keys struct {
	// GPGPassphrases are tried, in order, on passphrase-encrypted (SKESK)
	// OpenPGP messages.
	GPGPassphrases [][]byte
	// GPGPrivateKeys are OpenPGP private keys, armored or binary; each entry
	// may hold several keys.
	GPGPrivateKeys [][]byte
	// GPGPrivateKeyPassphrase unlocks protected private keys. If empty, each
	// GPGPassphrases entry is tried instead.
	GPGPrivateKeyPassphrase []byte
	// AgeIdentities are identity file contents: AGE-SECRET-KEY-1... lines
	// (several per entry, '#' comments allowed) or an unencrypted OpenSSH
	// private key PEM (ed25519 or rsa).
	AgeIdentities []string
	// AgePassphrases are tried, in order, on passphrase (scrypt) age files.
	AgePassphrases [][]byte
}

// Empty reports whether no decryption material is configured.
func (k Keys) Empty() bool {
	return len(k.GPGPassphrases) == 0 && len(k.GPGPrivateKeys) == 0 &&
		len(k.AgeIdentities) == 0 && len(k.AgePassphrases) == 0
}

// Decrypt detects the format of r and returns a plaintext stream.
//
// For FormatNone the (replaying) input reader is returned unchanged. When no
// configured key applies to the data, the error wraps ErrNoKey; when keys were
// tried but none worked, it wraps ErrWrongKey.
//
// Integrity failures (OpenPGP MDC/AEAD, age chunk authentication) are returned
// by Read, at the latest together with EOF; callers must treat any Read error
// as fatal and discard the partial plaintext.
func Decrypt(r io.Reader, keys Keys) (io.Reader, Format, error) {
	f, br, _, err := peekFormat(r)
	if err != nil {
		return nil, FormatNone, err
	}
	var plain io.Reader
	switch f {
	case FormatGPG:
		plain, err = decryptGPG(br, keys)
	case FormatAge:
		plain, err = decryptAge(br, keys)
	default:
		return br, FormatNone, nil
	}
	if err != nil {
		return nil, f, err
	}
	return plain, f, nil
}

// EncryptString encrypts data with a passphrase and returns an ASCII-armored
// OpenPGP message, suitable for embedding in text/YAML/JSON configuration.
// Compatible with EncryptString of encryptor v0.2 and earlier.
func EncryptString(data []byte, passphrase string) (string, error) {
	e, err := GPGPassphrase([]byte(passphrase), WithArmor())
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if _, err := EncryptStream(&buf, bytes.NewReader(data), e); err != nil {
		return "", fmt.Errorf("encryptor: encrypting data: %w", err)
	}
	return buf.String(), nil
}

// DecryptString decrypts an ASCII-armored OpenPGP message produced by
// EncryptString (any version) with the same passphrase.
func DecryptString(armored, passphrase string) ([]byte, error) {
	i := strings.Index(armored, pgpArmorHeader)
	if i < 0 {
		return nil, errors.New("encryptor: not an armored PGP message")
	}
	armored = armored[i:]
	plain, f, err := Decrypt(strings.NewReader(armored), Keys{GPGPassphrases: [][]byte{[]byte(passphrase)}})
	if err != nil {
		return nil, err
	}
	if f != FormatGPG {
		return nil, errors.New("encryptor: not an armored PGP message")
	}
	return io.ReadAll(plain)
}

// IsEncrypted reports whether s looks like an ASCII-armored PGP message or an
// ASCII-armored age file.
func IsEncrypted(s string) bool {
	return strings.Contains(s, pgpArmorHeader) || strings.Contains(s, ageArmorHeader)
}
