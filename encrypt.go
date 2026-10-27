package encryptor

import (
	"errors"
	"io"
)

var (
	// ErrNoKey means no configured key or passphrase applies to the format
	// (or the recipients) of the encrypted data.
	ErrNoKey = errors.New("encryptor: no key or passphrase configured that can decrypt this data")
	// ErrWrongKey means keys or passphrases were configured, but none of them
	// decrypted the data (wrong key, wrong passphrase or not a recipient).
	ErrWrongKey = errors.New("encryptor: wrong key or passphrase")
)

type options struct {
	armor bool
}

// Option configures an Encrypter.
type Option func(*options)

// WithArmor makes the Encrypter produce ASCII-armored output (a PGP armored
// message, or age armor).
func WithArmor() Option {
	return func(o *options) { o.armor = true }
}

func buildOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

// Encrypter wraps a destination writer with encryption.
type Encrypter interface {
	// Format returns the format this Encrypter produces.
	Format() Format
	// Wrap returns a writer that encrypts everything written to it into dst.
	// Close flushes and finalises the encryption but does not close dst.
	Wrap(dst io.Writer) (io.WriteCloser, error)
	// Fingerprints returns recipient identifiers for audit logs: GPG key
	// fingerprints (upper-case hex) or age recipient strings. It returns nil
	// for passphrase modes.
	Fingerprints() []string
}

// EncryptStream copies src through e into dst and finalises the encryption.
// dst is not closed. It returns the number of plaintext bytes read from src.
func EncryptStream(dst io.Writer, src io.Reader, e Encrypter) (int64, error) {
	if e == nil {
		return 0, errors.New("encryptor: nil Encrypter")
	}
	w, err := e.Wrap(dst)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(w, src)
	if cerr := w.Close(); err == nil {
		err = cerr
	}
	return n, err
}

// stackedWriter closes an inner writer, then the outer (armor) writer.
type stackedWriter struct {
	io.Writer
	closers []io.Closer
}

func (s *stackedWriter) Close() error {
	var first error
	for _, c := range s.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
