package encryptor

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
)

type ageEncrypter struct {
	recipients []age.Recipient
	names      []string // nil for passphrase mode
	opts       options
}

// AgeRecipients returns an Encrypter producing age files encrypted to every
// recipient: native "age1..." (X25519 or post-quantum hybrid) and OpenSSH
// "ssh-ed25519 ..." / "ssh-rsa ..." public key lines.
func AgeRecipients(recipients []string, opts ...Option) (Encrypter, error) {
	var (
		rs    []age.Recipient
		names []string
	)
	for _, s := range recipients {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		r, err := parseAgeRecipient(s)
		if err != nil {
			return nil, err
		}
		rs = append(rs, r)
		names = append(names, s)
	}
	if len(rs) == 0 {
		return nil, errors.New("encryptor: no age recipient provided")
	}
	// age refuses some recipient combinations (e.g. post-quantum with
	// classic); surface that now rather than at the first backup.
	if _, err := age.Encrypt(io.Discard, rs...); err != nil {
		return nil, fmt.Errorf("encryptor: age recipients: %w", err)
	}
	return &ageEncrypter{recipients: rs, names: names, opts: buildOptions(opts)}, nil
}

// AgePassphrase returns an Encrypter producing age files encrypted with a
// passphrase (scrypt).
func AgePassphrase(passphrase []byte, opts ...Option) (Encrypter, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("encryptor: empty age passphrase")
	}
	r, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, fmt.Errorf("encryptor: age passphrase: %w", err)
	}
	return &ageEncrypter{recipients: []age.Recipient{r}, opts: buildOptions(opts)}, nil
}

// ParseAgeRecipients parses a recipients list: entries are separated by
// newlines and/or commas, surrounding space is trimmed, blank lines and lines
// starting with '#' are skipped. Every entry is validated.
func ParseAgeRecipients(text string) ([]string, error) {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for _, s := range strings.Split(line, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			if _, err := parseAgeRecipient(s); err != nil {
				return nil, err
			}
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("encryptor: no age recipient found")
	}
	return out, nil
}

func parseAgeRecipient(s string) (age.Recipient, error) {
	if strings.HasPrefix(s, "ssh-") {
		r, err := agessh.ParseRecipient(s)
		if err != nil {
			return nil, fmt.Errorf("encryptor: invalid age SSH recipient %q: %w", abbreviate(s), err)
		}
		return r, nil
	}
	rs, err := age.ParseRecipients(strings.NewReader(s))
	if err != nil || len(rs) != 1 {
		if err == nil {
			err = errors.New("expected exactly one recipient")
		}
		return nil, fmt.Errorf("encryptor: invalid age recipient %q: %w", abbreviate(s), err)
	}
	return rs[0], nil
}

func abbreviate(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

func (a *ageEncrypter) Format() Format { return FormatAge }

func (a *ageEncrypter) Fingerprints() []string {
	if a.names == nil {
		return nil
	}
	return append([]string(nil), a.names...)
}

func (a *ageEncrypter) Wrap(dst io.Writer) (io.WriteCloser, error) {
	if dst == nil {
		return nil, errors.New("encryptor: nil destination writer")
	}
	out := dst
	var armorW io.WriteCloser
	if a.opts.armor {
		armorW = armor.NewWriter(dst)
		out = armorW
	}
	w, err := age.Encrypt(out, a.recipients...)
	if err != nil {
		return nil, fmt.Errorf("encryptor: age encrypt: %w", err)
	}
	sw := &stackedWriter{Writer: w, closers: []io.Closer{w}}
	if armorW != nil {
		sw.closers = append(sw.closers, armorW)
	}
	return sw, nil
}

// parseAgeIdentities parses identity file contents: AGE-SECRET-KEY-1 lines
// (comments allowed) or an unencrypted OpenSSH private key.
func parseAgeIdentities(texts []string) ([]age.Identity, error) {
	var ids []age.Identity
	for i, t := range texts {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "-----BEGIN") {
			id, err := agessh.ParseIdentity([]byte(t))
			if err != nil {
				var missing *ssh.PassphraseMissingError
				if errors.As(err, &missing) {
					return nil, fmt.Errorf("encryptor: age identity %d: passphrase-protected SSH keys are not supported", i+1)
				}
				return nil, fmt.Errorf("encryptor: age identity %d: %w", i+1, err)
			}
			ids = append(ids, id)
			continue
		}
		parsed, err := age.ParseIdentities(strings.NewReader(t))
		if err != nil {
			return nil, fmt.Errorf("encryptor: age identity %d: %w", i+1, err)
		}
		ids = append(ids, parsed...)
	}
	return ids, nil
}

// decryptAge decrypts an age file (armored or binary) from r.
//
// age refuses to mix scrypt identities with others in one call, so the header
// (only) is held in memory and each group of identities is tried against it;
// the stream is then decrypted with the recovered file key.
func decryptAge(r io.Reader, keys Keys) (io.Reader, error) {
	_, br, head, err := peekFormat(r)
	if err != nil {
		return nil, err
	}
	var body io.Reader = br
	if !bytes.HasPrefix(head, []byte(ageMagic)) {
		body = armor.NewReader(br)
	}

	ids, err := parseAgeIdentities(keys.AgeIdentities)
	if err != nil {
		return nil, err
	}

	rr := newReplayReader(body)
	header, err := age.ExtractHeader(rr)
	if err != nil {
		return nil, fmt.Errorf("encryptor: age: %w", err)
	}
	hasScrypt, hasOther := ageStanzaKinds(header)

	var groups [][]age.Identity
	if hasOther && len(ids) > 0 {
		groups = append(groups, ids)
	}
	if hasScrypt {
		for _, p := range keys.AgePassphrases {
			if len(p) == 0 {
				continue
			}
			id, err := age.NewScryptIdentity(string(p))
			if err != nil {
				return nil, fmt.Errorf("encryptor: age passphrase: %w", err)
			}
			groups = append(groups, []age.Identity{id})
		}
	}
	if len(groups) == 0 {
		need := "an identity"
		if hasScrypt {
			need = "a passphrase"
		}
		return nil, fmt.Errorf("%w: age file needs %s", ErrNoKey, need)
	}

	var lastErr error
	for _, g := range groups {
		fileKey, err := age.DecryptHeader(header, g...)
		if err != nil {
			lastErr = err
			continue
		}
		rr.rewind()
		rr.commit()
		plain, err := age.Decrypt(rr, age.NewInjectedFileKeyIdentity(fileKey))
		if err != nil {
			return nil, fmt.Errorf("encryptor: age: %w", err)
		}
		return &ageBodyReader{r: plain}, nil
	}
	return nil, fmt.Errorf("%w: age: %v", ErrWrongKey, lastErr)
}

// ageStanzaKinds reports whether an age header has scrypt and/or other
// recipient stanzas.
func ageStanzaKinds(header []byte) (scrypt, other bool) {
	sc := bufio.NewScanner(bytes.NewReader(header))
	sc.Buffer(make([]byte, 0, 4096), maxProbeBytes)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "-> ") {
			continue
		}
		fields := strings.Fields(line[3:])
		if len(fields) > 0 && fields[0] == "scrypt" {
			scrypt = true
		} else {
			other = true
		}
	}
	return scrypt, other
}

type ageBodyReader struct{ r io.Reader }

func (a *ageBodyReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("encryptor: age: %w", err)
	}
	return n, err
}
