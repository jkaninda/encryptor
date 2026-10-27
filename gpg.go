package encryptor

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
)

const pgpMessageType = "PGP MESSAGE"

// gpgConfig matches what gopenpgp v2 (encryptor v0.2 and earlier) produced and what gpg 2.2
// reads: AES-256, SHA-256, iterated+salted S2K with a high count, no
// compression (backups are compressed upstream) and no AEAD (SEIPD v1 + MDC).
func gpgConfig() *packet.Config {
	return &packet.Config{
		DefaultCipher:          packet.CipherAES256,
		DefaultHash:            crypto.SHA256,
		DefaultCompressionAlgo: packet.CompressionNone,
		S2KConfig: &s2k.Config{
			S2KMode:  s2k.IteratedSaltedS2K,
			Hash:     crypto.SHA256,
			S2KCount: 65011712,
		},
	}
}

var gpgHints = &openpgp.FileHints{IsBinary: true}

type gpgEncrypter struct {
	passphrase []byte
	recipients openpgp.EntityList
	opts       options
}

// GPGPassphrase returns an Encrypter producing OpenPGP messages encrypted
// symmetrically with passphrase (AES-256, SHA-256 iterated S2K).
func GPGPassphrase(passphrase []byte, opts ...Option) (Encrypter, error) {
	if len(passphrase) == 0 {
		return nil, errors.New("encryptor: empty GPG passphrase")
	}
	return &gpgEncrypter{passphrase: bytes.Clone(passphrase), opts: buildOptions(opts)}, nil
}

// GPGRecipients returns an Encrypter producing OpenPGP messages encrypted to
// every encryption-capable public key in keys. Each element may be armored or
// binary and may hold several keys. Keys without a usable encryption subkey
// are skipped; it is an error if none remains.
func GPGRecipients(keys [][]byte, opts ...Option) (Encrypter, error) {
	var recipients openpgp.EntityList
	now := time.Now()
	for i, k := range keys {
		el, err := readKeyRing(k)
		if err != nil {
			return nil, fmt.Errorf("encryptor: GPG key %d: %w", i+1, err)
		}
		for _, e := range el {
			if _, ok := e.EncryptionKey(now); ok {
				recipients = append(recipients, e)
			}
		}
	}
	if len(recipients) == 0 {
		return nil, errors.New("encryptor: no encryption-capable GPG public key provided")
	}
	return &gpgEncrypter{recipients: recipients, opts: buildOptions(opts)}, nil
}

func (g *gpgEncrypter) Format() Format { return FormatGPG }

func (g *gpgEncrypter) Fingerprints() []string {
	if len(g.recipients) == 0 {
		return nil
	}
	fps := make([]string, 0, len(g.recipients))
	for _, e := range g.recipients {
		fps = append(fps, fmt.Sprintf("%X", e.PrimaryKey.Fingerprint))
	}
	return fps
}

func (g *gpgEncrypter) Wrap(dst io.Writer) (io.WriteCloser, error) {
	if dst == nil {
		return nil, errors.New("encryptor: nil destination writer")
	}
	out := dst
	var armorW io.WriteCloser
	if g.opts.armor {
		var err error
		armorW, err = armor.Encode(dst, pgpMessageType, nil)
		if err != nil {
			return nil, fmt.Errorf("encryptor: gpg armor: %w", err)
		}
		out = armorW
	}
	var (
		w   io.WriteCloser
		err error
	)
	if g.recipients != nil {
		w, err = openpgp.Encrypt(out, g.recipients, nil, gpgHints, gpgConfig())
	} else {
		w, err = openpgp.SymmetricallyEncrypt(out, g.passphrase, gpgHints, gpgConfig())
	}
	if err != nil {
		return nil, fmt.Errorf("encryptor: gpg encrypt: %w", err)
	}
	sw := &stackedWriter{Writer: w, closers: []io.Closer{w}}
	if armorW != nil {
		sw.closers = append(sw.closers, armorW)
	}
	return sw, nil
}

// readKeyRing parses one or more OpenPGP keys, armored (possibly several
// concatenated armor blocks) or binary.
func readKeyRing(data []byte) (openpgp.EntityList, error) {
	text := bytes.TrimSpace(data)
	if len(text) == 0 {
		return nil, errors.New("empty key")
	}
	const begin = "-----BEGIN PGP "
	if !bytes.HasPrefix(text, []byte(begin)) {
		// Binary: never trim, trailing bytes may legitimately be whitespace values.
		return openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	var all openpgp.EntityList
	s := string(text)
	for len(s) > 0 {
		next := strings.Index(s[len(begin):], begin)
		block := s
		if next >= 0 {
			block, s = s[:next+len(begin)], s[next+len(begin):]
		} else {
			s = ""
		}
		el, err := openpgp.ReadArmoredKeyRing(strings.NewReader(block))
		if err != nil {
			return nil, err
		}
		all = append(all, el...)
	}
	return all, nil
}

// decryptGPG decrypts an OpenPGP message (armored or binary) from r.
func decryptGPG(r io.Reader, keys Keys) (io.Reader, error) {
	body, err := dearmorGPG(r)
	if err != nil {
		return nil, err
	}

	// Unlock private keys up front, so ReadMessage never has to prompt.
	var keyring openpgp.EntityList
	var lockedErr error
	for i, k := range keys.GPGPrivateKeys {
		el, err := readKeyRing(k)
		if err != nil {
			return nil, fmt.Errorf("encryptor: GPG private key %d: %w", i+1, err)
		}
		for _, e := range el {
			if err := unlockEntity(e, keys); err != nil {
				lockedErr = err
				continue
			}
			keyring = append(keyring, e)
		}
	}

	rr := newReplayReader(body)
	hasSKESK, pkeskIDs, err := scanGPGKeyPackets(rr)
	if err != nil {
		return nil, fmt.Errorf("encryptor: gpg: read message header: %w", err)
	}

	type attempt struct {
		keyring    openpgp.EntityList
		passphrase []byte
	}
	var attempts []attempt
	if len(pkeskIDs) > 0 && len(keyring) > 0 {
		attempts = append(attempts, attempt{keyring: keyring})
	}
	if hasSKESK {
		for _, p := range keys.GPGPassphrases {
			if len(p) > 0 {
				attempts = append(attempts, attempt{passphrase: p})
			}
		}
	}
	if len(attempts) == 0 {
		if len(pkeskIDs) > 0 && lockedErr != nil {
			return nil, fmt.Errorf("%w: gpg: %v", ErrWrongKey, lockedErr)
		}
		return nil, fmt.Errorf("%w: gpg message needs %s", ErrNoKey, describeGPGNeeds(hasSKESK, pkeskIDs))
	}

	var lastErr error
	for _, a := range attempts {
		rr.rewind()
		md, err := openpgp.ReadMessage(rr, a.keyring, oncePrompt(a.passphrase), gpgConfig())
		if errors.Is(err, errProbeTooLarge) {
			return nil, err
		}
		if err != nil {
			lastErr = err
			continue
		}
		rr.commit()
		return &gpgBodyReader{md: md}, nil
	}
	if lockedErr != nil && lastErr == nil {
		lastErr = lockedErr
	}
	return nil, fmt.Errorf("%w: gpg: %v", ErrWrongKey, lastErr)
}

func describeGPGNeeds(hasSKESK bool, ids []uint64) string {
	var parts []string
	if hasSKESK {
		parts = append(parts, "a passphrase")
	}
	if len(ids) > 0 {
		hex := make([]string, len(ids))
		for i, id := range ids {
			hex[i] = fmt.Sprintf("%016X", id)
		}
		parts = append(parts, "a private key ("+strings.Join(hex, ", ")+")")
	}
	if len(parts) == 0 {
		return "a key"
	}
	return strings.Join(parts, " or ")
}

func dearmorGPG(r io.Reader) (io.Reader, error) {
	_, br, head, err := peekFormat(r)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(bytes.TrimLeft(head, " \t\r\n"), []byte(pgpArmorHeader)) {
		return br, nil
	}
	block, err := armor.Decode(br)
	if err != nil {
		return nil, fmt.Errorf("encryptor: gpg armor: %w", err)
	}
	if block.Type != pgpMessageType {
		return nil, fmt.Errorf("encryptor: gpg armor: unexpected block type %q", block.Type)
	}
	return block.Body, nil
}

// scanGPGKeyPackets reads the session-key packets of a message, reporting
// whether it has a passphrase (SKESK) packet and the key IDs of public-key
// (PKESK) packets, then rewinds rr.
func scanGPGKeyPackets(rr *replayReader) (hasSKESK bool, ids []uint64, err error) {
	defer rr.rewind()
	pr := packet.NewReader(rr)
	for {
		p, err := pr.Next()
		if err != nil {
			return false, nil, err
		}
		switch p := p.(type) {
		case *packet.SymmetricKeyEncrypted:
			hasSKESK = true
		case *packet.EncryptedKey:
			ids = append(ids, p.KeyId)
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			return hasSKESK, ids, nil
		case *packet.LiteralData, *packet.Compressed, *packet.OnePassSignature:
			return false, nil, errors.New("message is not encrypted")
		}
	}
}

// unlockEntity decrypts every encrypted private key and subkey of e with the
// first candidate passphrase that works.
func unlockEntity(e *openpgp.Entity, keys Keys) error {
	if !entityLocked(e) {
		return nil
	}
	candidates := [][]byte{keys.GPGPrivateKeyPassphrase}
	if len(keys.GPGPrivateKeyPassphrase) == 0 {
		candidates = keys.GPGPassphrases
	}
	for _, p := range candidates {
		if len(p) == 0 {
			continue
		}
		if err := e.DecryptPrivateKeys(p); err == nil && !entityLocked(e) {
			return nil
		}
	}
	return fmt.Errorf("cannot unlock private key %X: wrong or missing private key passphrase", e.PrimaryKey.Fingerprint)
}

func entityLocked(e *openpgp.Entity) bool {
	if e.PrivateKey != nil && !e.PrivateKey.Dummy() && e.PrivateKey.Encrypted {
		return true
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Dummy() && sub.PrivateKey.Encrypted {
			return true
		}
	}
	return false
}

// oncePrompt answers ReadMessage's prompt with passphrase for a symmetric
// message once; any further call (or a request to unlock keys) fails, so
// ReadMessage never loops.
func oncePrompt(passphrase []byte) openpgp.PromptFunction {
	asked := false
	return func(_ []openpgp.Key, symmetric bool) ([]byte, error) {
		if asked || !symmetric || len(passphrase) == 0 {
			return nil, errors.New("no matching key or passphrase")
		}
		asked = true
		return passphrase, nil
	}
}

// gpgBodyReader surfaces integrity (MDC/AEAD) errors from the plaintext body
// and, for signed messages verified against a known key, signature errors at
// EOF.
type gpgBodyReader struct {
	md *openpgp.MessageDetails
}

func (g *gpgBodyReader) Read(p []byte) (int, error) {
	n, err := g.md.UnverifiedBody.Read(p)
	if err == io.EOF {
		if g.md.IsSigned && g.md.SignedBy != nil && g.md.SignatureError != nil {
			return n, fmt.Errorf("encryptor: gpg signature: %w", g.md.SignatureError)
		}
		return n, io.EOF
	}
	if err != nil {
		return n, fmt.Errorf("encryptor: gpg: %w", err)
	}
	return n, nil
}
