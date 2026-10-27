package encryptor

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"filippo.io/age"
	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const (
	streamSize    = 20 << 20 // 20 MiB
	fixturePass   = "fixture-pass"
	fixtureKeyPw  = "fixture-key-pass"
	testKeyPass   = "test-key-pass"
	fixtureGPGFpr = "57CB9921904914ABDA3B0C04FD8FDF0C6BADDB97"
)

// genReader returns a deterministic pseudo-random stream of n bytes.
func genReader(seed uint64, n int64) io.Reader {
	var s [32]byte
	s[0] = byte(seed)
	return io.LimitReader(rand.NewChaCha8(s), n)
}

func sumOf(t *testing.T, r io.Reader) ([32]byte, int64) {
	t.Helper()
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, n
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type gpgTestKey struct {
	pubArmored, pubBinary   []byte
	privArmored, privBinary []byte // protected with testKeyPass when protected
	fingerprint             string
}

func newGPGKey(t *testing.T, algo packet.PublicKeyAlgorithm, protect bool) gpgTestKey {
	t.Helper()
	cfg := &packet.Config{Algorithm: algo, RSABits: 2048}
	e, err := openpgp.NewEntity("test", "", "test@example.com", cfg)
	if err != nil {
		t.Fatal(err)
	}
	var k gpgTestKey
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	k.pubBinary = bytes.Clone(buf.Bytes())
	k.pubArmored = armorBytes(t, openpgp.PublicKeyType, k.pubBinary)
	if protect {
		if err := e.EncryptPrivateKeys([]byte(testKeyPass), nil); err != nil {
			t.Fatal(err)
		}
	}
	buf.Reset()
	serialize := e.SerializePrivate
	if protect {
		serialize = e.SerializePrivateWithoutSigning
	}
	if err := serialize(&buf, nil); err != nil {
		t.Fatal(err)
	}
	k.privBinary = bytes.Clone(buf.Bytes())
	k.privArmored = armorBytes(t, openpgp.PrivateKeyType, k.privBinary)
	k.fingerprint = strings.ToUpper(e.PrimaryKey.KeyIdString())
	return k
}

func armorBytes(t *testing.T, typ string, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, typ, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func newAgeIdentity(t *testing.T) (identity, recipient string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return "# created: test\n# public key: " + id.Recipient().String() + "\n" + id.String() + "\n", id.Recipient().String()
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// encryptBytes encrypts src fully into memory (for small payloads).
func encryptBytes(t *testing.T, e Encrypter, src []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	n, err := EncryptStream(&buf, bytes.NewReader(src), e)
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(src)) {
		t.Fatalf("EncryptStream copied %d bytes, want %d", n, len(src))
	}
	return buf.Bytes()
}

func decryptAll(r io.Reader, keys Keys) ([]byte, Format, error) {
	plain, f, err := Decrypt(r, keys)
	if err != nil {
		return nil, f, err
	}
	b, err := io.ReadAll(plain)
	return b, f, err
}

type roundTripCase struct {
	name   string
	enc    Encrypter
	keys   Keys
	format Format
	armor  bool
}

func roundTripCases(t *testing.T) []roundTripCase {
	gpgFixturePriv := readTestdata(t, "fixture_private.asc")
	k1 := newGPGKey(t, packet.PubKeyAlgoEdDSA, false)
	k2 := newGPGKey(t, packet.PubKeyAlgoRSA, true)
	ageID, ageRcpt := newAgeIdentity(t)
	sshPub := strings.TrimSpace(string(readTestdata(t, "ssh_ed25519.pub.txt")))
	sshPriv := string(readTestdata(t, "ssh_ed25519_identity"))
	m := must[Encrypter](t)

	return []roundTripCase{
		{"gpg-passphrase", m(GPGPassphrase([]byte("s3cret"))), Keys{GPGPassphrases: [][]byte{[]byte("s3cret")}}, FormatGPG, false},
		{"gpg-passphrase-armor", m(GPGPassphrase([]byte("s3cret"), WithArmor())), Keys{GPGPassphrases: [][]byte{[]byte("s3cret")}}, FormatGPG, true},
		{"gpg-recipient-armored-key-protected", m(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")})),
			Keys{GPGPrivateKeys: [][]byte{gpgFixturePriv}, GPGPrivateKeyPassphrase: []byte(fixtureKeyPw)}, FormatGPG, false},
		{"gpg-recipient-binary-key-armor-out", m(GPGRecipients([][]byte{readTestdata(t, "fixture_public.gpg")}, WithArmor())),
			Keys{GPGPrivateKeys: [][]byte{gpgFixturePriv}, GPGPassphrases: [][]byte{[]byte("nope"), []byte(fixtureKeyPw)}}, FormatGPG, true},
		{"gpg-multi-recipient-binary-unprotected", m(GPGRecipients([][]byte{append(bytes.Clone(k1.pubBinary), k2.pubBinary...)})),
			Keys{GPGPrivateKeys: [][]byte{k1.privBinary}}, FormatGPG, false},
		{"gpg-multi-recipient-rsa-protected", m(GPGRecipients([][]byte{k1.pubArmored, k2.pubArmored})),
			Keys{GPGPrivateKeys: [][]byte{k2.privArmored}, GPGPrivateKeyPassphrase: []byte(testKeyPass)}, FormatGPG, false},
		{"age-x25519", m(AgeRecipients([]string{ageRcpt})), Keys{AgeIdentities: []string{ageID}}, FormatAge, false},
		{"age-x25519-armor", m(AgeRecipients([]string{ageRcpt}, WithArmor())), Keys{AgeIdentities: []string{ageID}}, FormatAge, true},
		{"age-ssh-ed25519", m(AgeRecipients([]string{sshPub, ageRcpt})), Keys{AgeIdentities: []string{sshPriv}}, FormatAge, false},
		{"age-passphrase", m(AgePassphrase([]byte("pw"))), Keys{AgePassphrases: [][]byte{[]byte("pw")}}, FormatAge, false},
		{"age-passphrase-armor", m(AgePassphrase([]byte("pw"), WithArmor())), Keys{AgePassphrases: [][]byte{[]byte("pw")}}, FormatAge, true},
	}
}

// TestRoundTripStreaming pushes 20 MiB through encrypt -> io.Pipe -> decrypt
// for every mode. With an unbuffered pipe, Decrypt can only return (and the
// plaintext be read) while encryption is still running, so both directions
// must stream.
func TestRoundTripStreaming(t *testing.T) {
	for i, tc := range roundTripCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.enc.Format() != tc.format {
				t.Fatalf("Format() = %v, want %v", tc.enc.Format(), tc.format)
			}
			want, _ := sumOf(t, genReader(uint64(i), streamSize))

			pr, pw := io.Pipe()
			var cipherBytes atomic.Int64
			go func() {
				_, err := EncryptStream(&countWriter{w: pw, n: &cipherBytes}, genReader(uint64(i), streamSize), tc.enc)
				_ = pw.CloseWithError(err)
			}()

			var head bytes.Buffer
			plain, f, err := Decrypt(io.TeeReader(pr, &limitedBuffer{buf: &head, max: 64}), tc.keys)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if f != tc.format {
				t.Fatalf("detected %v, want %v", f, tc.format)
			}
			if got := cipherBytes.Load(); got >= streamSize {
				t.Fatalf("Decrypt returned only after %d ciphertext bytes were written: not streaming", got)
			}
			got, n := sumOf(t, plain)
			if n != streamSize || got != want {
				t.Fatalf("round trip mismatch: %d bytes", n)
			}
			isArmor := bytes.HasPrefix(head.Bytes(), []byte("-----BEGIN"))
			if isArmor != tc.armor {
				t.Fatalf("armored output = %v, want %v (head %q)", isArmor, tc.armor, head.Bytes())
			}
		})
	}
}

type countWriter struct {
	w io.Writer
	n *atomic.Int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n.Add(int64(n))
	return n, err
}

type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// TestWrapDoesNotBuffer checks that ciphertext reaches dst while input is
// still being written, i.e. Wrap does not accumulate the whole plaintext.
func TestWrapDoesNotBuffer(t *testing.T) {
	for _, tc := range roundTripCases(t) {
		t.Run(tc.name, func(t *testing.T) {
			var n atomic.Int64
			dst := &countWriter{w: io.Discard, n: &n}
			w, err := tc.enc.Wrap(dst)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(w, genReader(1, 4<<20)); err != nil {
				t.Fatal(err)
			}
			if got := n.Load(); got < 3<<20 {
				t.Fatalf("only %d ciphertext bytes emitted after 4 MiB of input", got)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if n.Load() < 4<<20 {
				t.Fatalf("ciphertext shorter than plaintext: %d", n.Load())
			}
		})
	}
}

// Close must not close the destination writer.
func TestCloseDoesNotCloseDst(t *testing.T) {
	for _, tc := range roundTripCases(t) {
		if !strings.Contains(tc.name, "armor") && tc.name != "gpg-passphrase" && tc.name != "age-x25519" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			dst := &closeTracker{}
			w, err := tc.enc.Wrap(dst)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = w.Write([]byte("hello"))
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			if dst.closed {
				t.Fatal("Close closed the destination writer")
			}
		})
	}
}

type closeTracker struct {
	bytes.Buffer
	closed bool
}

func (c *closeTracker) Close() error { c.closed = true; return nil }

func TestDetect(t *testing.T) {
	payload := []byte("detect me")
	gpgPass := must[Encrypter](t)(GPGPassphrase([]byte("p")))
	gpgPassArmor := must[Encrypter](t)(GPGPassphrase([]byte("p"), WithArmor()))
	gpgKey := must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")}))
	_, ageRcpt := newAgeIdentity(t)
	ageEnc := must[Encrypter](t)(AgeRecipients([]string{ageRcpt}))
	ageArmor := must[Encrypter](t)(AgeRecipients([]string{ageRcpt}, WithArmor()))

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(bytes.Repeat([]byte("sql "), 100))
	_ = zw.Close()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	_ = tw.WriteHeader(&tar.Header{Name: "data/file.txt", Mode: 0o644, Size: 4})
	_, _ = tw.Write([]byte("data"))
	_ = tw.Close()

	cases := []struct {
		name string
		data []byte
		want Format
	}{
		{"gpg-symmetric-binary", encryptBytes(t, gpgPass, payload), FormatGPG},
		{"gpg-symmetric-armor", encryptBytes(t, gpgPassArmor, payload), FormatGPG},
		{"gpg-pubkey-binary", encryptBytes(t, gpgKey, payload), FormatGPG},
		{"gpg-cli-symmetric", readTestdata(t, "gpgcli_symmetric.gpg"), FormatGPG},
		{"gpg-cli-symmetric-armor", readTestdata(t, "gpgcli_symmetric.asc"), FormatGPG},
		{"gpg-cli-pubkey", readTestdata(t, "gpgcli_pubkey.gpg"), FormatGPG},
		{"gpg-v1-passphrase", readTestdata(t, "v1_passphrase.gpg"), FormatGPG},
		{"gpg-v1-pubkey", readTestdata(t, "v1_pubkey.gpg"), FormatGPG},
		{"age-binary", encryptBytes(t, ageEnc, payload), FormatAge},
		{"age-armor", encryptBytes(t, ageArmor, payload), FormatAge},
		{"age-armor-leading-newline", append([]byte("\n"), encryptBytes(t, ageArmor, payload)...), FormatAge},
		{"age-cli", readTestdata(t, "agecli_x25519.age"), FormatAge},
		{"age-cli-armor", readTestdata(t, "agecli_x25519.asc"), FormatAge},
		{"gzip", gz.Bytes(), FormatNone},
		{"zstd", []byte{0x28, 0xb5, 0x2f, 0xfd, 0x04, 0x00, 0x51, 0x00}, FormatNone},
		{"xz", []byte{0xfd, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x04}, FormatNone},
		{"plain-sql", []byte("-- PostgreSQL database dump\nCREATE TABLE t (id int);\n"), FormatNone},
		{"tar", tarBuf.Bytes(), FormatNone},
		{"empty", nil, FormatNone},
		{"one-byte", []byte{0x8c}, FormatNone},
		{"pgp-public-key-block", readTestdata(t, "fixture_public.asc"), FormatNone},
		{"pgp-binary-public-key", readTestdata(t, "fixture_public.gpg"), FormatNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, r, err := Detect(bytes.NewReader(tc.data))
			if err != nil {
				t.Fatal(err)
			}
			if f != tc.want {
				t.Fatalf("Detect = %v, want %v", f, tc.want)
			}
			replay, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(replay, tc.data) {
				t.Fatal("reader returned by Detect does not replay the input")
			}
			if tc.want == FormatNone {
				plain, f, err := Decrypt(bytes.NewReader(tc.data), Keys{})
				if err != nil || f != FormatNone {
					t.Fatalf("Decrypt on plain data: %v, %v", f, err)
				}
				if b, _ := io.ReadAll(plain); !bytes.Equal(b, tc.data) {
					t.Fatal("Decrypt did not pass plain data through")
				}
			}
		})
	}
}

func TestDecryptErrors(t *testing.T) {
	payload := []byte("secret payload")
	ageID, ageRcpt := newAgeIdentity(t)
	otherAgeID, _ := newAgeIdentity(t)
	other := newGPGKey(t, packet.PubKeyAlgoEdDSA, false)
	gpgPriv := readTestdata(t, "fixture_private.asc")

	gpgPassCT := encryptBytes(t, must[Encrypter](t)(GPGPassphrase([]byte("right"))), payload)
	gpgKeyCT := encryptBytes(t, must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")})), payload)
	ageKeyCT := encryptBytes(t, must[Encrypter](t)(AgeRecipients([]string{ageRcpt})), payload)
	agePassCT := encryptBytes(t, must[Encrypter](t)(AgePassphrase([]byte("right"))), payload)

	cases := []struct {
		name string
		ct   []byte
		keys Keys
		want error
	}{
		{"gpg-pass-none", gpgPassCT, Keys{}, ErrNoKey},
		{"gpg-pass-only-age-keys", gpgPassCT, Keys{AgePassphrases: [][]byte{[]byte("right")}}, ErrNoKey},
		{"gpg-pass-wrong", gpgPassCT, Keys{GPGPassphrases: [][]byte{[]byte("wrong")}}, ErrWrongKey},
		{"gpg-pass-several-wrong", gpgPassCT, Keys{GPGPassphrases: [][]byte{[]byte("a"), []byte("b"), []byte("c")}}, ErrWrongKey},
		{"gpg-key-passphrase-only", gpgKeyCT, Keys{GPGPassphrases: [][]byte{[]byte("right")}}, ErrNoKey},
		{"gpg-key-other-private-key", gpgKeyCT, Keys{GPGPrivateKeys: [][]byte{other.privArmored}}, ErrWrongKey},
		{"gpg-key-wrong-key-passphrase", gpgKeyCT, Keys{GPGPrivateKeys: [][]byte{gpgPriv}, GPGPrivateKeyPassphrase: []byte("wrong")}, ErrWrongKey},
		{"gpg-key-locked-no-passphrase", gpgKeyCT, Keys{GPGPrivateKeys: [][]byte{gpgPriv}}, ErrWrongKey},
		{"age-key-none", ageKeyCT, Keys{GPGPassphrases: [][]byte{[]byte("x")}}, ErrNoKey},
		{"age-key-passphrase-only", ageKeyCT, Keys{AgePassphrases: [][]byte{[]byte("right")}}, ErrNoKey},
		{"age-key-wrong-identity", ageKeyCT, Keys{AgeIdentities: []string{otherAgeID}}, ErrWrongKey},
		{"age-pass-wrong", agePassCT, Keys{AgePassphrases: [][]byte{[]byte("wrong")}}, ErrWrongKey},
		{"age-pass-identity-only", agePassCT, Keys{AgeIdentities: []string{ageID}}, ErrNoKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := decryptAll(bytes.NewReader(tc.ct), tc.keys)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}

	t.Run("invalid-config", func(t *testing.T) {
		if _, _, err := Decrypt(bytes.NewReader(gpgKeyCT), Keys{GPGPrivateKeys: [][]byte{[]byte("garbage")}}); err == nil {
			t.Fatal("garbage private key accepted")
		}
		if _, _, err := Decrypt(bytes.NewReader(ageKeyCT), Keys{AgeIdentities: []string{"AGE-SECRET-KEY-1NOPE"}}); err == nil {
			t.Fatal("garbage age identity accepted")
		}
	})
}

// A ciphertext with a byte flipped in the middle must never decrypt silently:
// the error comes from Decrypt or, at the latest, from Read at EOF.
func TestTamperedCiphertext(t *testing.T) {
	payload, _ := io.ReadAll(genReader(7, 1<<20))
	ageID, ageRcpt := newAgeIdentity(t)
	cases := []struct {
		name string
		enc  Encrypter
		keys Keys
	}{
		{"gpg-passphrase", must[Encrypter](t)(GPGPassphrase([]byte("p"))), Keys{GPGPassphrases: [][]byte{[]byte("p")}}},
		{"gpg-recipient", must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")})),
			Keys{GPGPrivateKeys: [][]byte{readTestdata(t, "fixture_private.asc")}, GPGPrivateKeyPassphrase: []byte(fixtureKeyPw)}},
		{"age-x25519", must[Encrypter](t)(AgeRecipients([]string{ageRcpt})), Keys{AgeIdentities: []string{ageID}}},
		{"age-passphrase", must[Encrypter](t)(AgePassphrase([]byte("p"))), Keys{AgePassphrases: [][]byte{[]byte("p")}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct := encryptBytes(t, tc.enc, payload)
			// Sanity: untampered decrypts.
			if got, _, err := decryptAll(bytes.NewReader(ct), tc.keys); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("untampered decrypt failed: %v", err)
			}
			for _, pos := range []int{len(ct) / 2, len(ct) - 10} {
				bad := bytes.Clone(ct)
				bad[pos] ^= 0x01
				plain, _, err := Decrypt(bytes.NewReader(bad), tc.keys)
				if err != nil {
					continue
				}
				if _, err := io.Copy(io.Discard, plain); err == nil {
					t.Fatalf("tampered ciphertext (byte %d of %d) decrypted without error", pos, len(ct))
				}
			}
		})
	}
}

// Decrypt tries every candidate key that fits; wrong ones first must not
// prevent the right one from working.
func TestDecryptCandidates(t *testing.T) {
	payload := []byte("candidate payload")
	ageID, ageRcpt := newAgeIdentity(t)
	otherAgeID, _ := newAgeIdentity(t)
	other := newGPGKey(t, packet.PubKeyAlgoEdDSA, true)
	gpgPriv := readTestdata(t, "fixture_private.asc")

	gpgPassCT := encryptBytes(t, must[Encrypter](t)(GPGPassphrase([]byte("right"))), payload)
	gpgPassArmorCT := encryptBytes(t, must[Encrypter](t)(GPGPassphrase([]byte("right"), WithArmor())), payload)
	gpgKeyCT := encryptBytes(t, must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")})), payload)
	ageKeyCT := encryptBytes(t, must[Encrypter](t)(AgeRecipients([]string{ageRcpt})), payload)
	agePassCT := encryptBytes(t, must[Encrypter](t)(AgePassphrase([]byte("right"), WithArmor())), payload)

	wrongs := [][]byte{[]byte("wrong1"), []byte("wrong2"), []byte("wrong3"), []byte("right")}
	everything := Keys{
		GPGPassphrases: wrongs,
		GPGPrivateKeys: [][]byte{other.privArmored, gpgPriv},
		AgeIdentities:  []string{otherAgeID, ageID},
		AgePassphrases: wrongs,
	}
	cases := []struct {
		name string
		ct   []byte
		keys Keys
	}{
		{"gpg-passphrases", gpgPassCT, Keys{GPGPassphrases: wrongs}},
		{"gpg-passphrases-armor", gpgPassArmorCT, Keys{GPGPassphrases: wrongs}},
		{"gpg-wrong-key-then-passphrase", gpgPassCT, Keys{GPGPrivateKeys: [][]byte{other.privArmored}, GPGPassphrases: wrongs}},
		{"gpg-private-key-unlocked-by-gpg-passphrases", gpgKeyCT, Keys{GPGPrivateKeys: [][]byte{other.privArmored, gpgPriv}, GPGPassphrases: [][]byte{[]byte("x"), []byte(fixtureKeyPw)}}},
		{"gpg-keyring-with-several-keys", gpgKeyCT, Keys{GPGPrivateKeys: [][]byte{append(bytes.Clone(other.privArmored), gpgPriv...)}, GPGPrivateKeyPassphrase: []byte(fixtureKeyPw)}},
		{"age-identities", ageKeyCT, Keys{AgeIdentities: []string{otherAgeID, ageID}}},
		{"age-identities-one-file", ageKeyCT, Keys{AgeIdentities: []string{otherAgeID + ageID}}},
		{"age-passphrases", agePassCT, Keys{AgePassphrases: wrongs, AgeIdentities: []string{otherAgeID}}},
		{"everything-gpg-pass", gpgPassCT, everything},
		{"everything-age-key", ageKeyCT, everything},
		{"everything-age-pass", agePassCT, everything},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := decryptAll(bytes.NewReader(tc.ct), tc.keys)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("got %q", got)
			}
		})
	}
	t.Run("everything-gpg-key", func(t *testing.T) {
		k := everything
		k.GPGPrivateKeyPassphrase = []byte(fixtureKeyPw)
		got, _, err := decryptAll(bytes.NewReader(gpgKeyCT), k)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("got %q, %v", got, err)
		}
	})
}

func TestFormat(t *testing.T) {
	for _, tc := range []struct {
		f         Format
		name, ext string
	}{{FormatNone, "none", ""}, {FormatGPG, "gpg", ".gpg"}, {FormatAge, "age", ".age"}} {
		if tc.f.String() != tc.name || tc.f.Ext() != tc.ext {
			t.Errorf("%d: String=%q Ext=%q", tc.f, tc.f.String(), tc.f.Ext())
		}
		got, err := ParseFormat(strings.ToUpper(tc.name))
		if err != nil || got != tc.f {
			t.Errorf("ParseFormat(%q) = %v, %v", tc.name, got, err)
		}
	}
	for in, want := range map[string]Format{"PGP": FormatGPG, "OpenPGP": FormatGPG, " gpg ": FormatGPG, "Age": FormatAge, "": FormatNone} {
		if got, err := ParseFormat(in); err != nil || got != want {
			t.Errorf("ParseFormat(%q) = %v, %v", in, got, err)
		}
	}
	if _, err := ParseFormat("aes"); err == nil {
		t.Error("ParseFormat accepted an unknown format")
	}
}

func TestParseAgeRecipients(t *testing.T) {
	_, r1 := newAgeIdentity(t)
	_, r2 := newAgeIdentity(t)
	ssh := strings.TrimSpace(string(readTestdata(t, "ssh_ed25519.pub.txt")))
	text := "# backup recipients, comma, separated\n\n  " + r1 + " , " + r2 + "\n" + ssh + "\n# trailing comment\n"
	got, err := ParseAgeRecipients(text)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{r1, r2, ssh}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, bad := range []string{"", "# only a comment\n", r1 + ",age1notarecipient", "ssh-ed25519 AAAAnope"} {
		if _, err := ParseAgeRecipients(bad); err == nil {
			t.Errorf("ParseAgeRecipients(%q) accepted invalid input", bad)
		}
	}
}

func TestConstructorsAndFingerprints(t *testing.T) {
	if _, err := GPGPassphrase(nil); err == nil {
		t.Error("GPGPassphrase accepted an empty passphrase")
	}
	if _, err := AgePassphrase([]byte{}); err == nil {
		t.Error("AgePassphrase accepted an empty passphrase")
	}
	if _, err := GPGRecipients(nil); err == nil {
		t.Error("GPGRecipients accepted no keys")
	}
	if _, err := GPGRecipients([][]byte{[]byte("not a key")}); err == nil {
		t.Error("GPGRecipients accepted garbage")
	}
	if _, err := AgeRecipients(nil); err == nil {
		t.Error("AgeRecipients accepted no recipients")
	}
	if _, err := AgeRecipients([]string{"age1bogus"}); err == nil {
		t.Error("AgeRecipients accepted garbage")
	}

	e := must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")}))
	if fp := e.Fingerprints(); len(fp) != 1 || fp[0] != fixtureGPGFpr {
		t.Errorf("GPG fingerprints = %q, want %s", fp, fixtureGPGFpr)
	}
	k1 := newGPGKey(t, packet.PubKeyAlgoEdDSA, false)
	e = must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.gpg"), k1.pubArmored}))
	if fp := e.Fingerprints(); len(fp) != 2 || fp[0] != fixtureGPGFpr || !strings.HasSuffix(fp[1], k1.fingerprint) {
		t.Errorf("GPG fingerprints = %q", fp)
	}
	_, r := newAgeIdentity(t)
	e = must[Encrypter](t)(AgeRecipients([]string{" " + r + " "}))
	if fp := e.Fingerprints(); len(fp) != 1 || fp[0] != r {
		t.Errorf("age fingerprints = %q", fp)
	}
	for _, p := range []Encrypter{must[Encrypter](t)(GPGPassphrase([]byte("x"))), must[Encrypter](t)(AgePassphrase([]byte("x")))} {
		if p.Fingerprints() != nil {
			t.Errorf("%v passphrase Fingerprints() = %v, want nil", p.Format(), p.Fingerprints())
		}
	}
}

func TestKeysEmpty(t *testing.T) {
	if !(Keys{}).Empty() {
		t.Error("zero Keys not empty")
	}
	if !(Keys{GPGPrivateKeyPassphrase: []byte("x")}).Empty() {
		t.Error("a private-key passphrase alone is not decryption material")
	}
	for _, k := range []Keys{
		{GPGPassphrases: [][]byte{[]byte("x")}}, {GPGPrivateKeys: [][]byte{[]byte("x")}},
		{AgeIdentities: []string{"x"}}, {AgePassphrases: [][]byte{[]byte("x")}},
	} {
		if k.Empty() {
			t.Errorf("%+v reported empty", k)
		}
	}
}

func TestStringHelpers(t *testing.T) {
	s, err := EncryptString([]byte("db-password"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !IsEncrypted(s) {
		t.Fatal("IsEncrypted(EncryptString(...)) = false")
	}
	got, err := DecryptString("password: "+s, "pw")
	if err != nil || string(got) != "db-password" {
		t.Fatalf("DecryptString = %q, %v", got, err)
	}
	if _, err := DecryptString(s, "wrong"); err == nil {
		t.Fatal("DecryptString accepted a wrong passphrase")
	}
	if _, err := DecryptString("plain", "pw"); err == nil {
		t.Fatal("DecryptString accepted plain text")
	}
	_, r := newAgeIdentity(t)
	ageArmored := string(encryptBytes(t, must[Encrypter](t)(AgeRecipients([]string{r}, WithArmor())), []byte("x")))
	if !IsEncrypted(ageArmored) {
		t.Fatal("IsEncrypted(age armor) = false")
	}
	if IsEncrypted("hello") {
		t.Fatal("IsEncrypted(plain) = true")
	}
}

// Binary keys must not be whitespace-trimmed: their last byte can be 0x0a,
// 0x20, etc. Generate keys until one ends in such a byte.
func TestBinaryKeyEndingInWhitespaceByte(t *testing.T) {
	for range 2000 {
		k := newGPGKey(t, packet.PubKeyAlgoEdDSA, false)
		last := k.privBinary[len(k.privBinary)-1]
		if !bytes.ContainsRune([]byte(" \t\r\n\v\f"), rune(last)) {
			continue
		}
		if _, err := readKeyRing(k.privBinary); err != nil {
			t.Fatalf("binary key ending in %#x: %v", last, err)
		}
		return
	}
	t.Skip("no generated key ended in a whitespace byte")
}
