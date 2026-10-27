package encryptor

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Fixtures in testdata/ were produced by:
//   - v1_*: encryptor v0.2 and earlier (gopenpgp v2): Encrypt, EncryptWithPublicKey, EncryptString
//   - gpgcli_*: gpg 2.5 (--symmetric, --symmetric --armor, -r <fixture key>)
//   - agecli_*: age 1.3 (-r age1..., -a -r age1..., -R ssh_ed25519.pub)
//
// GPG fixture key: fixture_{public,private}.asc (private key passphrase
// "fixture-key-pass"); symmetric passphrase "fixture-pass".
func TestDecryptFixtures(t *testing.T) {
	plain := readTestdata(t, "plaintext.txt")
	gpgKey := Keys{
		GPGPrivateKeys:          [][]byte{readTestdata(t, "fixture_private.asc")},
		GPGPrivateKeyPassphrase: []byte(fixtureKeyPw),
	}
	gpgPass := Keys{GPGPassphrases: [][]byte{[]byte(fixturePass)}}
	ageX := Keys{AgeIdentities: []string{string(readTestdata(t, "age_identity.txt"))}}
	ageSSH := Keys{AgeIdentities: []string{string(readTestdata(t, "ssh_ed25519_identity"))}}

	cases := []struct {
		file string
		keys Keys
		want Format
	}{
		{"v1_passphrase.gpg", gpgPass, FormatGPG},
		{"v1_pubkey.gpg", gpgKey, FormatGPG},
		{"gpgcli_symmetric.gpg", gpgPass, FormatGPG},
		{"gpgcli_symmetric.asc", gpgPass, FormatGPG},
		{"gpgcli_pubkey.gpg", gpgKey, FormatGPG},
		{"agecli_x25519.age", ageX, FormatAge},
		{"agecli_x25519.asc", ageX, FormatAge},
		{"agecli_ssh.age", ageSSH, FormatAge},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			got, f, err := decryptAll(bytes.NewReader(readTestdata(t, tc.file)), tc.keys)
			if err != nil {
				t.Fatal(err)
			}
			if f != tc.want {
				t.Fatalf("format %v, want %v", f, tc.want)
			}
			if !bytes.Equal(got, plain) {
				t.Fatal("plaintext mismatch")
			}
		})
	}

	t.Run("v1_string.asc", func(t *testing.T) {
		got, err := DecryptString(string(readTestdata(t, "v1_string.asc")), fixturePass)
		if err != nil || string(got) != "v1 secret value" {
			t.Fatalf("DecryptString = %q, %v", got, err)
		}
	})
}

// TestCLIInterop encrypts with this package and decrypts with the gpg and age
// command line tools.
func TestCLIInterop(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	plain := readTestdata(t, "plaintext.txt")

	t.Run("gpg", func(t *testing.T) {
		gpg, err := exec.LookPath("gpg")
		if err != nil {
			t.Skip("gpg not on PATH")
		}
		// gpg-agent's socket path must be short; t.TempDir can exceed the limit.
		home, err := os.MkdirTemp("/tmp", "encgpg")
		if err != nil {
			t.Skip("cannot create short GNUPGHOME:", err)
		}
		t.Cleanup(func() {
			kill := exec.Command("gpgconf", "--kill", "all")
			kill.Env = append(os.Environ(), "GNUPGHOME="+home)
			_ = kill.Run()
			_ = os.RemoveAll(home)
		})
		run := func(stdin []byte, args ...string) []byte {
			t.Helper()
			cmd := exec.Command(gpg, append([]string{"--batch", "--quiet", "--pinentry-mode", "loopback", "--no-auto-key-locate"}, args...)...)
			cmd.Env = append(os.Environ(), "GNUPGHOME="+home)
			cmd.Stdin = bytes.NewReader(stdin)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("gpg %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
			}
			return out
		}
		run(nil, "--passphrase", fixtureKeyPw, "--import", filepath.Join("testdata", "fixture_private.asc"))

		pass := encryptBytes(t, must[Encrypter](t)(GPGPassphrase([]byte("cli-pass"))), plain)
		if got := run(pass, "--passphrase", "cli-pass", "--decrypt"); !bytes.Equal(got, plain) {
			t.Fatal("gpg decrypted passphrase message to different bytes")
		}
		passArmor := encryptBytes(t, must[Encrypter](t)(GPGPassphrase([]byte("cli-pass"), WithArmor())), plain)
		if got := run(passArmor, "--passphrase", "cli-pass", "--decrypt"); !bytes.Equal(got, plain) {
			t.Fatal("gpg decrypted armored passphrase message to different bytes")
		}
		keyed := encryptBytes(t, must[Encrypter](t)(GPGRecipients([][]byte{readTestdata(t, "fixture_public.asc")})), plain)
		if got := run(keyed, "--passphrase", fixtureKeyPw, "--decrypt"); !bytes.Equal(got, plain) {
			t.Fatal("gpg decrypted public-key message to different bytes")
		}
	})

	t.Run("age", func(t *testing.T) {
		ageBin, err := exec.LookPath("age")
		if err != nil {
			t.Skip("age not on PATH")
		}
		run := func(stdin []byte, args ...string) []byte {
			t.Helper()
			cmd := exec.Command(ageBin, args...)
			cmd.Stdin = bytes.NewReader(stdin)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("age %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
			}
			return out
		}
		idFile := filepath.Join("testdata", "age_identity.txt")
		recipient := strings.TrimSpace(strings.TrimPrefix(
			grepLine(t, string(readTestdata(t, "age_identity.txt")), "# public key:"), "# public key:"))
		sshPub := strings.TrimSpace(string(readTestdata(t, "ssh_ed25519.pub.txt")))

		for _, armor := range []bool{false, true} {
			var opts []Option
			if armor {
				opts = append(opts, WithArmor())
			}
			ct := encryptBytes(t, must[Encrypter](t)(AgeRecipients([]string{recipient}, opts...)), plain)
			if got := run(ct, "-d", "-i", idFile); !bytes.Equal(got, plain) {
				t.Fatalf("age (armor=%v) decrypted to different bytes", armor)
			}
		}
		ct := encryptBytes(t, must[Encrypter](t)(AgeRecipients([]string{sshPub})), plain)
		if got := run(ct, "-d", "-i", filepath.Join("testdata", "ssh_ed25519_identity")); !bytes.Equal(got, plain) {
			t.Fatal("age decrypted ssh-ed25519 message to different bytes")
		}
		// age -p reads the passphrase from a terminal only, so scrypt files are
		// covered by the Go round trip tests instead.
	})
}

func grepLine(t *testing.T, text, prefix string) string {
	t.Helper()
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	t.Fatalf("no line starting with %q", prefix)
	return ""
}
