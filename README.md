# Go Encryptor

Streaming OpenPGP (GPG) and [age](https://age-encryption.org) encryption for backup pipelines
(dump → compress → encrypt → upload) with constant memory: nothing is buffered whole.

```shell
go get github.com/jkaninda/encryptor
```

## Encrypt

```go
import "github.com/jkaninda/encryptor"

enc, err := encryptor.GPGPassphrase([]byte(passphrase))                 // or:
enc, err = encryptor.GPGRecipients([][]byte{pubKeyASCOrBinary})          // one or more public keys
enc, err = encryptor.AgeRecipients([]string{"age1…", "ssh-ed25519 …"})   // X25519 / SSH recipients
enc, err = encryptor.AgePassphrase([]byte(passphrase), encryptor.WithArmor())

w, err := enc.Wrap(upload)        // upload is any io.Writer (pipe, S3 multipart writer, file…)
_, err = io.Copy(w, compressed)
err = w.Close()                   // finalises encryption; does NOT close upload

name := "backup.sql.gz" + enc.Format().Ext() // ".gpg" or ".age"
log.Println("recipients", enc.Fingerprints())
```

`EncryptStream(dst, src, enc)` does the Wrap/Copy/Close in one call.
`ParseAgeRecipients(text)` parses a recipients file or a comma separated env var.

GPG output uses AES-256, SHA-256 iterated S2K, no compression and no AEAD (SEIPD v1 + MDC), so it is
readable by `gpg` 2.2+ and by encryptor v0.2 and earlier (gopenpgp).

## Decrypt

```go
plain, format, err := encryptor.Decrypt(download, encryptor.Keys{
    GPGPassphrases:          [][]byte{[]byte(os.Getenv("GPG_PASSPHRASE"))},
    GPGPrivateKeys:          [][]byte{privKey},  // armored or binary
    GPGPrivateKeyPassphrase: []byte(keyPass),    // if empty, GPGPassphrases are tried
    AgeIdentities:           []string{identityFileContents}, // AGE-SECRET-KEY-1… or OpenSSH key
    AgePassphrases:          [][]byte{[]byte(agePass)},
})
switch {
case errors.Is(err, encryptor.ErrNoKey):    // nothing configured fits this file
case errors.Is(err, encryptor.ErrWrongKey): // keys configured, none worked
}
_, err = io.Copy(out, plain) // any Read error (incl. at EOF) means tampering: discard the output
```

The format is detected from the stream's first bytes (`Detect`), so unencrypted input (gzip, zstd, SQL,
tar…) is passed through unchanged with `FormatNone`. All candidate keys are tried; only the encryption
header is held in memory while doing so.

Integrity (OpenPGP MDC, age chunk MACs) is verified while streaming; a failure is returned by `Read`, at
the latest together with EOF. Treat partial output as untrusted until the reader returns `io.EOF`.

Note: OpenPGP v4 symmetric messages have no reliable passphrase check, so in rare cases (≈1 in several
thousand) a wrong candidate passphrase is only detected by the integrity check at EOF instead of by
`Decrypt`. It is still always an error, never silent.

## String helpers

`EncryptString`, `DecryptString` (armored PGP strings, compatible with v0.2 and earlier) and
`IsEncrypted` (PGP or age armor) are kept unchanged.

## Upgrading from v0.2

v0.3 replaces the in-memory, file-writing API with the streaming one above. Files written by
earlier versions decrypt unchanged (they are covered by the test fixtures).

| v0.2 | v0.3 |
|---|---|
| `Encrypt(data, outFile, passphrase)` | `GPGPassphrase(pass)` + `EncryptStream(file, src, enc)` |
| `EncryptWithPublicKey(data, outFile, pubKey)` | `GPGRecipients([][]byte{pubKey})` + `EncryptStream` |
| `Decrypt(data, outFile, passphrase)` | `Decrypt(src, Keys{GPGPassphrases: ...})` + `io.Copy` |
| `DecryptWithPrivateKey(data, outFile, privKey, pass)` | `Decrypt(src, Keys{GPGPrivateKeys: ..., GPGPrivateKeyPassphrase: ...})` |
| `EncryptString`, `DecryptString`, `IsEncrypted` | unchanged |
