// Package encryptor /
/*****
@author    Jonas Kaninda
@license   MIT License <https://opensource.org/licenses/MIT>
@Copyright © 2024 Jonas Kaninda
**/
package encryptor

import (
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// pgpMessageHeader marks the start of an ASCII-armored PGP message.
const pgpMessageHeader = "-----BEGIN PGP MESSAGE-----"

// outputFileMode is the permission applied to files written by this package.
const outputFileMode = 0o644

// writeOutputFile writes data to outputFile, wrapping any failure with context.
func writeOutputFile(outputFile string, data []byte) error {
	if err := os.WriteFile(outputFile, data, outputFileMode); err != nil {
		return fmt.Errorf("error saving file %q: %w", outputFile, err)
	}
	return nil
}

// EncryptString encrypts data with a passphrase and returns an ASCII-armored
// PGP message suitable for embedding in text/YAML/JSON configuration.
func EncryptString(data []byte, passphrase string) (string, error) {
	message := crypto.NewPlainMessage(data)
	encrypted, err := crypto.EncryptMessageWithPassword(message, []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("error encrypting data: %w", err)
	}
	armored, err := encrypted.GetArmored()
	if err != nil {
		return "", fmt.Errorf("error armoring encrypted data: %w", err)
	}
	return armored, nil
}

// DecryptString decrypts an ASCII-armored PGP message produced by EncryptString
// using the same passphrase.
func DecryptString(armored, passphrase string) ([]byte, error) {
	message, err := crypto.NewPGPMessageFromArmored(armored)
	if err != nil {
		return nil, fmt.Errorf("error reading armored message: %w", err)
	}
	decrypted, err := crypto.DecryptMessageWithPassword(message, []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}
	return decrypted.GetBinary(), nil
}

// IsEncrypted reports whether s looks like an ASCII-armored PGP message.
func IsEncrypted(s string) bool {
	return strings.Contains(s, pgpMessageHeader)
}

// Encrypt encrypts a file using a passphrase
func Encrypt(inputFileBytes []byte, outputFile string, passphrase string) error {
	message := crypto.NewPlainMessage(inputFileBytes)

	encryptedMessage, err := crypto.EncryptMessageWithPassword(message, []byte(passphrase))
	if err != nil {
		return fmt.Errorf("error encrypting file: %w", err)
	}

	return writeOutputFile(outputFile, encryptedMessage.GetBinary())
}

// EncryptWithPublicKey encrypts a file using a public key
func EncryptWithPublicKey(inputFileBytes []byte, outputFile string, pubKeyBytes []byte) error {
	publicKeyObj, err := crypto.NewKeyFromArmored(string(pubKeyBytes))
	if err != nil {
		return fmt.Errorf("error parsing public key: %w", err)
	}

	// Create a new keyring with the public key
	keyRing, err := crypto.NewKeyRing(publicKeyObj)
	if err != nil {
		return fmt.Errorf("error creating key ring: %w", err)
	}

	// Encrypt the file
	message := crypto.NewPlainMessage(inputFileBytes)
	encMessage, err := keyRing.Encrypt(message, nil)
	if err != nil {
		return fmt.Errorf("error encrypting file: %w", err)
	}

	return writeOutputFile(outputFile, encMessage.GetBinary())
}

// Decrypt decrypts a file using passphrase
func Decrypt(inputFileBytes []byte, outputFile string, passphrase string) error {
	// Create a PGP message object from the encrypted file content
	encryptedMessage := crypto.NewPGPMessage(inputFileBytes)

	// Decrypt the message using the passphrase
	plainMessage, err := crypto.DecryptMessageWithPassword(encryptedMessage, []byte(passphrase))
	if err != nil {
		return fmt.Errorf("error decrypting file: %w", err)
	}

	return writeOutputFile(outputFile, plainMessage.GetBinary())
}

// DecryptWithPrivateKey decrypts a file using a private key and passphrase.
func DecryptWithPrivateKey(inputFileBytes []byte, outputFile string, privateKey []byte, passphrase string) error {

	// Create a key object from the armored private key
	privateKeyObj, err := crypto.NewKeyFromArmored(string(privateKey))
	if err != nil {
		return fmt.Errorf("error parsing private key: %w", err)
	}

	if passphrase != "" {
		privateKeyObj, err = privateKeyObj.Unlock([]byte(passphrase))
		if err != nil {
			return fmt.Errorf("error unlocking private key: %w", err)
		}
	}

	// Create a new keyring with the unlocked private key
	keyRing, err := crypto.NewKeyRing(privateKeyObj)
	if err != nil {
		return fmt.Errorf("error creating key ring: %w", err)
	}

	// Decrypt the file
	encryptedMessage := crypto.NewPGPMessage(inputFileBytes)
	message, err := keyRing.Decrypt(encryptedMessage, nil, 0)
	if err != nil {
		return fmt.Errorf("error decrypting file: %w", err)
	}

	return writeOutputFile(outputFile, message.GetBinary())
}
