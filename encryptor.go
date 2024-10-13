// Package encryptor /
/*****
@author    Jonas Kaninda
@license   MIT License <https://opensource.org/licenses/MIT>
@Copyright © 2024 Jonas Kaninda
**/
package encryptor

import (
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"os"
)

// Encrypt encrypts a file using a passphrase
func Encrypt(inputFileBytes []byte, outputFile string, passphrase string) error {
	// Define the passphrase to encrypt the file
	_passphrase := []byte(passphrase)

	// Create a message object from the file content
	message := crypto.NewPlainMessage(inputFileBytes)
	// Encrypt the message using the passphrase
	encryptedMessage, err := crypto.EncryptMessageWithPassword(message, _passphrase)
	if err != nil {
		return errors.New(fmt.Sprintf("Error encrypting file: %s", err))
	}
	// Save the encrypted file
	err = os.WriteFile(outputFile, encryptedMessage.GetBinary(), 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving encrypted filee: %s", err))
	}
	return nil
}

// EncryptWithPublicKey encrypts a file using a public key
func EncryptWithPublicKey(inputFileBytes []byte, outputFile string, pubKeyBytes []byte) error {
	// Create a new keyring with the public key
	publicKeyObj, err := crypto.NewKeyFromArmored(string(pubKeyBytes))
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing public key: %s", err))
	}

	keyRing, err := crypto.NewKeyRing(publicKeyObj)
	if err != nil {

		return errors.New(fmt.Sprintf("Error creating key ring: %v", err))
	}

	// encryptWithGPG the file
	message := crypto.NewPlainMessage(inputFileBytes)
	encMessage, err := keyRing.Encrypt(message, nil)
	if err != nil {
		return errors.New(fmt.Sprintf("Error encrypting file: %v", err))
	}

	// Save the encrypted file
	err = os.WriteFile(outputFile, encMessage.GetBinary(), 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving encrypted file: %v", err))
	}
	return nil

}

// Decrypt decrypts a file using passphrase
func Decrypt(inputFileBytes []byte, outputFile string, passphrase string) error {
	// Define the passphrase used to encrypt the file
	_passphrase := []byte(passphrase)
	// Create a PGP message object from the encrypted file content
	encryptedMessage := crypto.NewPGPMessage(inputFileBytes)
	// Decrypt the message using the passphrase
	plainMessage, err := crypto.DecryptMessageWithPassword(encryptedMessage, _passphrase)
	if err != nil {
		return errors.New(fmt.Sprintf("Error decrypting file: %s", err))
	}

	// Save the decrypted file (restore it)
	err = os.WriteFile(outputFile, plainMessage.GetBinary(), 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving decrypted file: %s", err))
	}
	return nil
}

// DecryptWithPrivateKey decrypts a file using a private key and passphrase.
func DecryptWithPrivateKey(inputFileBytes []byte, outputFile string, privateKey []byte, passphrase string) error {

	// Read the password for the private key (if it’s password-protected)
	password := []byte(passphrase)

	// Create a key object from the armored private key
	privateKeyObj, err := crypto.NewKeyFromArmored(string(privateKey))
	if err != nil {
		return errors.New(fmt.Sprintf("Error parsing private key: %s", err))
	}

	// Unlock the private key with the password
	if passphrase != "" {
		// Unlock the private key with the password
		_, err = privateKeyObj.Unlock(password)
		if err != nil {
			return errors.New(fmt.Sprintf("Error unlocking private key: %s", err))
		}

	}

	// Create a new keyring with the private key
	keyRing, err := crypto.NewKeyRing(privateKeyObj)
	if err != nil {
		return errors.New(fmt.Sprintf("Error creating key ring: %v", err))
	}

	// decryptWithGPG the file
	encryptedMessage := crypto.NewPGPMessage(inputFileBytes)
	message, err := keyRing.Decrypt(encryptedMessage, nil, 0)
	if err != nil {
		return errors.New(fmt.Sprintf("Error decrypting file: %s", err))
	}

	// Save the decrypted file
	err = os.WriteFile(outputFile, message.GetBinary(), 0644)
	if err != nil {
		return errors.New(fmt.Sprintf("Error saving decrypted file: %s", err))
	}
	return nil
}
