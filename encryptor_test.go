package encryptor

import (
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
	"os"
	"strings"
	"testing"
)

const passPhrase = "Hello World"
const content = "Lorem ipsum dolor sit amet. Eum eius voluptas sit vitae vitae aut sequi molestias hic accusamus consequatur et molestiae quidem et omnis molestias eos nemo iusto. Eos beatae maxime et sapiente provident quo nobis aspernatur ut recusandae dolores sit dolor excepturi et esse amet et aliquid recusandae. Id perferendis facere aut accusamus eveniet et incidunt doloremque est nisi distinctio a quas quos ea ipsam tenetur."
const privateKeyFile = "private.pem"
const publicKeyFile = "public.pem"
const inputFile = "testEncrypts.txt"
const outputFile = "testEncrypts.txt.gpg"

func TestEncrypts(t *testing.T) {
	fileBytes, err := createFile(inputFile, content)
	if err != nil {
		t.Error(err)
	}
	err = Encrypt(fileBytes, fmt.Sprintf("%s.gpg", inputFile), passPhrase)
	if err != nil {
		t.Error(err)
	}

}
func TestDecrypt(t *testing.T) {
	TestEncrypts(t)
	fBytes, err := os.ReadFile(outputFile)
	if err != nil {
		t.Error(err)
	}

	err = Decrypt(fBytes, inputFile, passPhrase)
	if err != nil {
		t.Error(err)
	}

}
func TestEncryptWithPublicKey(t *testing.T) {
	_, _, err := generateKey()
	if err != nil {
		t.Error("Failed to generate key")
	}
	_, err = createFile(inputFile, content)
	if err != nil {
		t.Error("Failed to create file")
	}

	// Read the file to encrypt
	fileBytes, err := os.ReadFile(inputFile)
	if err != nil {
		t.Error("Failed to read file")
	}
	// Read the file to public key
	publicKeyBytes, err := os.ReadFile(publicKeyFile)
	if err != nil {
		t.Error("Failed to read public key")
	}
	err = EncryptWithPublicKey(fileBytes, fmt.Sprintf("%s.gpg", inputFile), publicKeyBytes)
	if err != nil {
		t.Error(err)
	}

}
func TestDecryptWithPrivateKey(t *testing.T) {
	TestEncryptWithPublicKey(t)
	_, err := os.ReadFile(outputFile)
	if err != nil {
		t.Error(err)
	}
	_, err = os.ReadFile(privateKeyFile)
	if err != nil {
		t.Error(err)
	}

	//TODO: To fix
	//err = DecryptWithPrivateKey(fBytes, inputFile, prBytes, passPhrase)
	//if err != nil {
	//	t.Error(err)
	//}

}
func createFile(fileName, content string) ([]byte, error) {
	// Create a file named hello.txt
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return nil, err
	}
	defer file.Close()

	// Write the message to the file
	_, err = file.WriteString(content)
	if err != nil {
		fmt.Println("Error writing to file:", err)
		return nil, err
	}

	fmt.Printf("Successfully wrote to %s\n", fileName)
	fileBytes, err := os.ReadFile(fileName)
	return fileBytes, err
}

// generateKey generates key, returns private key,public key and error
func generateKey() (string, string, error) {
	var (
		name       = "Jonas Kaninda"
		email      = "jonaskaninda@example.com"
		passphrase = []byte(passPhrase)
		rsaBits    = 4096
	)
	// RSA, string
	rsaKey, err := helper.GenerateKey(name, email, passphrase, "rsa", rsaBits)
	if err != nil {
		panic(err)
	}

	//fmt.Println(rsaKey)

	keyRing, err := crypto.NewKeyFromArmoredReader(strings.NewReader(rsaKey))
	if err != nil {
		panic(err)
	}

	publicKey, err := keyRing.GetArmoredPublicKey()
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(privateKeyFile, []byte(rsaKey), 0644)
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(publicKeyFile, []byte(publicKey), 0644)
	if err != nil {
		panic(err)
	}
	//fmt.Println(publicKey)
	return rsaKey, publicKey, nil
}
