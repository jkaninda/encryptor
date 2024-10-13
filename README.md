# Go  Encryptor

## Install
```shell
go get github.com/jkaninda/encryptor
```

## Encrypt using passphrase


```go
fileBytes, err := os.ReadFile("file.txt")
outputFile :="file.txt.gpg"
if err != nil {
fmt.Printf("Error reading file: %s \n", err)
}
err = encryptor.Encrypt(fileBytes, outputFile, "passphrase")
if err != nil {
panic(err)
}
```

## Decrypt using passphrase

```go
fileBytes, err := os.ReadFile("file.txt.gpg")
outputFile :="file.txt"
if err != nil {
fmt.Printf("Error reading file: %s \n", err)
}
err = encryptor.Decrypt(fileBytes, outputFile, "passphrase")
if err != nil {
panic(err)
}
```

## Encrypt using GPG public Key

```go
	fileBytes, err := os.ReadFile("file.txt")
	outputFile := "file.txt.gpg"
	if err != nil {
		fmt.Printf("Error reading file: %s \n", err)
	}
	pubKey, err := os.ReadFile("public_key.asc")
	if err != nil {
		fmt.Printf("Error reading public key: %s ", err)
	}
	err = encryptor.EncryptWithPublicKey(fileBytes, outputFile, pubKey)
	if err != nil {
		panic(err)
	}
```
## Decrypt using GPG private Key

```go

```