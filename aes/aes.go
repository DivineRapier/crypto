package aes

import (
	"crypto/aes"
	"crypto/rand"
)

// DecryptIGE decrypts the given text in 16-bytes blocks by using the given
// key in 16 or 24 or 32-bytes for AES-128, AES-192, or AES-256 and 32-bytes
// initialization vector
func DecryptIGE(cipherText, key, iv []byte) ([]byte, error) {
	var (
		cipherTextBlock [16]byte
		plainText       []byte
	)

	iv1 := iv[:len(iv)/2]
	iv2 := iv[len(iv)/2:]

	ciper, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockCount := len(cipherText) / 16

	for blockIndex := 0; blockIndex < blockCount; blockIndex++ {
		for i := 0; i < 16; i++ {
			cipherTextBlock[i] = cipherText[blockIndex*16+i] ^ iv2[i]
		}
		plainTextBlock := make([]byte, 16)
		ciper.Decrypt(plainTextBlock, cipherTextBlock[:])
		for i := 0; i < 16; i++ {
			plainTextBlock[i] ^= iv1[i]
		}
		iv1 = cipherText[blockIndex*16 : blockIndex*16+16]
		iv2 = plainTextBlock

		plainText = append(plainText, plainTextBlock...)
	}

	return plainText, nil
}

// EncryptIGE encrypts the given text in 16-bytes blocks by using the given
// key in 16 or 24 or 32-bytes for AES-128, AES-192, or AES-256 and 32-bytes
// initialization vector
func EncryptIGE(plainText, key, iv []byte) ([]byte, error) {
	padding := len(plainText) % 16
	if padding > 0 {
		var buf [16]byte
		_, err := rand.Read(buf[:])
		if err != nil {
			return nil, err
		}
		plainText = append(plainText, buf[:16-padding]...)
	}

	iv1 := iv[:len(iv)/2]
	iv2 := iv[len(iv)/2:]

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	var cipherText []byte

	blocksCount := len(plainText) / 16

	for blockIndex := 0; blockIndex < blocksCount; blockIndex++ {
		plainTexBlock := plainText[blockIndex*16 : blockIndex*16+16]

		for i := 0; i < 16; i++ {
			plainTexBlock[i] ^= iv1[i]
		}

		var cipherTextBlock [16]byte

		cipher.Encrypt(cipherTextBlock[:], plainTexBlock)

		for i := 0; i < 16; i++ {
			cipherTextBlock[i] ^= iv2[i]
		}

		iv1 = cipherTextBlock[:]
		iv2 = plainText[blockIndex*16 : blockIndex*16+16]

		cipherText = append(cipherText, cipherTextBlock[:]...)
	}

	return cipherText, nil
}
