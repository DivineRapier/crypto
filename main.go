package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"runtime"
)

var (
	ErrPaddingSize = errors.New("padding size error please check the secret key or iv")
)

func EncryptAES(key []byte, input, output string) {
	plaintext, err := ioutil.ReadFile(input)
	if err != nil {
		panic(err)
	}

	ciphertext, err := AesCbcEncrypt(plaintext, key)
	if err != nil {
		panic(err)
	}

	// return hex string
	ioutil.WriteFile(output, ciphertext, 0644)
}

func DecryptAES(key []byte, input, output string) {

	ciphertext, err := ioutil.ReadFile(input)
	if err != nil {
		panic(err)
	}

	plaintext, err := AesCbcDecrypt(ciphertext, key)
	if err != nil {
		panic(err)
	}

	ioutil.WriteFile(output, plaintext, 0644)
}

func PKCS5Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - (len(plainText) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	newText := append(plainText, padText...)
	return newText
}

func PKCS5UnPadding(plainText []byte) ([]byte, error) {
	length := len(plainText)
	number := int(plainText[length-1])
	if number >= length {
		return nil, ErrPaddingSize
	}
	return plainText[:length-number], nil
}

func AesCbcEncrypt(plainText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddingText := PKCS5Padding(plainText, block.BlockSize())

	iv := []byte("divinerapier0123")
	blockMode := cipher.NewCBCEncrypter(block, iv)
	cipherText := make([]byte, len(paddingText))
	blockMode.CryptBlocks(cipherText, paddingText)
	return cipherText, nil
}

func AesCbcDecrypt(cipherText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case runtime.Error:
				log.Println("runtime err:", err, "Check that the key or text is correct")
			default:
				log.Println("error:", err)
			}
		}
	}()
	iv := []byte("divinerapier0123")
	blockMode := cipher.NewCBCDecrypter(block, iv)
	paddingText := make([]byte, len(cipherText))
	blockMode.CryptBlocks(paddingText, cipherText)

	plainText, err := PKCS5UnPadding(paddingText)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}

func main() {
	var (
		inputfile, outputfile, key string
		decreypt                   bool
	)
	flag.StringVar(&inputfile, "in", "", "input file path")
	flag.StringVar(&outputfile, "out", "", "output file path")
	flag.StringVar(&key, "key", "", "encrypt key")
	flag.BoolVar(&decreypt, "dec", false, "decrypt the file")
	flag.Parse()
	if decreypt {
		DecryptAES([]byte(key), inputfile, outputfile)
	} else {
		EncryptAES([]byte(key), inputfile, outputfile)
	}
}
