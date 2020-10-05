package aes

import "testing"

func TestAESEncrypt(t *testing.T) {

	input := "hello world"
	key := []byte("0123456789abcdef")
	vi := []byte("0123456789abcdef0123456789abcdef")

	cipher, err := EncryptIGE([]byte(input), key, vi)
	if err != nil {
		t.Errorf("encrypt. error: %v\n", err)
		return
	}
	t.Logf("cipher: %#v\n", cipher)
	plain, err := DecryptIGE(cipher, key, vi)
	t.Logf("plain: %x\n", plain)
	if err != nil {
		t.Error(err)
	}
}
