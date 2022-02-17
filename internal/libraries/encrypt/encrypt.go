package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

var randomBytes = []byte{
	13,
	30,
	15,
	22,
	72,
	36,
	79,
	61,
	39,
	88,
	57,
	12,
	23,
	78,
	47,
	75,
}

type Encrypt struct {
	Seed []byte
}

func padOrTrim(data string, size int) []byte {
	b := []byte(data)
	l := len(b)
	if l == size {
		return b
	}

	if l > size {
		return b[l-size:]
	}

	tmp := make([]byte, size)
	copy(tmp[size-l:], b)
	return tmp
}

func NewEncrypt(seed string) *Encrypt {
	return &Encrypt{
		Seed: padOrTrim(seed, 32),
	}
}

func Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

func (e *Encrypt) Encrypt(data string) (string, error) {
	block, err := aes.NewCipher(e.Seed)
	if err != nil {
		return "", err
	}

	dataBytes := []byte(data)
	cfb := cipher.NewCFBEncrypter(block, randomBytes)
	ciphertext := make([]byte, len(dataBytes))
	cfb.XORKeyStream(ciphertext, dataBytes)

	return Encode(ciphertext), nil
}

func (e *Encrypt) Decrypt(data string) (string, error) {
	block, err := aes.NewCipher(e.Seed)
	if err != nil {
		return "", err
	}

	cipherText, err := Decode(data)
	if err != nil {
		return "", err
	}

	cfb := cipher.NewCFBDecrypter(block, randomBytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)

	return string(plainText), nil
}
