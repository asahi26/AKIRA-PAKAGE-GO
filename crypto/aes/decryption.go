package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
)

//Decryption :  복호화 함수
func Decryption(s Common) (string, error) {
	switch {
	//암호화 키값 없음
	case s.CryptoKey == "":
		return "", errors.New("aes : null point CryptoKey")
	//CBC코드인데 IV값 없음
	case s.CryptoMode == AesCbcMode && s.CryptoIV == "":
		return "", errors.New("aes : null point CryptoIV")
	//128비트 암호화 방식인데 암호화 키값 길이 안맞음
	case s.CryptoBit == Aes128 && len(s.CryptoKey) != 16:
		return "", errors.New("aes : out of bounds CryptoKey")
	//256비트 암호화 방식인데 암호화 키값 길이 안맞음
	case s.CryptoBit == Aes256 && len(s.CryptoKey) != 32:
		return "", errors.New("aes : out of bounds CryptoKey")
	//CBC코드인데 IV값 길이 안맞음
	case s.CryptoBit == AesCbcMode && len(s.CryptoIV) != 16:
		return "", errors.New("aes : out of bounds CryptoIV")
	default:
		{
			if s.CryptoMode == AesCbcMode {
				return cbcDecryption(s)
			} else if s.CryptoMode == AesEcbMode {
				return ecbDecryption(s)
			} else {
				return "", errors.New("aes : null poin mode error")
			}
		}
	}
}

//cbcDecryption : CBC 모드 복호화
func cbcDecryption(s Common) (string, error) {
	message := strings.Replace(s.CryptoMessage, " ", "+", -1)
	text, _ := base64.StdEncoding.DecodeString(message)

	// AES 대칭키 암호화 블록 생성
	block, err := aes.NewCipher([]byte(s.CryptoKey))
	if err != nil {
		return "", err
	}

	if len(text) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	decrypted := make([]byte, len(text))
	iv := []byte(s.CryptoIV)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, text)

	if s.CryptoPadding == AesPkcs5Padding {
		return string(pkcs5UnPadding(decrypted)[:]), nil
	} else if s.CryptoPadding == AesPkcs7Padding {
		return string(pkcs7UnPadding(decrypted)[:]), nil
	} else {
		return "", errors.New("aes : null poin padding error")
	}
}

//ecbDecryption : ECB 모드 복호화
func ecbDecryption(s Common) (string, error) {
	message := strings.Replace(s.CryptoMessage, " ", "+", -1)
	message = strings.Replace(message, "-", "+", -1)
	text, _ := base64.StdEncoding.DecodeString(message)

	// AES 대칭키 암호화 블록 생성
	block, err := aes.NewCipher([]byte(s.CryptoKey))
	if err != nil {
		return "", err
	}

	decrypted := make([]byte, len(text))
	mode := newECBDecrypter(block)
	mode.CryptBlocks(decrypted, text)

	if s.CryptoPadding == AesPkcs5Padding {
		return string(pkcs5UnPadding(decrypted)[:]), nil
	} else if s.CryptoPadding == AesPkcs7Padding {
		return string(pkcs7UnPadding(decrypted)[:]), nil
	} else {
		return "", errors.New("aes : null poin padding error")
	}
}

//pkcsS5UnPadding
func pkcs5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

//pkcs7UnPadding
func pkcs7UnPadding(src []byte) []byte {
	padlen := int(src[len(src)-1])
	return src[:(len(src) - padlen)]
}

//NewECBDecrypter : ECB모드 생성
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func (x *ecbDecrypter) BlockSize() int { return x.blockSize }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
