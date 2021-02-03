package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

//Encryption :  암호화 함수
func Encryption(s Common) (string, error) {
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
	case s.CryptoMode == AesCbcMode && len(s.CryptoIV) != 16:
		return "", errors.New("aes : out of bounds CryptoIV")
	default:
		{
			if s.CryptoMode == AesCbcMode {
				return cbcEncryption(s)
			} else if s.CryptoMode == AesEcbMode {
				return ecbEncryption(s)
			} else {
				return "", errors.New("aes : null poin mode error")
			}
		}
	}
}

//cbcEncryption : CBC 모드 암호화
func cbcEncryption(s Common) (string, error) {
	// AES 대칭키 암호화 블록 생성
	block, err := aes.NewCipher([]byte(s.CryptoKey))
	if err != nil {
		return "", err
	}

	//string byte로 전환
	plaintext := []byte(s.CryptoMessage)
	blockSize := block.BlockSize()

	//요청된 패딩방식 확인
	if s.CryptoPadding == AesPkcs5Padding {
		plaintext = pkcs5Padding(plaintext, blockSize)
	} else {
		plaintext = pkcs7Padding(plaintext, blockSize)
	}

	ciphertext := make([]byte, len(plaintext)) // 초기화 벡터 공간(aes.BlockSize)만큼 더 생성
	iv := []byte(s.CryptoIV)[:blockSize]

	mode := cipher.NewCBCEncrypter(block, iv) // 암호화 블록과 초기화 벡터를 넣어서 암호화 블록 모드 인스턴스 생성
	mode.CryptBlocks(ciphertext, plaintext)   // 암호화 블록 모드 인스턴스로

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

//ecbEncryption : ECB 모드 암호화
func ecbEncryption(s Common) (string, error) {
	// AES 대칭키 암호화 블록 생성
	block, err := aes.NewCipher([]byte(s.CryptoKey))
	if err != nil {
		return "", err
	}

	ecb := newECBEncrypter(block)
	//string byte로 전환
	plaintext := []byte(s.CryptoMessage)
	blockSize := block.BlockSize()

	//요청된 패딩방식 확인
	if s.CryptoPadding == AesPkcs5Padding {
		plaintext = pkcs5Padding(plaintext, blockSize)
	} else {
		plaintext = pkcs7Padding(plaintext, blockSize)
	}

	ciphertext := make([]byte, len(plaintext)) // 초기화 벡터 공간(aes.BlockSize)만큼 더 생성
	ecb.CryptBlocks(ciphertext, plaintext)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

//pkcs5Padding
func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//pkcs7Padding
func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	/*padlen := 1
	for ((len(ciphertext) + padlen) % blockSize) != 0 {
		padlen = padlen + 1
	}
	padtext := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(ciphertext, padtext...)*/

	padding := (blockSize - len(ciphertext)%blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//newECBEncrypter : ECB 모드 생성
func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

func (x *ecbEncrypter) BlockSize() int { return x.blockSize }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
