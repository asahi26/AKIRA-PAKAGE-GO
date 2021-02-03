package aes

import "crypto/cipher"

//aes암복호화 라이브러리 공통 상수
const (
	Aes128          = "AES128 암호화"
	Aes256          = "AES256 암호화"
	AesEcbMode      = "ECB 대칭키 모드"
	AesCbcMode      = "CBC 대칭키 모드"
	AesPkcs5Padding = "PKCS5 패딩"
	AesPkcs7Padding = "PKCS7 패딩"
)

//Common : aes암복호화 기본 요청 구조
type Common struct {
	CryptoMessage string //암복호화 할 메세지
	CryptoKey     string //암복호화 키
	CryptoIV      string //CBC코드 IV키
	CryptoBit     string //비트 구분
	CryptoMode    string //모드 구분
	CryptoPadding string //패딩 구분
}

//ecb : go에서는 ecb모드를 지원하지 않으므로 자체 제작을 위한 구조체
type ecb struct {
	b         cipher.Block
	blockSize int
}

type ecbEncrypter ecb
type ecbDecrypter ecb

//newECB : ECB 모드 생성
func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}
