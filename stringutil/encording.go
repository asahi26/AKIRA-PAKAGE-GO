package stringutil

import (
	"bytes"
	"io/ioutil"
	"strings"

	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/transform"
)

//EuckrToUtf8 : Euc-kr에서 Utf-8로 인코딩 변경하기
func EuckrToUtf8(value string) string {
	var b bytes.Buffer
	wInUTF8 := transform.NewWriter(&b, korean.EUCKR.NewEncoder())
	wInUTF8.Write([]byte(value))
	wInUTF8.Close()

	return b.String()
}

//Utf8ToEuckr : Utf-8에서 Euc-kr로 인코딩 하기
func Utf8ToEuckr(value string) string {
	rInUTF8 := transform.NewReader(strings.NewReader(value), korean.EUCKR.NewDecoder())
	decBytes, _ := ioutil.ReadAll(rInUTF8)

	return string(decBytes)
}

//Int32ToString : int32에서 string으로 인코딩 하기
func Int32ToString(n int32) string {
	buf := [11]byte{}
	pos := len(buf)
	i := int64(n)
	signed := i < 0
	if signed {
		i = -i
	}
	for {
		pos--
		buf[pos], i = '0'+byte(i%10), i/10
		if i == 0 {
			if signed {
				pos--
				buf[pos] = '-'
			}
			return string(buf[pos:])
		}
	}
}
