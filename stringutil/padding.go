package stringutil

//StrPadLeft : 특정 문자열로 채우기
func StrPadLeft(input string, padLength int, padString string) string {
	output := padString

	for padLength > len(output) {
		output += output
	}

	if len(input) >= padLength {
		return input
	}

	return output[:padLength-len(input)] + input
}
