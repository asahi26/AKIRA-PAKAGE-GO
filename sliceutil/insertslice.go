package sliceutil

//InsertStringSlice : String형 슬라이스 인덱스 별 추가
func InsertStringSlice(array []string, index int, element string) []string {
	result := append(array, element)
	copy(result[index+1:], result[index:])
	result[index] = element
	return result
}
