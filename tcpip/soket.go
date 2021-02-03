package tcpip

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

//CallSoket : tcp/ip 소켓 통신
func CallSoket(ip string, port string, message string) (string, error) {
	//소켓 연결
	address := ip + ":" + port
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	//소켓 타임 아웃 세팅
	//conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	//메세지 전송
	fmt.Fprintf(conn, message+"\r\n")
	//응답 메세지
	result, _ := bufio.NewReader(conn).ReadString('\n')
	return result, nil
}

//CallCryptoSoket : tcp/ip 소켓 통신
func CallCryptoSoket(ip string, port string, message string, timeout time.Duration) (string, error) {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS10,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	//소켓 연결
	address := ip + ":" + port
	conn, err := tls.Dial("tcp", address, cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	//소켓 타임 아웃 세팅
	//conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.SetDeadline(time.Now().Add(timeout * time.Second))

	//메세지 전송
	fmt.Fprintf(conn, message+"\r\n")
	//응답 메세지
	result, _ := bufio.NewReader(conn).ReadString('\n')
	return result, nil
}

//SoketConnectCheck : tcp/ip 소켓 연결 확인
func SoketConnectCheck(ip string, port string) bool {
	//소켓 연결
	address := ip + ":" + port
	conn, err := net.Dial("tcp", address)
	defer conn.Close()
	if err != nil {
		return false
	}
	return true
}

//CryptoSoketConnectCheck : tcp/ip 소켓 연결 확인
func CryptoSoketConnectCheck(ip string, port string) bool {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	//소켓 연결
	address := ip + ":" + port
	conn, err := tls.Dial("tcp", address, cfg)
	defer conn.Close()
	if err != nil {
		return false
	}
	return true
}

//ReadSoketMessage : tcp/ip 소켓 통신
func ReadSoketMessage(ip string, port string) (string, error) {
	//소켓 연결
	address := ip + ":" + port
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	//응답 메세지
	result, _ := bufio.NewReader(conn).ReadString('\n')
	return result, nil
}

//ReadCryptoSoketMessage : tcp/ip 소켓 통신
func ReadCryptoSoketMessage(ip string, port string, timeout time.Duration) (string, error) {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	//소켓 연결
	address := ip + ":" + port
	conn, err := tls.Dial("tcp", address, cfg)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	//응답 메세지
	result, _ := bufio.NewReader(conn).ReadString('\n')
	return result, nil
}

//ReadSoketMessageOnlySunbot : tcp/ip 소켓 통신, 선봇 전용
func ReadSoketMessageOnlySunbot(ip string, port string) (string, error) {
	//소켓 연결
	address := ip + ":" + port
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	//응답 메세지
	result, _ := bufio.NewReader(conn).ReadString('\n')
	if strings.Contains(result, "Enter password:") {
		fmt.Fprintf(conn, "adept"+"\r\n")
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		result, _ = bufio.NewReader(conn).ReadString('\n')
	}

	return result, nil
}

//CallSoketOnlySunbot : tcp/ip 소켓 통신, 로봇전용
func CallSoketOnlySunbot(ip string, port string, message string) (string, error) {
	//소켓 연결
	address := ip + ":" + port
	conn, err := net.Dial("tcp", address)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	//소켓 타임 아웃 세팅
	//conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	result, _ := bufio.NewReader(conn).ReadString('\n')
	if strings.Contains(result, "Enter password:") {
		fmt.Fprintf(conn, "adept"+"\r\n")
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
		bufio.NewReader(conn).ReadString('\n')
	}

	//메세지 전송
	fmt.Fprintf(conn, message+"\r\n")
	//응답 메세지
	result, _ = bufio.NewReader(conn).ReadString('\n')
	return result, nil
}
