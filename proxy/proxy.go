package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	ModeSOCKS5      = 1
	ModeHTTPConnect = 2
	ModeHTTPProxy   = 3
)

// WebSocketClient 接口定义
type WebSocketClient interface {
	DialWithECH(maxRetries int) (*websocket.Conn, error)
}

type ProxyServer struct {
	listenAddr string
	wsClient   WebSocketClient
	proxyIP    string
	bufPool    sync.Pool
}

func NewProxyServer(listenAddr string, wsClient WebSocketClient, proxyIP string) *ProxyServer {
	return &ProxyServer{
		listenAddr: listenAddr,
		wsClient:   wsClient,
		proxyIP:    proxyIP,
		bufPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}
}

func (s *ProxyServer) Run() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("监听失败: %v", err)
	}
	defer listener.Close()

	log.Printf("[代理] 服务器启动: %s (支持SOCKS5和HTTP)", s.listenAddr)
	if s.proxyIP != "" {
		log.Printf("[代理] 回退代理IP: %s", s.proxyIP)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[代理] 接受连接失败: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *ProxyServer) handleConnection(conn net.Conn) {
	if conn == nil {
		return
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	clientAddr := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	firstByte := buf[0]

	switch firstByte {
	case 0x05:
		s.handleSOCKS5(conn, clientAddr, firstByte)
	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		s.handleHTTP(conn, clientAddr, firstByte)
	default:
		log.Printf("[代理] %s 未知协议: 0x%02x", clientAddr, firstByte)
	}
}

func (s *ProxyServer) handleSOCKS5(conn net.Conn, clientAddr string, firstByte byte) {
	if conn == nil {
		return
	}

	if firstByte != 0x05 {
		log.Printf("[SOCKS5] %s 版本错误: 0x%02x", clientAddr, firstByte)
		return
	}

	buf := make([]byte, 1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	nmethods := buf[0]
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}

	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	buf = make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}

	if buf[0] != 5 {
		return
	}

	command := buf[1]
	atyp := buf[3]

	var host string
	switch atyp {
	case 0x01:
		buf = make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()

	case 0x03:
		buf = make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		domainBuf := make([]byte, buf[0])
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)

	case 0x04:
		buf = make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		host = net.IP(buf).String()

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	buf = make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return
	}
	port := int(buf[0])<<8 | int(buf[1])

	if command != 0x01 {
		log.Printf("[SOCKS5] %s 不支持的命令: 0x%02x", clientAddr, command)
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	var target string
	if atyp == 0x04 {
		target = fmt.Sprintf("[%s]:%d", host, port)
	} else {
		target = fmt.Sprintf("%s:%d", host, port)
	}

	log.Printf("[SOCKS5] %s -> %s", clientAddr, target)

	if err := s.handleTunnel(conn, target, clientAddr, ModeSOCKS5, nil); err != nil {
		if !isNormalCloseError(err) {
			log.Printf("[SOCKS5] %s 代理失败: %v", clientAddr, err)
		}
	}
}

func (s *ProxyServer) handleHTTP(conn net.Conn, clientAddr string, firstByte byte) {
	if conn == nil {
		return
	}

	reader := bufio.NewReader(io.MultiReader(
		strings.NewReader(string(firstByte)),
		conn,
	))

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Fields(requestLine)
	if len(parts) < 3 {
		return
	}

	method := parts[0]
	requestURL := parts[1]
	httpVersion := parts[2]

	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			headers[strings.ToLower(key)] = value
		}
	}

	switch method {
	case "CONNECT":
		log.Printf("[HTTP-CONNECT] %s -> %s", clientAddr, requestURL)
		if err := s.handleTunnel(conn, requestURL, clientAddr, ModeHTTPConnect, nil); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-CONNECT] %s 代理失败: %v", clientAddr, err)
			}
		}

	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE":
		log.Printf("[HTTP-%s] %s -> %s", method, clientAddr, requestURL)

		var target string
		var path string

		if strings.HasPrefix(requestURL, "http://") {
			urlWithoutScheme := strings.TrimPrefix(requestURL, "http://")
			idx := strings.Index(urlWithoutScheme, "/")
			if idx > 0 {
				target = urlWithoutScheme[:idx]
				path = urlWithoutScheme[idx:]
			} else {
				target = urlWithoutScheme
				path = "/"
			}
		} else {
			target = headers["host"]
			path = requestURL
		}

		if target == "" {
			conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			return
		}

		if !strings.Contains(target, ":") {
			target += ":80"
		}

		var requestBuilder strings.Builder
		requestBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVersion))

		for _, line := range headerLines {
			key := strings.Split(line, ":")[0]
			keyLower := strings.ToLower(strings.TrimSpace(key))
			if keyLower != "proxy-connection" && keyLower != "proxy-authorization" {
				requestBuilder.WriteString(line)
				requestBuilder.WriteString("\r\n")
			}
		}
		requestBuilder.WriteString("\r\n")

		if contentLength := headers["content-length"]; contentLength != "" {
			var length int
			fmt.Sscanf(contentLength, "%d", &length)
			if length > 0 && length < 10*1024*1024 {
				body := make([]byte, length)
				if _, err := io.ReadFull(reader, body); err == nil {
					requestBuilder.Write(body)
				}
			}
		}

		firstFrame := []byte(requestBuilder.String())

		if err := s.handleTunnel(conn, target, clientAddr, ModeHTTPProxy, firstFrame); err != nil {
			if !isNormalCloseError(err) {
				log.Printf("[HTTP-%s] %s 代理失败: %v", method, clientAddr, err)
			}
		}

	default:
		log.Printf("[HTTP] %s 不支持的方法: %s", clientAddr, method)
		conn.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
	}
}

func (s *ProxyServer) handleTunnel(conn net.Conn, target, clientAddr string, mode int, firstFrame []byte) error {
	if conn == nil {
		return errors.New("连接对象为空")
	}

	wsConn, err := s.wsClient.DialWithECH(2)
	if err != nil {
		s.sendErrorResponse(conn, mode)
		return fmt.Errorf("建立WebSocket连接失败: %w", err)
	}
	defer func() {
		if wsConn != nil {
			wsConn.Close()
		}
	}()

	var mu sync.Mutex

	stopPing := make(chan bool)
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				wsConn.WriteMessage(websocket.PingMessage, nil)
				mu.Unlock()
			case <-stopPing:
				return
			}
		}
	}()
	defer close(stopPing)

	conn.SetDeadline(time.Time{})

	if firstFrame == nil && mode == ModeSOCKS5 {
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		buffer := s.bufPool.Get().([]byte)
		n, _ := conn.Read(buffer)
		_ = conn.SetReadDeadline(time.Time{})
		if n > 0 && n <= 32*1024 {
			firstFrame = make([]byte, n)
			copy(firstFrame, buffer[:n])
		} else if n > 32*1024 {
			firstFrame = make([]byte, 32*1024)
			copy(firstFrame, buffer[:32*1024])
		} else {
			firstFrame = nil
		}
		s.bufPool.Put(buffer)
	}

	var connectMsg []byte
	if s.proxyIP != "" {
		connectMsg = append([]byte(fmt.Sprintf("CONNECT:%s|", target)), firstFrame...)
		connectMsg = append(connectMsg, []byte(fmt.Sprintf("|%s", s.proxyIP))...)
	} else {
		connectMsg = append([]byte(fmt.Sprintf("CONNECT:%s|", target)), firstFrame...)
	}

	mu.Lock()
	err = wsConn.WriteMessage(websocket.TextMessage, connectMsg)
	mu.Unlock()
	if err != nil {
		s.sendErrorResponse(conn, mode)
		return fmt.Errorf("发送连接请求失败: %w", err)
	}

	_, msg, err := wsConn.ReadMessage()
	if err != nil {
		s.sendErrorResponse(conn, mode)
		return fmt.Errorf("读取连接响应失败: %w", err)
	}

	response := string(msg)
	if strings.HasPrefix(response, "ERROR:") {
		s.sendErrorResponse(conn, mode)
		return errors.New(response)
	}
	if response != "CONNECTED" {
		s.sendErrorResponse(conn, mode)
		return fmt.Errorf("意外响应: %s", response)
	}

	if err := s.sendSuccessResponse(conn, mode); err != nil {
		return fmt.Errorf("发送成功响应失败: %w", err)
	}

	log.Printf("[代理] %s 已连接: %s", clientAddr, target)

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() {
		once.Do(func() { close(done) })
	}

	go func() {
		buf := s.bufPool.Get().([]byte)
		defer s.bufPool.Put(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				mu.Lock()
				wsConn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
				mu.Unlock()
				closeDone()
				return
			}

			mu.Lock()
			err = wsConn.WriteMessage(websocket.BinaryMessage, buf[:n])
			mu.Unlock()
			if err != nil {
				closeDone()
				return
			}
		}
	}()

	go func() {
		for {
			mt, msg, err := wsConn.ReadMessage()
			if err != nil {
				closeDone()
				return
			}

			if mt == websocket.TextMessage {
				if string(msg) == "CLOSE" {
					closeDone()
					return
				}
			}

			if _, err := conn.Write(msg); err != nil {
				closeDone()
				return
			}
		}
	}()

	<-done
	log.Printf("[代理] %s 已断开: %s", clientAddr, target)
	return nil
}

func (s *ProxyServer) sendErrorResponse(conn net.Conn, mode int) {
	switch mode {
	case ModeSOCKS5:
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	case ModeHTTPConnect, ModeHTTPProxy:
		conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
	}
}

func (s *ProxyServer) sendSuccessResponse(conn net.Conn, mode int) error {
	switch mode {
	case ModeSOCKS5:
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return err
	case ModeHTTPConnect:
		_, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		return err
	case ModeHTTPProxy:
		return nil
	}
	return nil
}

func isNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		contains(errStr, "normal closure")
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
