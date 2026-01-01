package websocket

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"ech-workers/ech"

	"github.com/gorilla/websocket"
)

type WebSocketClient struct {
	serverAddr string
	token      string
	echManager *ech.ECHManager
	serverIP   string
}

func NewWebSocketClient(serverAddr, token string, echManager *ech.ECHManager, serverIP string) *WebSocketClient {
	return &WebSocketClient{
		serverAddr: serverAddr,
		token:      token,
		echManager: echManager,
		serverIP:   serverIP,
	}
}

func (c *WebSocketClient) ParseServerAddr() (host, port, path string, err error) {
	if c.serverAddr == "" {
		return "", "", "", errors.New("服务器地址为空")
	}

	path = "/"
	addr := c.serverAddr
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		if slashIdx < len(addr) {
			path = addr[slashIdx:]
		}
		addr = addr[:slashIdx]
	}

	if addr == "" {
		return "", "", "", errors.New("服务器地址格式错误")
	}

	host, port, err = net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return "", "", "", fmt.Errorf("无效的服务器地址格式: %v", err)
	}

	return host, port, path, nil
}

func (c *WebSocketClient) DialWithECH(maxRetries int) (*websocket.Conn, error) {
	host, port, path, err := c.ParseServerAddr()
	if err != nil {
		return nil, fmt.Errorf("解析服务器地址失败: %w", err)
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", host, port, path)

	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		tlsCfg, tlsErr := c.echManager.BuildTLSConfig(host)
		if tlsErr != nil {
			lastErr = tlsErr
			if attempt < maxRetries && (strings.Contains(tlsErr.Error(), "ECH配置") ||
				strings.Contains(tlsErr.Error(), "未找到ECH")) {
				log.Printf("[ECH] TLS配置失败，尝试刷新ECH配置 (%d/%d): %v", attempt, maxRetries, tlsErr)
				c.echManager.Refresh()
				time.Sleep(500 * time.Millisecond)
				continue
			}
			return nil, fmt.Errorf("构建TLS配置失败: %w", tlsErr)
		}

		dialer := websocket.Dialer{
			TLSClientConfig: tlsCfg,
			Subprotocols: func() []string {
				if c.token == "" {
					return nil
				}
				return []string{c.token}
			}(),
			HandshakeTimeout: 10 * time.Second,
		}

		if c.serverIP != "" {
			dialer.NetDial = func(network, address string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				ipHost := c.serverIP
				userHost, userPort, splitErr := net.SplitHostPort(c.serverIP)
				if splitErr == nil {
					ipHost = userHost
					port = userPort
				}
				return net.DialTimeout(network, net.JoinHostPort(ipHost, port), 10*time.Second)
			}
		}

		wsConn, _, dialErr := dialer.Dial(wsURL, nil)
		if dialErr != nil {
			lastErr = dialErr
			if attempt < maxRetries && (strings.Contains(dialErr.Error(), "ECH") ||
				strings.Contains(dialErr.Error(), "encrypted")) {
				log.Printf("[ECH] 连接失败，尝试刷新ECH配置 (%d/%d): %v", attempt, maxRetries, dialErr)
				c.echManager.Refresh()
				time.Sleep(time.Second)
				continue
			}
			return nil, fmt.Errorf("WebSocket连接失败: %w", dialErr)
		}

		log.Printf("[WebSocket] 连接成功建立 (尝试%d次)", attempt)
		return wsConn, nil
	}

	return nil, fmt.Errorf("连接失败，已达最大重试次数(%d): %v", maxRetries, lastErr)
}
