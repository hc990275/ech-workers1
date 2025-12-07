package config

import (
	"errors"
	"net"
	"strings"
)

type Config struct {
	ListenAddr string
	ServerAddr string
	ServerIP   string
	Token      string
	DNSServer  string
	ECHDomain  string
	ProxyIP    string
}

func (c *Config) Validate() error {
	if c.ServerAddr == "" {
		return errors.New("必须指定服务端地址 (-f)")
	}

	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		if !strings.Contains(err.Error(), "missing port") {
			return errors.New("监听地址格式无效")
		}
		// 如果没有端口，添加默认端口
		if strings.Contains(c.ListenAddr, ":") {
			// IPv6 地址
			c.ListenAddr = "[" + c.ListenAddr + "]:30000"
		} else {
			c.ListenAddr = c.ListenAddr + ":30000"
		}
	}

	return nil
}
