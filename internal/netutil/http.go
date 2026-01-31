package netutil

import (
	"net"
	"net/http"
	"time"
)

var DefaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          1024,
	MaxIdleConnsPerHost:   256,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

func NewClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: DefaultTransport,
	}
}
