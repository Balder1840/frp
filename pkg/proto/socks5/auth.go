package socks5

import (
	"crypto/subtle"
	"fmt"
	"net"

	"github.com/go-gost/gosocks5"
)

// StrEQ returns whether s1 and s2 are equal
func strEQ(s1, s2 string) bool {
	return subtle.ConstantTimeCompare([]byte(s1), []byte(s2)) == 1
}

// VerifyByMap returns an verifier that verify by an username-password map
func verifyByMap(users map[string]string) func(string, string) bool {
	return func(username, password string) bool {
		pw, ok := users[username]
		if !ok {
			return false
		}
		return strEQ(pw, password)
	}
}

// auth tunnel client auth request
func (c *Client) auth(userConn net.Conn, workConn net.Conn) error {
	authRequest, err := gosocks5.ReadUserPassRequest(userConn)
	if err != nil {
		return fmt.Errorf(`[socks5] client read auth request faild: %s`, err)
	}

	if err := authRequest.Write(workConn); err != nil {
		return fmt.Errorf(`[socks5] client write auth request faild: %s`, err)
	}

	authReply, err := gosocks5.ReadUserPassResponse(workConn)
	if err != nil {
		return fmt.Errorf(`[socks5] client read auth reply faild: %s`, err)
	}

	if err := authReply.Write(userConn); err != nil {
		return fmt.Errorf(`[socks5] client write auth reply faild: %s`, err)
	}

	return nil
}
