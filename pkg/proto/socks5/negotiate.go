package socks5

import (
	"fmt"
	"net"
)

// negotiate tunnel client negotiate request
func (c *Client) negotiate(userConn net.Conn, workConn net.Conn) (*NegotiationReply, error) {
	negotiationRequest, err := ReadNegotiationRequest(userConn)
	if err != nil {
		return nil, fmt.Errorf(`[socks5] client read negotiate request faild: %s`, err)

	}

	if err := negotiationRequest.Write(workConn); err != nil {
		return nil, fmt.Errorf(`[socks5] client write negotiate request faild: %s`, err)
	}

	negotiationReply, err := ReadNegotiationReply(workConn)
	if err != nil {
		return nil, fmt.Errorf(`[socks5] client read negotiate reply faild: %s`, err)
	}

	if err := negotiationReply.Write(userConn); err != nil {
		return nil, fmt.Errorf(`[socks5] client write negotiate reply faild: %s`, err)
	}

	return negotiationReply, nil
}
