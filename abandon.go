// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

// Will return an error. Normally due to closed connection.
func (l *Conn) Abandon(abandonMessageID uint64) (error *Error) {
	messageID := l.nextMessageID()
	encodedAbandon := ber.NewInteger(ber.ClassApplication, ber.TypePrimative, ApplicationAbandonRequest, abandonMessageID, ApplicationMap[ApplicationAbandonRequest])

	packet, err := requestBuildPacket(messageID, encodedAbandon, nil)
	if err != nil {
		return err
	}

	if l.Debug {
		ber.PrintPacket(packet)
	}

	channel, err := l.sendMessage(packet)

	if err != nil {
		return err
	}

	if channel == nil {
		return NewError(ErrorNetwork, errors.New("Could not send message"))
	}

	defer l.finishMessage(messageID)
	if l.Debug {
		fmt.Printf("%d: NOT waiting Abandon for response\n", messageID)
	}

	// success
	return nil
}
