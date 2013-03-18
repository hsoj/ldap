// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"github.com/mavricknz/asn1-ber"
)

// messageID - messageID obtained from Conn.nextMessageID()
// opPacket - the operation BER encoded Packet e.g. Search/Modify/Delete/Compare
// controls - the controls to add to the Request
// returns the BER encoded LDAP request or an Error
func requestBuildPacket(messageID uint64, opPacket *ber.Packet, controls []Control) (p *ber.Packet, err *Error) {

	p = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	p.AppendChild(opPacket)

	if controls != nil && len(controls) > 0 {
		cPacket, err := encodeControls(controls)
		if err != nil {
			return nil, err
		}
		p.AppendChild(cPacket)
	}
	return
}
