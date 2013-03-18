// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

/*
CompareRequest ::= [APPLICATION 14] SEQUENCE {
    entry           LDAPDN,
    ava             AttributeValueAssertion }

AttributeValueAssertion ::= SEQUENCE {
    attributeDesc   AttributeDescription,
    assertionValue  AssertionValue }
*/

type CompareRequest struct {
	DN       string
	Name     string
	Value    string
	Controls []Control
}

func (l *Conn) Compare(compareReq *CompareRequest) *Error {
	messageID := l.nextMessageID()
	encodedCompare, err := encodeCompareRequest(compareReq)
	if err != nil {
		return err
	}

	packet, err := requestBuildPacket(messageID, encodedCompare, compareReq.Controls)
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
		fmt.Printf("%d: waiting for response\n", messageID)
	}

	packet = <-channel

	if l.Debug {
		fmt.Printf("%d: got response %p\n", messageID, packet)
	}

	if packet == nil {
		return NewError(ErrorNetwork, errors.New("Could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(packet)
	}

	result_code, result_description := getLDAPResultCode(packet)

	if l.Debug {
		fmt.Printf("%d: returning\n", messageID)
	}
	// CompareTrue = 6, CompareFalse = 5
	// return an "Error"
	return NewError(result_code, errors.New(result_description))
}

func encodeCompareRequest(req *CompareRequest) (*ber.Packet, *Error) {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationCompareRequest, nil, ApplicationMap[ApplicationCompareRequest])
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, req.DN, "LDAP DN"))
	ava, err := encodeItem([]string{req.Name, "=", req.Value})
	if err != nil {
		return nil, err
	}
	p.AppendChild(ava)
	return p, nil
}

func NewCompareRequest(dn, name, value string) (req *CompareRequest) {
	req = &CompareRequest{DN: dn, Name: name, Value: value, Controls: make([]Control, 0)}
	return
}
