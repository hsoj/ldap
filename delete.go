// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"
	"github.com/mavricknz/asn1-ber"
)

type DeleteRequest struct {
	DN       string
	Controls []Control
}

func (req *DeleteRequest) RecordType() uint8 {
	return DeleteRecord
}

/*
Simple delete
*/

func (l *Conn) Delete(delReq *DeleteRequest) (error *Error) {
	messageID := l.nextMessageID()
	encodedDelete := ber.NewString(ber.ClassApplication, ber.TypePrimative, ApplicationDelRequest, delReq.DN, ApplicationMap[ApplicationDelRequest])

	packet, err := requestBuildPacket(messageID, encodedDelete, delReq.Controls)
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

	if result_code != 0 {
		return NewError(result_code, errors.New(result_description))
	}

	if l.Debug {
		fmt.Printf("%d: returning\n", messageID)
	}
	// success
	return nil
}

func NewDeleteRequest(dn string) (delReq *DeleteRequest) {
	delReq = &DeleteRequest{DN: dn, Controls: make([]Control, 0)}
	return
}

// TDDO make generic for mod/del/search via interface.
func (delReq *DeleteRequest) AddControl(control Control) {
	if delReq.Controls == nil {
		delReq.Controls = make([]Control, 0)
	}
	delReq.Controls = append(delReq.Controls, control)
}
