// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	//"encoding/hex"
	"fmt"
	// "runtime/debug"
	"testing"
	//"time"
)

var local_ldap_binddn string = "cn=directory manager"
var local_ldap_passwd string = "qwerty"
var local_ldap_server string = "localhost"
var local_ldap_port uint16 = 1389
var local_base_dn string = "dc=example,dc=com"
var local_filter []string = []string{
	"(sn=Abb*)",
	"(uniqueMember=*)",
	"(|(uniqueMember=*)(sn=Abbie))",
	"(&(objectclass=person)(cn=ab*))",
	`(&(objectclass=person)(cn=\41\42*))`, // same as above
	"(&(objectclass=person)(cn=ko*))",
	"(&(|(sn=an*)(sn=ba*))(!(sn=bar*)))",
	"(&(ou:dn:=people)(sn=aa*))"}

// go test -test.v -run="TestLocalSearch$" ldap
// Setup an OpenDJ server on port 1389 with 2000->20k default entries
// http://www.forgerock.org/opendj.html

var local_attributes []string = []string{
	"cn",
	"description"}

var local_addDNs []string = []string{"cn=Jon Boy,ou=People,dc=example,dc=com"}
var local_addAttrs []EntryAttribute = []EntryAttribute{
	EntryAttribute{
		Name: "objectclass",
		Values: []string{
			"person", "inetOrgPerson", "organizationalPerson", "top",
		},
	},
	EntryAttribute{
		Name: "cn",
		Values: []string{
			"Jon Boy",
		},
	},
	EntryAttribute{
		Name: "givenName",
		Values: []string{
			"Jon",
		},
	},
	EntryAttribute{
		Name: "sn",
		Values: []string{
			"Boy",
		},
	},
}

func TestLocalConnect(t *testing.T) {
	fmt.Printf("TestLocalConnect: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()
	fmt.Printf("TestLocalConnect: finished...\n")
}

func TestLocalSearch(t *testing.T) {
	fmt.Printf("TestLocalSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))

	// l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[0],
		local_attributes,
		nil)
	// ber.Debug = true
	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestLocalSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func TestLocalSearchWithPaging(t *testing.T) {
	fmt.Printf("TestLocalSearchWithPaging: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[3],
		local_attributes,
		nil)
	sr, err := l.SearchWithPaging(search_request, 5)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	fmt.Printf("TestLocalSearchWithPaging: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func testLocalMultiGoroutineSearch(t *testing.T, l *Conn, results chan *SearchResult, i int) {
	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[i],
		local_attributes,
		nil)
	sr, err := l.Search(search_request)

	if err != nil {
		t.Errorf(err.Error())
		results <- nil
		return
	}

	results <- sr
}

func TestLocalMultiGoroutineSearch(t *testing.T) {
	fmt.Printf("TestLocalMultiGoroutineSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	results := make([]chan *SearchResult, len(local_filter))
	for i := range local_filter {
		results[i] = make(chan *SearchResult)
		go testLocalMultiGoroutineSearch(t, l, results[i], i)
	}
	for i := range local_filter {
		sr := <-results[i]
		if sr == nil {
			t.Errorf("Did not receive results from goroutine for %q", local_filter[i])
		} else {
			fmt.Printf("TestLocalMultiGoroutineSearch(%d): %s -> num of entries = %d\n", i, local_filter[i], len(sr.Entries))
		}
	}
}

// TODO: fix a lot of the code duplication

func TestLocalAddAndDelete(t *testing.T) {
	fmt.Printf("TestLocalAddAndDelete: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	addReq := NewAddRequest(local_addDNs[0])
	for _, attr := range local_addAttrs {
		addReq.AddAttribute(&attr)
	}
	fmt.Printf("Adding: %s\n", local_addDNs[0])
	err = l.Add(addReq)
	if err != nil {
		t.Errorf("Add : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
	fmt.Printf("Deleting: %s\n", local_addDNs[0])
	delRequest := &DeleteRequest{local_addDNs[0], nil}
	err = l.Delete(delRequest)
	if err != nil {
		t.Errorf("Delete : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
}

func TestLocalCompare(t *testing.T) {
	fmt.Printf("TestLocalCompare: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	addReq := NewAddRequest(local_addDNs[0])
	for _, attr := range local_addAttrs {
		addReq.AddAttribute(&attr)
	}
	fmt.Printf("Adding: %s\n", local_addDNs[0])
	err = l.Add(addReq)
	if err != nil {
		t.Errorf("Add : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	fmt.Printf("Comparing: %s : sn=Boy which is True\n", local_addDNs[0])
	compareReq := NewCompareRequest(local_addDNs[0], "sn", "Boy")
	err = l.Compare(compareReq)
	if err.ResultCode != LDAPResultCompareTrue {
		t.Errorf("Compare True: %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
	fmt.Printf("Compare Result : %d : %s\n", err.ResultCode, LDAPResultCodeMap[err.ResultCode])

	fmt.Printf("Comparing: %s : sn=BoyIsThisWrong which is False\n", local_addDNs[0])
	compareReq = NewCompareRequest(local_addDNs[0], "sn", "BoyIsThisWrong")
	err = l.Compare(compareReq)
	if err.ResultCode != LDAPResultCompareFalse {
		t.Errorf("Compare False: %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
	fmt.Printf("Compare Result : %d : %s\n", err.ResultCode, LDAPResultCodeMap[err.ResultCode])

	fmt.Printf("Deleting: %s\n", local_addDNs[0])
	delRequest := &DeleteRequest{local_addDNs[0], nil}
	err = l.Delete(delRequest)
	if err != nil {
		t.Errorf("Delete : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
}

func TestLocalControlPermissiveModifyRequest(t *testing.T) {
	fmt.Printf("ControlPermissiveModifyRequest: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	addReq := NewAddRequest(local_addDNs[0])
	for _, attr := range local_addAttrs {
		addReq.AddAttribute(&attr)
	}
	fmt.Printf("Adding: %s\n", local_addDNs[0])
	err = l.Add(addReq)
	if err != nil {
		t.Errorf("Add : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	modreq := NewModifyRequest(local_addDNs[0])
	mod := NewMod(ModAdd, "description", []string{"aaa"})
	modreq.AddMod(mod)
	fmt.Printf(modreq.DumpModRequest())
	err = l.Modify(modreq)
	if err != nil {
		t.Errorf("Modify : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	mod = NewMod(ModAdd, "description", []string{"aaa", "bbb", "ccc"})
	modreq = NewModifyRequest(local_addDNs[0])
	modreq.AddMod(mod)
	control := NewControlString(ControlTypePermissiveModifyRequest, true, "")
	fmt.Println(control.String())
	modreq.AddControl(control)
	fmt.Printf(modreq.DumpModRequest())
	err = l.Modify(modreq)
	if err != nil {
		t.Errorf("Modify (Permissive): %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	mod = NewMod(ModAdd, "description", []string{"aaa", "bbb", "ccc", "ddd"})
	modreq = NewModifyRequest(local_addDNs[0])
	modreq.AddMod(mod)
	control = NewControlPermissiveModifyRequest(false)
	fmt.Println(control.String())
	modreq.AddControl(control)
	fmt.Printf(modreq.DumpModRequest())
	err = l.Modify(modreq)
	if err != nil {
		t.Errorf("Modify (Permissive): %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	fmt.Printf("Deleting: %s\n", local_addDNs[0])
	delRequest := NewDeleteRequest(local_addDNs[0])
	err = l.Delete(delRequest)

	if err != nil {
		t.Errorf("Delete : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
}

func TestLocalControlMatchedValuesRequest(t *testing.T) {
	fmt.Printf("LocalControlMatchedValuesRequest: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}

	addReq := NewAddRequest(local_addDNs[0])
	for _, attr := range local_addAttrs {
		addReq.AddAttribute(&attr)
	}
	fmt.Printf("Adding: %s\n", local_addDNs[0])
	err = l.Add(addReq)
	if err != nil {
		t.Errorf("Add : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	fmt.Printf("Modify: %s = {aaa, bbb, ccc}\n", "description")
	mod := NewMod(ModAdd, "description", []string{"aaa", "bbb", "ccc", "aabb"})
	modreq := NewModifyRequest(local_addDNs[0])
	modreq.AddMod(mod)
	err = l.Modify(modreq)
	if err != nil {
		t.Errorf("Modify: %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}

	control := NewControlMatchedValuesRequest(true, "(description=aaa)")
	fmt.Println(control.String())
	fmt.Printf("Search: (objectclass=*), (description=aaa) via MatchedValuesRequest\n")
	search_request := NewSearchRequest(
		local_addDNs[0],
		ScopeBaseObject, DerefAlways, 0, 0, false,
		"(objectclass=*)",
		[]string{"description"},
		nil,
	)
	search_request.AddControl(control)
	//l.Debug = true
	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf("Search: %s : result = %d : %s\n", addDNs[0], err.ResultCode, err.Err)
		return
	}
	//l.Debug = false
	fmt.Printf("Search Result:")
	fmt.Println(sr.Entries[0].Attributes[0])

	control = NewControlMatchedValuesRequest(true, "(description=a*)")
	fmt.Println(control.String())
	fmt.Printf("Search: (objectclass=*), (description=a*) via MatchedValuesRequest\n")
	search_request = NewSearchRequest(
		local_addDNs[0],
		ScopeBaseObject, DerefAlways, 0, 0, false,
		"(objectclass=*)",
		[]string{"description"},
		nil,
	)
	search_request.AddControl(control)
	//l.Debug = true
	sr, err = l.Search(search_request)
	if err != nil {
		t.Errorf("Search: %s : result = %d : %s\n", addDNs[0], err.ResultCode, err.Err)
		return
	}
	//l.Debug = false
	fmt.Printf("Search Result:")
	fmt.Println(sr.Entries[0].Attributes[0])

	fmt.Printf("Deleting: %s\n", local_addDNs[0])
	delRequest := NewDeleteRequest(local_addDNs[0])
	err = l.Delete(delRequest)

	if err != nil {
		t.Errorf("Delete : %s : result = %d\n", addDNs[0], err.ResultCode)
		return
	}
}

type counter struct {
	EntryCount          int
	ReferenceCount      int
	AbandonAtEntryCount int
}

func (c *counter) ProcessDiscreteResult(sr *DiscreteSearchResult, connInfo *ConnectionInfo) (stopProcessing bool, err *Error) {
	switch sr.SearchResultType {
	case SearchResultEntry:
		fmt.Println("result entry")
		c.EntryCount++
		if c.AbandonAtEntryCount != 0 {
			if c.EntryCount == c.AbandonAtEntryCount {
				fmt.Printf("Abandoning at request: %d\n", connInfo.MessageID)
				err = connInfo.Conn.Abandon(connInfo.MessageID)
				// While we are abandoning the results its not an error in this case.
				return true, nil
			}
		}
	case SearchResultDone:
		fmt.Println("results done")
	case SearchResultReference:
		fmt.Println("result referral")
		c.ReferenceCount++
	}
	return false, nil
}

func TestLocalSearchWithHandler(t *testing.T) {
	fmt.Printf("TestLocalSearchWithCallback: starting...\n")

	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))

	// l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[0],
		local_attributes,
		nil)

	l.Debug = false

	// Blocking
	fmt.Println("Blocking version...")
	resultCounter := new(counter)
	err = l.SearchWithHandler(search_request, resultCounter, nil)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestLocalSearchWithCallback: %s entries = %d, Referrals = %d\n",
		search_request.Filter, resultCounter.EntryCount, resultCounter.ReferenceCount)

	// Non-Blocking
	fmt.Println("Non-Blocking version...")
	resultChan := make(chan *Error)
	resultCounter = new(counter)
	go l.SearchWithHandler(search_request, resultCounter, resultChan)
	fmt.Println("do stuff ...")
	err = <-resultChan
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestLocalSearchWithCallback - go routine: %s entries = %d, Referrals = %d\n",
		search_request.Filter, resultCounter.EntryCount, resultCounter.ReferenceCount)

	// TODO blocking + abandon non-trival version.

	// Non-Blocking + Abandoning
	fmt.Println("Non-Blocking + Abandon version...")
	resultChan = make(chan *Error)
	resultCounter = new(counter)
	resultCounter.AbandonAtEntryCount = 4
	go l.SearchWithHandler(search_request, resultCounter, resultChan)
	err = <-resultChan
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestLocalSearchWithCallback - go routine: %s entries = %d, Referrals = %d\n",
		search_request.Filter, resultCounter.EntryCount, resultCounter.ReferenceCount)
}

func TestLocalSearchPagingWithHandler(t *testing.T) {
	fmt.Printf("TestLocalSearchPagingWithHandler: starting...\n")

	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))

	// l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSearchRequest(
		local_base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		local_filter[0],
		local_attributes,
		nil)

	l.Debug = false
	pagingControl := NewControlPaging(2)
	search_request.Controls = append(search_request.Controls, pagingControl)

	for {
		sr := new(SearchResult)
		err = l.SearchWithHandler(search_request, sr, nil)
		if err != nil {
			t.Errorf(err.Error())
			return
		}
		_, pagingResponsePacket := FindControl(sr.Controls, ControlTypePaging)
		if pagingResponsePacket == nil {
			t.Errorf("Expected Paging Control.")
		}
		pagingControl.Cookie = pagingResponsePacket.(*ControlPaging).Cookie
		ReplaceControl(search_request.Controls, pagingControl)
		fmt.Printf("TestLocalSearchPagingWithHandler: %s entries = %d, Referrals = %d\n",
			search_request.Filter, len(sr.Entries), len(sr.Referrals))
		if len(pagingControl.Cookie) == 0 {
			return
		}
	}
}

func TestLocalConnAndSearch(t *testing.T) {
	fmt.Printf("TestLocalConnAndSearch: starting...\n")
	l := new(Conn)
	l.Network = "tcp"
	l.Addr = fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port)
	fmt.Println(l)
	err := l.DialUsingConn()

	// l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSimpleSearchRequest(
		local_base_dn,
		ScopeWholeSubtree,
		local_filter[0],
		local_attributes,
	)
	// ber.Debug = true
	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	fmt.Printf("TestLocalSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func TestLocalOrderedSearch(t *testing.T) {
	fmt.Printf("TestLocalOrderedSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))

	// l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSimpleSearchRequest(
		local_base_dn,
		ScopeWholeSubtree,
		local_filter[3],
		local_attributes,
	)

	serverSideSortAttrRuleOrder := ServerSideSortAttrRuleOrder{
		AttributeName: "cn",
		OrderingRule:  "",
		ReverseOrder:  false,
	}
	sortKeyList := make([]ServerSideSortAttrRuleOrder, 0, 1)
	sortKeyList = append(sortKeyList, serverSideSortAttrRuleOrder)
	sortControl := NewControlServerSideSortRequest(sortKeyList, true)
	fmt.Println(sortControl.String())
	search_request.AddControl(sortControl)
	l.Debug = false
	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	_, sssResponse := FindControl(sr.Controls, ControlTypeServerSideSortResponse)
	if sssResponse != nil {
		fmt.Println(sssResponse.String())
	}
	fmt.Printf("TestLocalSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func TestLocalVlvSearch(t *testing.T) {
	fmt.Printf("TestLocalVlvSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", local_ldap_server, local_ldap_port))

	// l.Debug = true
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	defer l.Close()

	err = l.Bind(local_ldap_binddn, local_ldap_passwd)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	search_request := NewSimpleSearchRequest(
		local_base_dn,
		ScopeWholeSubtree,
		"(cn=*)",
		local_attributes,
	)
	vlvControl := new(ControlVlvRequest)
	vlvControl.BeforeCount = 0
	vlvControl.AfterCount = 3

	offset := new(VlvOffSet)
	offset.Offset = 1
	offset.ContentCount = 3

	vlvControl.ByOffset = offset

	//pack, _ := vlvControl.Encode()
	//fmt.Println(hex.Dump(pack.Bytes()))

	search_request.AddControl(vlvControl)

	serverSideSortAttrRuleOrder := ServerSideSortAttrRuleOrder{
		AttributeName: "cn",
		OrderingRule:  "",
		ReverseOrder:  false,
	}
	sortKeyList := make([]ServerSideSortAttrRuleOrder, 0, 1)
	sortKeyList = append(sortKeyList, serverSideSortAttrRuleOrder)
	sortControl := NewControlServerSideSortRequest(sortKeyList, true)
	search_request.AddControl(sortControl)

	l.Debug = false
	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	_, vlvResp := FindControl(sr.Controls, ControlTypeVlvResponse)
	if vlvResp != nil {
		fmt.Println(vlvResp.String())
	}
	for _, entry := range sr.Entries {
		fmt.Println(entry.GetAttributeValues("cn")[0])
	}
	fmt.Printf("TestLocalVlvSearch (byOffSet): %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))

	search_request = NewSimpleSearchRequest(
		local_base_dn,
		ScopeWholeSubtree,
		"(cn=*)",
		local_attributes,
	)

	vlvControl = new(ControlVlvRequest)
	vlvControl.BeforeCount = 0
	vlvControl.AfterCount = 3
	vlvControl.GreaterThanOrEqual = "Aaren Amar"

	//pack, _ := vlvControl.Encode()
	//fmt.Println(hex.Dump(pack.Bytes()))

	search_request.AddControl(vlvControl)
	search_request.AddControl(sortControl)

	sr, err = l.Search(search_request)
	if err != nil {
		t.Errorf(err.Error())
		return
	}
	_, vlvResp = FindControl(sr.Controls, ControlTypeVlvResponse)
	if vlvResp != nil {
		fmt.Println(vlvResp.String())
	}
	for _, entry := range sr.Entries {
		fmt.Println(entry.GetAttributeValues("cn")[0])
	}
	fmt.Printf("TestLocalVlvSearch (value): %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
	fmt.Printf("TestLocalVlvSearch: Finished.\n")
}
