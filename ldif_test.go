package ldap

import (
	//"bufio"
	//"errors"
	"fmt"
	//"io"
	//"os"
	"strings"
	"testing"
)

var simpleLDIF string = `
version: 1

# comment

dn: cn=bob,ou=people,o=example.com
cn: bob
# comment in entry
description: a multi-line
  attribute value
-

dn: cn=joe,ou=people,o=example.com
cn: joe
description:: VGhpcyB0ZXh0IHdhcyBvcmlnaW5hbGx5IGJhc2U2NCBlbmNvZGVkLg==

dn: cn=joe,ou=people,o=example.com
changetype: modify
replace: cn
cn: joe blogs
-
delete: cn=joeDelete,ou=people,o=example.com
-
add: sn
sn: clogs
-

dn: cn=joe2,ou=people,o=example.com
changetype: add
cn: joe blogs

dn: cn=joe2,ou=people,o=example.com
changetype: delete
`

func TestLDIFOpenAndRead(t *testing.T) {
	reader := strings.NewReader(simpleLDIF)
	lr, err := NewLDIFReader(reader)
	if err != nil {
		t.Errorf(err.Error())
	}

	// record 0
	fmt.Printf("Reading record 0\n")
	record, err := lr.ReadLDIFEntry()
	if err != nil {
		t.Errorf(err.Error())
	}
	if record.RecordType() != EntryRecord {
		t.Errorf("record 0: record.RecordType() mismatch")
	}
	entry := record.(*Entry)
	if entry.GetAttributeValues("description")[0] != "a multi-line attribute value" {
		t.Errorf("record 0: description mismatch")
	}
	fmt.Printf("0 (entry): DN: %s\n", entry.DN)

	// record 1
	fmt.Printf("Reading record 1\n")
	//LDIFDebug = true
	record, err = lr.ReadLDIFEntry()
	if err != nil {
		t.Errorf(err.Error())
	}
	if record.RecordType() != EntryRecord {
		t.Errorf("record 1: record.RecordType() mismatch")
	}
	entry = record.(*Entry)
	if entry.GetAttributeValues("description")[0] != "This text was originally base64 encoded." {
		t.Errorf("record 1: description mismatch")
	}
	fmt.Printf("1 (entry): DN: %s\n", entry.DN)
	//LDIFDebug = false

	// record 2
	fmt.Printf("Reading record 2\n")
	record, err = lr.ReadLDIFEntry()
	if err != nil {
		fmt.Println(err.Error())
	}
	if record.RecordType() != ModifyRecord {
		fmt.Errorf("record 2: record.RecordType() mismatch")
	}
	modRequest := record.(*ModifyRequest)
	fmt.Printf("2 (ModifyRequest): DN: %s\n", modRequest.DN)
	fmt.Printf(modRequest.DumpModRequest())

	// record 3
	fmt.Printf("Reading record 3\n")
	record, err = lr.ReadLDIFEntry()
	if err != nil {
		fmt.Println(err.Error())
	}
	if record.RecordType() != AddRecord {
		t.Errorf("record 3: record.RecordType() mismatch")
	}
	addRequest := record.(*AddRequest)
	fmt.Printf("3 (addRequest): DN: %s\n", addRequest.Entry.DN)

	// record 4
	fmt.Printf("Reading record 4\n")
	record, err = lr.ReadLDIFEntry()
	if err != nil {
		fmt.Println(err.Error())
	}
	if record.RecordType() != DeleteRecord {
		t.Errorf("record 4: record.RecordType() mismatch")
	}
	deleteRequest := record.(*DeleteRequest)
	fmt.Printf("3 (deleteRequest): DN: %s\n", deleteRequest.DN)

	// nil record
	fmt.Printf("Reading record 5 (nil)\n")
	record, err = lr.ReadLDIFEntry()
	if err != nil {
		t.Errorf(err.Error())
	}
	if record != nil {
		t.Errorf("record nil: record was not nil!")
	}

	// reading 250K entries ~ 15sec on 4+ year old desktop.
	// ldif generated from OpenDJ install
	//file, nerr := os.Open("e:/temp/250k.ldif")
	//if nerr != nil {
	//	t.Errorf(nerr.Error())
	//	return
	//}
	//defer file.Close()

	//bufReader := bufio.NewReader(file)
	//lr, err = NewLDIFReader(bufReader)
	//if err != nil {
	//	t.Errorf(err.Error())
	//}
	//for {
	//	record, err = lr.ReadLDIFEntry()
	//	if err != nil {
	//		t.Errorf(err.Error())
	//	}
	//	if record == nil {
	//		break
	//	}
	//	entry := record.(*Entry)
	//	fmt.Println(entry.DN)
	//	fmt.Println(entry.GetAttributeValue("entryUUID"))
	//}
}
