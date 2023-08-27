package main

import (
	"fmt"
	"net"
	"os"
	"errors"
	"github.com/megakuul/kerberos-sim/shared/message"
	"github.com/megakuul/kerberos-sim/shared/crypto"
	"google.golang.org/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"
)

var svc_addr string
var kdc_addr string
var user_principal_name string
var svc_principal_name string
var password string

const LIFETIME = uint64(259200)

func FetchSPN(svc_addr string) (string, error) {
	con, err := net.Dial("tcp", svc_addr)
	if err!=nil {
		return "", err
	}
	defer con.Close()

	Req := &message.SVCMessage{
		M: &message.SVCMessage_SPNReq{
			SPNReq: &message.SPN_Request{
				SVC_Addr: svc_addr,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return "", err
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return "", err
	}

	bRes := make([]byte, 1024)
	n, err := con.Read(bRes)
	if err!=nil {
		return "", err
	}

	Res:= &message.SPN_Response{}
	if err := proto.Unmarshal(bRes[:n], Res); err!=nil {
		// Return the error if the svc returned a error instead of the Protobuf
		return string(bRes), err
	}
	
	return Res.SPN, nil
}

func RequestTGT(kdc_addr string, upn string, passwd string, lifetime uint64, ip_list []string) (crypto.AS_CT, []byte, error) {
	as_ct := crypto.AS_CT{}

	addr, err := net.ResolveUDPAddr("udp", kdc_addr)
	if err!=nil {
		return as_ct, nil, err
	}
	
	con, err := net.DialUDP("udp", nil, addr)
	if err!=nil {
		return as_ct, nil, err
	}
	defer con.Close()

	Req := &message.KDCMessage{
		M: &message.KDCMessage_ASReq{
			ASReq: &message.KRB_AS_Request{
				UserPrincipal: upn,
				Lifetime: lifetime,
				IP_List: ip_list,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return as_ct, nil, err
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return as_ct, nil, err
	}

	bRes := make([]byte, 1024)
	n, _, err := con.ReadFromUDP(bRes)
	if err!=nil {
		return as_ct, nil, err
	}
	
	Res:= &message.KRB_AS_Response{}
	if err:=proto.Unmarshal(bRes[:n], Res); err!=nil {
		return as_ct, nil, errors.New(string(bRes))
	}

	as_ct, err = crypto.DecryptAS_CT(Res.CT, []byte(passwd))
	if err!=nil {
		return as_ct, nil, err
	}

	return as_ct, Res.TGT, nil
}

func RequestTGS() {

}

func RequestSVC() {

}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: client [svc] [kdc]")
		os.Exit(1)
	}

	svc_addr = os.Args[1]
	kdc_addr = os.Args[2]

	svc_principal_name, err := FetchSPN(svc_addr)
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}
	
	fmt.Printf("Enter User Principal Name: ")
	_, err = fmt.Scanln(&user_principal_name)
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Enter Password: ")
	bpassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println()
	password = string(bpassword)

	ct, tgt, err := RequestTGT(kdc_addr, user_principal_name, password, LIFETIME, nil)
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}

	_ = svc_principal_name
	_ = tgt
	
	fmt.Printf("Lifetime: %v\n", ct.Lifetime)
}
