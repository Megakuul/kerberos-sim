package main

import (
	"fmt"
	"net"
	"os"

	"github.com/megakuul/kerberos-sim/message"
	"google.golang.org/protobuf/proto"
	"golang.org/x/crypto/ssh/terminal"
)

var svc_addr string
var kdc_addr string
var user_principal_name string
var svc_principal_name string
var password string


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

// TODO: Return a TGT and a session key instead of a string
func RequestTGT(kdc_addr string, upn string) (string, error) {
	addr, err := net.ResolveUDPAddr("udp", kdc_addr)
	if err!=nil {
		return "", nil
	}

	con, err := net.DialUDP("udp", nil, addr)
	if err!=nil {
		return "", nil
	}
	defer con.Close()

	Req := &message.KDCMessage{
		M: &message.KDCMessage_ASReq{
			ASReq: &message.KRB_AS_Request{
				UPN: upn,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return "", nil
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return "", nil
	}

	bRes := make([]byte, 1024)
	n, _, err := con.ReadFromUDP(bRes)
	if err!=nil {
		return "", nil
	}

	// TODO: Implement server Logic and remove this return
	return string(bRes), nil
	
	Res:= &message.KRB_AS_Response{}
	if err:=proto.Unmarshal(bRes[:n], Res); err!=nil {
		return string(bRes), err
	}

	return string(Res.TGT), nil
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

	fmt.Println(svc_principal_name)
	res, err := RequestTGT(kdc_addr, user_principal_name)
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println(res)
}
