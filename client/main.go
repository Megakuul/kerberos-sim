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

	req := &message.SPNRequest{
		SVC_Addr: svc_addr,
	}

	breq, err := proto.Marshal(req)
	if err!=nil {
		return "", err
	}
	_, err = con.Write(breq)
	if err!=nil {
		return "", err
	}

	bres := make([]byte, 1024)
	n, err := con.Read(bres)
	if err!=nil {
		return "", err
	}

	res:= &message.SPNResponse{}
	if err := proto.Unmarshal(bres[:n], res); err!=nil {
		return "", err
	}
	return res.SPN, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("usage: %s [svc] [kdc]\n", os.Args[0])
		os.Exit(1)
	}

	svc_addr = os.Args[1]
	kdc_addr = os.Args[2]

	svc_principal_name, err = FetchSPN(svc_addr)
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
	password = string(bpassword)	
	
}
