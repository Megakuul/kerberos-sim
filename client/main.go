package main

import (
	"fmt"
	"os"
	"github.com/megakuul/kerberos-sim/client/handler"
	"golang.org/x/crypto/ssh/terminal"
)

var svc_addr string
var kdc_addr string
var user_principal_name string
var svc_principal_name string
var password string

const LIFETIME = uint64(259200)

func main() {
	if len(os.Args) != 3 {
		fmt.Println("usage: client [svc] [kdc]")
		os.Exit(1)
	}

	svc_addr = os.Args[1]
	kdc_addr = os.Args[2]

	svc_principal_name, err := handler.FetchSPN(svc_addr)
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

	as_ct, tgt, err := handler.RequestTGT(
		kdc_addr,
		user_principal_name,
		password,
		LIFETIME,
		nil,
	)
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Fetched TGT (stage 1 & 2)")

	tgs_ct, st, err := handler.RequestTGS(
		kdc_addr,
		svc_principal_name,
		user_principal_name,
		LIFETIME,
		as_ct.SK_TGS,
		tgt,
	)
	
	if err!=nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("Fetched ST (stage 3 & 4)")

	var curinput string
	for {
		fmt.Printf("%s>", svc_principal_name)
		fmt.Scanln(&curinput)
		output, err := handler.RequestSVC(
			svc_addr,
			curinput,
			user_principal_name,
			tgs_ct.SK_SVC,
			st,
		)
		if err!=nil {
			fmt.Println(err)
			continue
		}
		fmt.Println(output)
	}
}
