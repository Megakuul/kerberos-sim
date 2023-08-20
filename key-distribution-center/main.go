package main

import (
	"github.com/spf13/viper"
	"fmt"
	"os"
	"net"
	"sync"
	"log"
	"github.com/megakuul/kerberos-sim/message"
	"google.golang.org/protobuf/proto"
)


type Database struct {
	KDC_Port string `mapstructure:"kdc_port"`
	Kerberos_Token string `mapstructure:"kerberos_token"`
	User_Principals []UserPrincipal `mapstructure:"user_principals"`
	Service_Principals []ServicePrincipal `mapstructure:"service_principals"`
}

type UserPrincipal struct {
	Userid int `mapstructure:"userid"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type ServicePrincipal struct {
	Name string `mapstructure:"name"`
	Key string  `mapstructure:"key"`
}

func LoadDatabase() (Database, error) {
	var database Database

	viper.SetConfigName("database")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./database")
	viper.AddConfigPath("./key-distribution-center")

	err := viper.ReadInConfig()
	if err!=nil {
		return database, err
	}

	err = viper.Unmarshal(&database);
	if err!=nil {
		return database, err
	}

	return database, nil
}

func StartKDC(port string, wg *sync.WaitGroup, errchan chan<-error) {
	defer wg.Done()

	if port == "" {
		log.Fatal("No valid KDC_Port in database [kdc_port: ':187']")
		os.Exit(1)
	}
	
	addr, err := net.ResolveUDPAddr("udp", port)
	if err!=nil {
		log.Fatal(err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err!=nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer conn.Close()
	fmt.Printf("Key-Distribution-Center launched on Port %s\n", port)

	buffer := make([]byte, 1024)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err!=nil {
			errchan<-err
			continue
		}
		req := &message.KDCMessage{}
		if err := proto.Unmarshal(buffer[:n], req); err != nil {
			if _,err = conn.WriteToUDP([]byte(
				fmt.Sprintf("Invalid protobuf request [ERR]:\n%s\n", err),
			), addr); err != nil {
				errchan<-err
			}
			continue
		}
		
		fmt.Printf("Read this shit %s\n", buffer[:n])
		switch req.Msg.(type) {
		case *message.KDCMessage_TGTReq:
			fmt.Println("Got a TGT Request")
		case *message.KDCMessage_TGSReq:
			fmt.Println("Got a TGS Request")
		default:
			fmt.Println("Unknown type")
		}
		
		_,err = conn.WriteToUDP([]byte("I do something"), addr)
		if err!=nil {
			errchan<-err
			continue
		}	
	}
}

func main() {
	db, err := LoadDatabase()
	if err!=nil {
		fmt.Fprintf(os.Stderr, "[ERR]:\n%s\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	errch := make(chan error)

	wg.Add(1)
	go StartKDC(db.KDC_Port, &wg, errch)
	
	go func() {
		for err := range errch {
			if err!=nil {
				fmt.Fprintf(os.Stderr, "[Err]:\n%s\n")
			}
		}
	}()

	wg.Wait()
}
