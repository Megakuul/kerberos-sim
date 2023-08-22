package main

import (
	"fmt"
	"net"
	"log"
	"sync"
	"os"
	"github.com/megakuul/kerberos-sim/message"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/proto"
)

type Database struct {
	SVC_Port string `mapstructure:"svc_port"`
	Shared_Secret string `mapstructure:"shared_secret"`
	SPN string `mapstructure:"spn"`
}

func LoadDatabase() (Database, error) {
	var database Database

	viper.SetConfigName("database")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./database")
	viper.AddConfigPath("./service")

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

func StartSVCListener(db Database, wg *sync.WaitGroup, errchan chan<-error) {
	defer wg.Done()

	if db.SVC_Port == "" {
		log.Fatal("No valid SVC_Port in database [svc_port: ':187'")
		os.Exit(1)
	}

	addr, err := net.ResolveTCPAddr("tcp", db.SVC_Port)
	if err!=nil {
		log.Fatal(err)
		os.Exit(1)
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err!= nil {
		log.Fatal(err)
		os.Exit(1)
	}
	defer listener.Close()
	fmt.Printf("Service %s launched on Port %s\n", db.SPN, db.SVC_Port)

	bReq := make([]byte, 1024)

	for {
		con, err := listener.AcceptTCP()
		if err!=nil {
			errchan<-err
			con.Close()
			continue
		}
		defer con.Close()

		n, err := con.Read(bReq)
		if err!=nil {
			errchan<-err
			continue
		}
		
		Req := &message.SVCMessage{}

		if err := proto.Unmarshal(bReq[:n], Req); err!=nil {
			if _,err = con.Write([]byte(
				fmt.Sprintf("Invalid protobuf request [ERR]:\n%s\n", err),
			)); err!=nil {
				errchan<-err
			}
			continue
		}

		fmt.Println("I read some shit")
		
		switch m := Req.M.(type) {
		case *message.SVCMessage_SPNReq:
			HandleSPN(con, db, errchan)
		default:
			fmt.Println("Unimplemented type")
			_ = m
		}
	}
}

func HandleSPN(con *net.TCPConn, db Database, errchan chan<-error) {
	Res := &message.SPNResponse{
		SPN: db.SPN,
	}
	
	bRes, err := proto.Marshal(Res)
	if err!=nil {
		errchan<-err
		_, err = con.Write([]byte(err.Error()))
		if err!=nil {
			errchan<-err
			return
		}
	}
	
	_, err = con.Write(bRes)
	if err!=nil {
		errchan<-err
		_, err = con.Write([]byte(err.Error()))
		if err!=nil {
			errchan<-err
			return
		}	
	}
}

func main() {
	db, err := LoadDatabase()
	if err!=nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	errch := make(chan error)

	wg.Add(1)
	go StartSVCListener(db, &wg, errch)

	go func() {
		for err := range errch {
			if err!=nil {
				log.Fatal(err)
			}
		}
	}()

	wg.Wait()
}


