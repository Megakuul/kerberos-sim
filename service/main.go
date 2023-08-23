package main

import (
	"fmt"
	"net"
	"log"
	"sync"
	"os"
	"errors"
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

func StartSVCListener(db *Database, wg *sync.WaitGroup, errchan chan<-error, exit *exit) {
	defer wg.Done()

	if db.SVC_Port == "" {
		exit.code = 1
		exit.err = errors.New("No valid SVC_Port in database [svc_port]: ':187'")
		return
	}

	addr, err := net.ResolveTCPAddr("tcp", db.SVC_Port)
	if err!=nil {
		exit.code = 1
		exit.err = err
		return
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err!= nil {
		exit.code = 1
		exit.err = err
		return
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

		go func (origCon *net.TCPConn) {
			con := *origCon
			defer con.Close()
			n, err := con.Read(bReq)
			if err!=nil {
				errchan<-err
				return
			}
			
			Req := &message.SVCMessage{}

			if err := proto.Unmarshal(bReq[:n], Req); err!=nil {
				if _,err = con.Write([]byte(
					fmt.Sprintf("Invalid protobuf request [ERR]:\n%s\n", err),
				)); err!=nil {
					errchan<-err
				}
				return
			}

			fmt.Println("I read some shit")
			
			switch m := Req.M.(type) {
			case *message.SVCMessage_SPNReq:
				HandleSPNReq(&con, db, errchan)
			case *message.SVCMessage_APReq:
				HandleAPReq(&con, db, m, errchan)
			case *message.SVCMessage_CMDReq:
				HandleCMDReq(&con, db, m, errchan)
			default:
				errchan<-errors.New("Unimplemented type")
			}
		}(con)
	}
}

func HandleCMDReq(con *net.TCPConn, db *Database, msg *message.SVCMessage_CMDReq, errchan chan<-error) {

	
}

func HandleAPReq(con *net.TCPConn, db *Database, msg *message.SVCMessage_APReq, errchan chan<-error) {
	
}

func HandleSPNReq(con *net.TCPConn, db *Database, errchan chan<-error) {
	Res := &message.SPN_Response{
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

type exit struct {
	err error
	code int	
}

func main() {
	db, err := LoadDatabase()
	if err!=nil {
		log.Fatal(err)
	}

	exit := &exit{nil,0}
	
	var wg sync.WaitGroup
	errch := make(chan error)

	wg.Add(1)
	go StartSVCListener(&db, &wg, errch, exit)

	go func() {
		for err := range errch {
			if err!=nil {
				log.Fatal(err)
			}
		}
	}()

	wg.Wait()

	if exit.err!=nil{
		log.Fatal(exit.err)
	}
	os.Exit(exit.code)
}


