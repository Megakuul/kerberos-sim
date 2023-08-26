package main

import (
	"fmt"
	"os"
	"net"
	"sync"
	"log"
	"errors"
	"strings"
	"time"
	"math/rand"
	"github.com/spf13/viper"
	"github.com/megakuul/kerberos-sim/shared/message"
	"github.com/megakuul/kerberos-sim/shared/crypto"
	"google.golang.org/protobuf/proto"
)


type Database struct {
	KDC_Port string `mapstructure:"kdc_port"`
	Kerberos_Token string `mapstructure:"kerberos_token"`
	Key_Bytes uint `mapstructure:"key_bytes"`
	Realms []Realm `mapstructure:"realms"`
}

type Realm struct {
	Name string `mapstructure:"name"`
	Max_Lifetime uint `mapstructure:"max_lifetime"`
	User_Principals []UserPrincipal `mapstructure:"user_principals"`
	Service_Principals []ServicePrincipal `mapstructure:"service_principals"`
}

type UserPrincipal struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type ServicePrincipal struct {
	SPN string `mapstructure:"spn"`
	Shared_Secret string `mapstructure:"shared_secret"`
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

func StartKDCListener(db *Database, wg *sync.WaitGroup, errchan chan<-error, exit *exit) {
	defer wg.Done()
	
	if db.KDC_Port == "" {
		exit.code = 1
		exit.err = errors.New("No valid KDC_Port in database [kdc_port: ':187']")
		return
	}
	
	addr, err := net.ResolveUDPAddr("udp", db.KDC_Port)
	if err!=nil {
		exit.code = 1
		exit.err = err
		return
	}

	listener, err := net.ListenUDP("udp", addr)
	if err!=nil {
		exit.code = 1
		exit.err = err
		return
	}
	defer listener.Close()
	fmt.Printf("Key-Distribution-Center launched on Port %s\n", db.KDC_Port)

	buffer := make([]byte, 1024)
	for {
		n, addr, err := listener.ReadFromUDP(buffer)
		if err!=nil {
			errchan<-err
			continue
		}

		go func(data []byte, n int, origAddr *net.UDPAddr) {
			addr := *origAddr
			Req := &message.KDCMessage{}
			if err := proto.Unmarshal(data[:n], Req); err != nil {
				if _,err = listener.WriteToUDP([]byte(
					fmt.Sprintf("Invalid protobuf request [ERR]:\n%s\n", err),
				), &addr); err != nil {
					errchan<-err
				}
				return
			}
			
			fmt.Printf("Read this shit %s\n", data[:n])
			switch m:=Req.M.(type) {
			case *message.KDCMessage_ASReq:
				HandleASReq(listener, &addr, db, m, errchan)
			case *message.KDCMessage_TGSReq:
				HandleTGSReq(listener, &addr, db, m, errchan)
			default:
				errchan<-errors.New("Unimplemented type")
			}
		}(buffer, n, addr)
	}
}

func HandleASReq(listener *net.UDPConn, addr *net.UDPAddr, db *Database, msg *message.KDCMessage_ASReq, errchan chan<-error) {
	upn_slice:= strings.Split(msg.UserPrincipal, '@')
	if len(upn_slice) >= 2 {
		if _,err := listener.WriteToUDP(
			[]byte("Invalid UPN, expected [user@realm]"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}
	var realm *Realm
	for _, rlm := range db.Realms {
		if rlm.Name == upn_slice[1] {
			realm = &rlm
			break
		}
	}
	if realm==nil {
		if _,err := listener.WriteToUDP(
			[]byte("Realm not found on KDC database"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}
	var password string
	for _, up := range realm.User_Principals {
		if up.Username == upn_slice[0] {
			password = up.Password
			break
		}
	}
	if password=="" {
		if _,err := listener.WriteToUDP(
			[]byte("No such user found"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}
	
	lifetime:=msg.Lifetime
	if msg.Lifetime>realm.Max_Lifetime {
		lifetime = realm.Max_Lifetime
	}
	timestamp:=uint(time.Now().Unix())

	sk := make([]byte, db.Key_Bytes)
	if _,err := rand.Read(sk); err!=nil {
		errchan<-err
		if _,err := listener.WriteToUDP(
			[]byte("Failed to generate sessionkey"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}

	tgt:= &crypto.TGT{
		sk,
		msg.UserPrincipal,
		msg.IP_List,
		lifetime,
		timestamp,
	}
	as_ct := &crypto.AS_CT{
		sk,
		lifetime,
		timestamp,
	}
	encrypted_tgt, err := crypto.EncryptTGT(tgt, []byte(db.Kerberos_Token))
	if err!=nil {
		errchan<-err
		if _,err := listener.WriteToUDP(
			[]byte("Failed to encrypt TGT token"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}
	encrypted_as_ct, err := crypto.EncryptAS_CT(as_ct, []byte(password))
	if err!=nil {
		errchan<-err
		if _,err := listener.WriteToUDP(
			[]byte("Failed to encrypt AS_CT token"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}
	Res:=&message.KRB_AS_Response{
		encrypted_tgt,
		encrypted_as_ct,
	}
	bRes, err := proto.Marshal(Res)
	if err!=nil {
		errchan<-err
		if _,err := listener.WriteToUDP(
			[]byte("Failed to build protobuf response"),
			addr,
		); err != nil {
			errchan<-err
		}
		return
	}
	
	_,err := listener.WriteToUDP(bRes, addr)
	if err!=nil {
		errchan<-err
		return
	}
}

func HandleTGSReq(listener *net.UDPConn, addr *net.UDPAddr, db *Database, msg *message.KDCMessage_TGSReq, errchan chan<-error) {
	_,err := listener.WriteToUDP([]byte("Handle TGS"), addr)
	if err!=nil {
		errchan<-err
		return
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
		os.Exit(1)
	}

	exit := &exit{nil,0}
	
	var wg sync.WaitGroup
	errch := make(chan error)

	wg.Add(1)
	go StartKDCListener(&db, &wg, errch, exit)

	// Handle Warnings at runtime
	go func() {
		for err := range errch {
			if err!=nil {
				log.Fatal(err)
			}
		}
	}()

	wg.Wait()

	if exit.err!=nil {
		log.Fatal(exit.err)
	}
	os.Exit(exit.code)
}
