package listener

import (
	"fmt"
	"net"
	"sync"
	"errors"
	"google.golang.org/protobuf/proto"
	"github.com/megakuul/kerberos-sim/shared/message"
	"github.com/megakuul/kerberos-sim/key-distribution-center/dataloader"
	"github.com/megakuul/kerberos-sim/key-distribution-center/handler"
)

type Exit struct {
	Err error
	Code int	
}

func StartKDCListener(db *dataloader.Database, wg *sync.WaitGroup, errchan chan<-error, exit *Exit) {
	defer wg.Done()
	
	if db.KDC_Port == "" {
		exit.Code = 1
		exit.Err = errors.New("No valid KDC_Port in database [kdc_port: ':187']")
		return
	}
	
	addr, err := net.ResolveUDPAddr("udp", db.KDC_Port)
	if err!=nil {
		exit.Code = 1
		exit.Err = err
		return
	}

	listener, err := net.ListenUDP("udp", addr)
	if err!=nil {
		exit.Code = 1
		exit.Err = err
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
			
			switch m:=Req.M.(type) {
			case *message.KDCMessage_ASReq:
				handler.HandleASReq(listener, &addr, db, m.ASReq, errchan)
			case *message.KDCMessage_TGSReq:
				handler.HandleTGSReq(listener, &addr, db, m.TGSReq, errchan)
			default:
				errchan<-err
				if _,err := listener.WriteToUDP(
					[]byte("Invalid Protobuf request"),
					&addr,
				); err != nil {
					errchan<-err
				}
			}
		}(buffer, n, addr)
	}
}
