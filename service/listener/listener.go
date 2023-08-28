package listener

import (
	"fmt"
	"sync"
	"net"
	"errors"
	"google.golang.org/protobuf/proto"
	"github.com/megakuul/kerberos-sim/shared/message"
	"github.com/megakuul/kerberos-sim/service/dataloader"
	"github.com/megakuul/kerberos-sim/service/handler"
)

const M_INVALIDADDR = "SVC_ADDR FROM DATABASE IS INVALID! (EXPECTED svc_addr: ':187')"
const M_INVALIDPROTO = "INVALID PROTOBUF REQUEST! (EXPECTED VALID PROTO3 BLOCK)"
const M_UNEXPECTEDPROTO = "UNEXPECTED PROTOBUF REQUEST! (EXPECTED SPN, AP or CMD REQUEST) "

type Exit struct {
	Err error
	Code int
}

func StartSVCListener(
	db *dataloader.Database,
	wg *sync.WaitGroup,
	errchan chan<-error,
	exit *Exit) {
	
	defer wg.Done()

	if db.SVC_Addr == "" {
		exit.Code = 1
		exit.Err = errors.New(M_INVALIDADDR)
		return
	}

	addr, err := net.ResolveTCPAddr("tcp", db.SVC_Addr)
	if err!=nil {
		exit.Code = 1
		exit.Err = err
		return
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err!= nil {
		exit.Code = 1
		exit.Err = err
		return
	}
	defer listener.Close()
	
	fmt.Printf("%s listening on %s\n", db.SPN, db.SVC_Addr)

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
					M_INVALIDPROTO,
				)); err!=nil {
					errchan<-err
				}
				return
			}
			
			switch m := Req.M.(type) {
			case *message.SVCMessage_SPNReq:
				handler.HandleSPNReq(&con, db, errchan)
			case *message.SVCMessage_APReq:
				handler.HandleAPReq(&con, db, m.APReq, errchan)
			case *message.SVCMessage_CMDReq:
				handler.HandleCMDReq(&con, db, m.CMDReq, errchan)
			default:
				errchan<-errors.New(M_UNEXPECTEDPROTO)
				if _,err := con.Write(
					[]byte(M_UNEXPECTEDPROTO),
				); err != nil {
					errchan<-err
				}
			}
		}(con)
	}
}



