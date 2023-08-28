package handler

import (
	"net"
	"google.golang.org/protobuf/proto"
	"github.com/megakuul/kerberos-sim/service/dataloader"
	"github.com/megakuul/kerberos-sim/shared/message"
)

func HandleSPNReq(con *net.TCPConn, db *dataloader.Database, errchan chan<-error) {
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

func HandleAPReq(con *net.TCPConn, db *dataloader.Database, msg *message.KRB_AP_Request, errchan chan<-error) {
	
}

func HandleCMDReq(con *net.TCPConn, db *dataloader.Database, msg *message.CMD_Request, errchan chan<-error) {

	
}
