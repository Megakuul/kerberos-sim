package handler

import (
	"net"
	"time"
	"google.golang.org/protobuf/proto"
	"github.com/megakuul/kerberos-sim/shared/crypto"
	"github.com/megakuul/kerberos-sim/service/dataloader"
	"github.com/megakuul/kerberos-sim/shared/message"
)

const M_FAILEDDECRYPTST = "FAILED TO DECRYPT SERVICE TICKET!"
const M_FAILEDDECRYPTAUTH = "FAILED TO DECRYPT AUTHENTICATOR!"
const M_TIMEOUTOFSYNC = "INVALID TIMESTAMP! (CHECK IF YOUR TIME IS IN SYNC)"
const M_STCORRUPTED = "SERVICE TICKET IS CORRUPTED! (WRONG USERPRINCIPAL or SERVICEPRINCIPAL)"
const M_STEXPIRED = "SERVICE TICKET HAS EXPIRED!"
const M_NOTALLOWED = "YOUR NOT ALLOWED TO USE THIS TICKET FROM YOUR CURRENT IP ADDRESS!"
const M_FAILEDDECRYPTREQ = "FAILED TO DECRYPT REQUEST!"
const M_FAILEDENCRYPTRES = "FAILED TO ENCRYPT RESPONSE!"
const M_FAILEDBUILDPROTO = "FAILED TO BUILD PROTO RESPONSE!"

// Max time shift of 5 minutes
const MAX_TIME_SHIFT = uint64(300)

func handleErr(errm string, con *net.TCPConn, errchan chan<-error) {
	if _, err := con.Write(
		[]byte(errm),
	); err!=nil {
		errchan<-err
	}	
}

func HandleSPNReq(
	con *net.TCPConn,
	db *dataloader.Database,
	errchan chan<-error) {
	
	Res := &message.SPN_Response{
		SPN: db.SPN,
	}
	
	bRes, err := proto.Marshal(Res)
	if err!=nil {
		errchan<-err
		handleErr(err.Error(), con, errchan)
		return
	}
	
	_, err = con.Write(bRes)
	if err!=nil {
		errchan<-err
		handleErr(err.Error(), con, errchan)
		return
	}
}

func HandleAPReq(
	con *net.TCPConn,
	db *dataloader.Database,
	msg *message.AP_Request,
	errchan chan<-error) {

	st, err := crypto.DecryptST(msg.ST, []byte(db.Shared_Secret))
	if err!= nil {
		handleErr(M_FAILEDDECRYPTST, con, errchan)
		return
	}

	auth, err := crypto.DecryptAUTH(msg.Authenticator, st.SK_SVC)
	if err!=nil {
		handleErr(M_FAILEDDECRYPTAUTH, con, errchan)
		return
	}
	
	timestamp:=uint64(time.Now().Unix())

	// Check if time is out of sync
	if auth.Timestamp>timestamp+MAX_TIME_SHIFT || auth.Timestamp<timestamp-MAX_TIME_SHIFT {
		handleErr(M_TIMEOUTOFSYNC, con, errchan)
		return
	}

	// Check if Service Principal matches
	if st.SVCPrincipal!=db.SPN {
		handleErr(M_STCORRUPTED, con, errchan)
		return
	}

	// Check if User Principal matches
	if auth.UserPrincipal!=st.UserPrincipal {
		handleErr(M_STCORRUPTED, con, errchan)
		return
	}

	// Check if ST has expired
	if st.Lifetime+st.Timestamp < timestamp {
		handleErr(M_STEXPIRED, con, errchan)
		return
	}

	// This is very inefficient, in production use a hashmap instead
	if st.IP_List!=nil {
		ip := con.RemoteAddr().(*net.TCPAddr).IP.String()
		contained := false
		for _, curip := range st.IP_List {
			if ip == curip {
				contained = true
				break
			}
		}
		if !contained {
			handleErr(M_NOTALLOWED, con, errchan)
			return
		}
	}

	req, err := crypto.DecryptAP_REQ(msg.REQ, st.SK_SVC)
	if err!=nil {
		handleErr(M_FAILEDDECRYPTREQ, con, errchan)
		return
	}

	
	// Here you would usually handle the applications functionalitys
	// For this example app we just use a super simple "remote shell"
	// that sends and receives strings
	ap_res:= &crypto.AP_RES {
		Response: getShellOutput(req.Request, &st),
		Timestamp: timestamp,
	}

	encrypted_ap_res, err := crypto.EncryptAP_RES(ap_res, st.SK_SVC)
	if err!=nil {
		handleErr(M_FAILEDENCRYPTRES, con, errchan)
		return
	}

	Res:= &message.AP_Response {
		RES: encrypted_ap_res,
	}

	bRes, err := proto.Marshal(Res)
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDBUILDPROTO, con, errchan)
		return
	}
	
	_, err = con.Write(bRes)
	if err!=nil {
		errchan<-err
		return
	}
}

