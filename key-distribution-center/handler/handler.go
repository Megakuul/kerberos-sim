package handler

import (
	"net"
	"time"
	"strings"
	"math/rand"
	"google.golang.org/protobuf/proto"
	"github.com/megakuul/kerberos-sim/shared/message"
	"github.com/megakuul/kerberos-sim/shared/crypto"
	"github.com/megakuul/kerberos-sim/key-distribution-center/dataloader"
)


const M_INVALIDUPN = "INVALID USERPRINCIPAL FORMAT! (EXPECTED 'USER@REALM')"
const M_FAILEDSK = "FAILED TO GENERATE SESSIONKEY! THIS MAY BE A TEMPORARY PROBLEM"
const M_FAILEDENCRYPTTGT = "FAILED TO ENCRYPT TICKET GRANTING TICKET!"
const M_FAILEDENCRYPTAS_CT = "FAILED TO ENCRYPT AUTH-SERVICE CLIENT TICKET!"
const M_FAILEDENCRYPTST = "FAILED TO ENCRYPT SERVICE TICKET!"
const M_FAILEDENCRYPTTGS_CT = "FAILED TO ENCRYPT TICKET GRANTING SERVICE CLIENT TICKET!"
const M_FAILEDBUILDPROTO = "FAILED TO BUILD PROTO RESPONSE!"
const M_UNEXPECTEDSPN = "UNEXPECTED SERVICEPRINCIPAL FORMAT! (EXPECTED 'SERVICE@REALM')"
const M_FAILEDDECRYPTTGT = "FAILED TO DECRYPT TICKET GRANTING TICKET!"
const M_FAILEDDECRYPTAUTH = "FAILED TO DECRYPT AUTHENTICATOR!"
const M_TIMEOUTOFSYNC = "INVALID TIMESTAMP! (CHECK IF YOUR TIME IS IN SYNC)"
const M_TGTCORRUPTED = "TICKET GRANTING TICKET IS CORRUPTED!"
const M_TGTEXPIRED = "TICKET GRANTING TICKET HAS EXPIRED!"
	

// Max time shift of 5 minutes
const MAX_TIME_SHIFT = uint64(300)

func handleErr(err string, listener *net.UDPConn, addr *net.UDPAddr, errchan chan<-error) {
	if _,err := listener.WriteToUDP(
		[]byte(err),
		addr,
	); err != nil {
		errchan<-err
	}
}

func HandleASReq(listener *net.UDPConn, addr *net.UDPAddr, db *dataloader.Database, msg *message.KRB_AS_Request, errchan chan<-error) {
	upn_slice:= strings.Split(msg.UserPrincipal, "@")
	if len(upn_slice) < 2 {
		handleErr(M_INVALIDUPN, listener, addr, errchan)
		return
	}
	
	realm, err := dataloader.GetRealm(upn_slice[1], db)
	if err!=nil {
		handleErr(err.Error(), listener, addr, errchan)
		return
	}

	user, err := dataloader.GetUser(upn_slice[0], realm)
	if err!=nil {
		handleErr(err.Error(), listener, addr, errchan)
		return
	}
	password := user.Password
	
	lifetime:=msg.Lifetime
	if msg.Lifetime>realm.Max_Lifetime {
		lifetime = realm.Max_Lifetime
	}
	timestamp:=uint64(time.Now().Unix())

	sk := make([]byte, db.Key_Bytes)
	if _,err := rand.Read(sk); err!=nil {
		errchan<-err
		handleErr(M_FAILEDSK, listener, addr, errchan)
		return
	}

	tgt:= &crypto.TGT{
		SK_TGS: sk,
		UserPrincipal: msg.UserPrincipal,
		IP_List: msg.IP_List,
		Lifetime: lifetime,
		Timestamp: timestamp,
	}
	as_ct := &crypto.AS_CT{
		SK_TGS: sk,
		Lifetime: lifetime,
		Timestamp: timestamp,
	}

	encrypted_tgt, err := crypto.EncryptTGT(tgt, []byte(db.Kerberos_Token))
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDENCRYPTTGT, listener, addr, errchan)
		return
	}
	encrypted_as_ct, err := crypto.EncryptAS_CT(as_ct, []byte(password))
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDENCRYPTAS_CT, listener, addr, errchan)
		return
	}
	Res:=&message.KRB_AS_Response{
		TGT: encrypted_tgt,
		CT: encrypted_as_ct,
	}
	bRes, err := proto.Marshal(Res)
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDBUILDPROTO, listener, addr, errchan)
		return
	}
	
	_,err = listener.WriteToUDP(bRes, addr)
	if err!=nil {
		errchan<-err
		return
	}
}

func HandleTGSReq(listener *net.UDPConn, addr *net.UDPAddr, db *dataloader.Database, msg *message.KRB_TGS_Request, errchan chan<-error) {

	spn_slice:= strings.Split(msg.SVCPrincipal, "@")
	if len(spn_slice) < 2 {
		handleErr(M_UNEXPECTEDSPN, listener, addr, errchan)
		return
	}

	realm, err := dataloader.GetRealm(spn_slice[1], db)
	if err!=nil {
		handleErr(err.Error(), listener, addr, errchan)
		return
	}

	tgt, err := crypto.DecryptTGT(msg.TGT, []byte(db.Kerberos_Token))
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDDECRYPTTGT, listener, addr, errchan)
		return
	}

	auth, err := crypto.DecryptAUTH(msg.Authenticator, tgt.SK_TGS)
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDDECRYPTAUTH, listener, addr, errchan)
		return
	}

	lifetime:=msg.Lifetime
	if msg.Lifetime>realm.Max_Lifetime {
		lifetime = realm.Max_Lifetime
	}
	timestamp:=uint64(time.Now().Unix())

	// Check if time is out of sync
	if auth.Timestamp > timestamp+MAX_TIME_SHIFT || auth.Timestamp < timestamp-MAX_TIME_SHIFT {
		handleErr(M_TIMEOUTOFSYNC, listener, addr, errchan)
		return
	}

	// Check if Authenticator matches to TGT
	if auth.UserPrincipal!=tgt.UserPrincipal {
		handleErr(M_TGTCORRUPTED, listener, addr, errchan)
		return
	}

	// Check if TGT has expired
	if tgt.Lifetime+tgt.Timestamp < timestamp {
		handleErr(M_TGTEXPIRED, listener, addr, errchan)
		return
	}

	upn_slice:= strings.Split(tgt.UserPrincipal, "@")
	if len(upn_slice) < 2 {
		handleErr(M_TGTCORRUPTED, listener, addr, errchan)
		return
	}

	var svc *dataloader.ServicePrincipal
	if strings.ToLower(upn_slice[1]) == strings.ToLower(spn_slice[1]) {
		// Handle Services inside the same Realm as the user
		svc, err = dataloader.GetService(spn_slice[0], realm)
		if err!=nil {
			handleErr(err.Error(), listener, addr, errchan)
			return
		}
	} else {
		// Handle CrossRealmServices
		src_realm, err:=dataloader.GetRealm(upn_slice[1], db)
		if err!=nil {
			handleErr(err.Error(), listener, addr, errchan)
			return
		}
		svc, err = dataloader.GetCrossRealmService(spn_slice[0], realm, src_realm)
		if err!=nil {
			handleErr(err.Error(), listener, addr, errchan)
			return
		}
	}

	sk := make([]byte, db.Key_Bytes)
	if _,err := rand.Read(sk); err!=nil {
		errchan<-err
		handleErr(M_FAILEDSK, listener, addr, errchan)
		return
	}

	st:= &crypto.ST{
		UserPrincipal: tgt.UserPrincipal,
		SVCPrincipal: msg.SVCPrincipal,
		IP_List: tgt.IP_List,
		Lifetime: lifetime,
		Timestamp: timestamp,
		SK_SVC: sk,
	}
	tgs_ct := &crypto.TGS_CT{
		SK_SVC: sk,
		SVCPrincipal: msg.SVCPrincipal,
		Lifetime: lifetime,
		Timestamp: timestamp,
	}
	encrypted_st, err := crypto.EncryptST(st, []byte(svc.Shared_Secret))
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDENCRYPTST, listener, addr, errchan)
		return
	}
	encrypted_tgs_ct, err := crypto.EncryptTGS_CT(tgs_ct, tgt.SK_TGS)
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDENCRYPTTGS_CT, listener, addr, errchan)
		return
	}
	
	Res:=&message.KRB_TGS_Response{
		ST: encrypted_st,
		CT: encrypted_tgs_ct,
	}
	bRes, err := proto.Marshal(Res)
	if err!=nil {
		errchan<-err
		handleErr(M_FAILEDBUILDPROTO, listener, addr, errchan)
		return
	}
	
	_,err = listener.WriteToUDP(bRes, addr)
	if err!=nil {
		errchan<-err
		return
	}
}
