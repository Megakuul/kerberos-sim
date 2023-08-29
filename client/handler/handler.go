package handler

import (
	"net"
	"errors"
	"time"
	"github.com/megakuul/kerberos-sim/shared/message"
	"github.com/megakuul/kerberos-sim/shared/crypto"
	"google.golang.org/protobuf/proto"
)

func FetchSPN(svc_addr string) (string, error) {
	con, err := net.Dial("tcp", svc_addr)
	if err!=nil {
		return "", err
	}
	defer con.Close()

	Req := &message.SVCMessage{
		M: &message.SVCMessage_SPNReq{
			SPNReq: &message.SPN_Request{
				SVC_Addr: svc_addr,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return "", err
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return "", err
	}

	bRes := make([]byte, 1024)
	n, err := con.Read(bRes)
	if err!=nil {
		return "", err
	}

	Res:= &message.SPN_Response{}
	if err := proto.Unmarshal(bRes[:n], Res); err!=nil {
		// Return the error if the svc returned a error instead of the Protobuf
		return string(bRes), err
	}
	
	return Res.SPN, nil
}

func RequestTGT(
	kdc_addr string,
	upn string,
	passwd string,
	lifetime uint64,
	ip_list []string) (crypto.AS_CT, []byte, error) {
	
	as_ct := crypto.AS_CT{}

	addr, err := net.ResolveUDPAddr("udp", kdc_addr)
	if err!=nil {
		return as_ct, nil, err
	}
	
	con, err := net.DialUDP("udp", nil, addr)
	if err!=nil {
		return as_ct, nil, err
	}
	defer con.Close()

	Req := &message.KDCMessage{
		M: &message.KDCMessage_ASReq{
			ASReq: &message.KRB_AS_Request{
				UserPrincipal: upn,
				Lifetime: lifetime,
				IP_List: ip_list,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return as_ct, nil, err
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return as_ct, nil, err
	}

	bRes := make([]byte, 1024)
	n, _, err := con.ReadFromUDP(bRes)
	if err!=nil {
		return as_ct, nil, err
	}
	
	Res:= &message.KRB_AS_Response{}
	if err:=proto.Unmarshal(bRes[:n], Res); err!=nil {
		return as_ct, nil, errors.New(string(bRes))
	}

	as_ct, err = crypto.DecryptAS_CT(Res.CT, []byte(passwd))
	if err!=nil {
		// Here you could display a more verbose message by returning err
		return as_ct, nil, errors.New("Wrong Password")
	}

	return as_ct, Res.TGT, nil
}


func RequestTGS(
	kdc_addr string,
	spn string,
	upn string,
	lifetime uint64,
	sk []byte,
	tgt []byte) (crypto.TGS_CT, []byte, error) {
	
	tgs_ct := crypto.TGS_CT{}

	addr, err := net.ResolveUDPAddr("udp", kdc_addr)
	if err!=nil {
		return tgs_ct, nil, err
	}
	
	con, err := net.DialUDP("udp", nil, addr)
	if err!=nil {
		return tgs_ct, nil, err
	}
	defer con.Close()

	Auth := &crypto.AUTH{
		UserPrincipal: upn,
		Timestamp: uint64(time.Now().Unix()),
	}
	bAuth, err := crypto.EncryptAUTH(Auth, sk)
	if err!=nil {
		return tgs_ct, nil, err
	}

	Req := &message.KDCMessage{
		M: &message.KDCMessage_TGSReq{
			TGSReq: &message.KRB_TGS_Request{
				SVCPrincipal: spn,
				Lifetime: lifetime,
				Authenticator: bAuth,
				TGT: tgt,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return tgs_ct, nil, err
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return tgs_ct, nil, err
	}

	bRes := make([]byte, 1024)
	n, _, err := con.ReadFromUDP(bRes)
	if err!=nil {
		return tgs_ct, nil, err
	}
	
	Res:= &message.KRB_TGS_Response{}
	if err:=proto.Unmarshal(bRes[:n], Res); err!=nil {
		return tgs_ct, nil, errors.New(string(bRes))
	}

	tgs_ct, err = crypto.DecryptTGS_CT(Res.CT, sk)
	if err!=nil {
		return tgs_ct, nil, err
	}

	return tgs_ct, Res.ST, nil
}

func RequestSVC(
	svc_addr string,
	request string,
	upn string,
	sk []byte,
	st []byte) (string, error) {

	con, err := net.Dial("tcp", svc_addr)
	if err!=nil {
		return "", err
	}
	defer con.Close()

	auth:= &crypto.AUTH {
		UserPrincipal: upn,
		Timestamp: uint64(time.Now().Unix()),
	}

	encrypted_auth, err:= crypto.EncryptAUTH(auth, sk)
	if err!=nil {
		return "", err
	}

	ap_req := &crypto.AP_REQ {
		Request: request,
	}

	encrypted_ap_req, err := crypto.EncryptAP_REQ(ap_req, sk)
	if err!=nil {
		return "", err
	}
	
	Req := &message.SVCMessage{
		M: &message.SVCMessage_APReq{
			APReq: &message.AP_Request{
				Authenticator: encrypted_auth,
				ST: st,
				REQ: encrypted_ap_req,
			},
		},
	}

	bReq, err := proto.Marshal(Req)
	if err!=nil {
		return "", err
	}
	_, err = con.Write(bReq)
	if err!=nil {
		return "", err
	}

	bRes := make([]byte, 1024)
	n, err := con.Read(bRes)
	if err!=nil {
		return "", err
	}

	Res:= &message.AP_Response{}
	if err := proto.Unmarshal(bRes[:n], Res); err!=nil {
		// Return the error if the svc returned a error instead of the Protobuf
		return string(bRes), err
	}

	decrypted_ap_res, err := crypto.DecryptAP_RES(Res.RES, sk)
	if err!=nil {
		return "", err
	}

	// Here you could also potentially check the timestamp of the server
	return decrypted_ap_res.Response, nil
}

