package crypto

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/cipher"
	"crypto/rand"
	"google.golang.org/protobuf/proto"
)

func EncryptTGT(tgt *TGT, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(tgt)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptTGT(tgt []byte, key []byte) (TGT, error) {
	tgt_buf := TGT{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return tgt_buf, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return tgt_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := tgt[:nSize], tgt[nSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertxt, []byte{})
	if err!=nil {
		return tgt_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &tgt_buf); err!=nil {
		return tgt_buf, err
	}
	
	return tgt_buf, nil
}

func EncryptAS_CT(as_ct *AS_CT, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(as_ct)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptAS_CT(as_ct []byte, key []byte) (AS_CT, error) {
	as_ct_buf := AS_CT{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return as_ct_buf, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return as_ct_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := as_ct[:nSize], as_ct[nSize:]
	
	decrypted, err := gcm.Open(nil, nonce, ciphertxt, []byte{})
	if err!=nil {
		return as_ct_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &as_ct_buf); err!=nil {
		return as_ct_buf, err
	}
	return as_ct_buf, nil
}

func EncryptAUTH(auth *AUTH, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(auth)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptAUTH(auth []byte, key []byte) (AUTH, error) {
	auth_buf := AUTH{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return auth_buf, err
	}
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return auth_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := auth[:nSize], auth[nSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertxt, []byte{})
	if err!=nil {
		return auth_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &auth_buf); err!=nil {
		return auth_buf, err
	}
	return auth_buf, nil
}


func EncryptTGS_CT(tgs_ct *TGS_CT, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(tgs_ct)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptTGS_CT(tgs_ct []byte, key []byte) (TGS_CT, error) {
	tgs_ct_buf := TGS_CT{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return tgs_ct_buf, err
	}
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return tgs_ct_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := tgs_ct[:nSize], tgs_ct[nSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertxt, nil)
	if err!=nil {
		return tgs_ct_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &tgs_ct_buf); err!=nil {
		return tgs_ct_buf, err
	}
	return tgs_ct_buf, nil
}

func EncryptST(st *ST, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(st)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptST(st []byte, key []byte) (ST, error) {
	st_buf := ST{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return st_buf, err
	}
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return st_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := st[:nSize], st[nSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertxt, nil)
	if err!=nil {
		return st_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &st_buf); err!=nil {
		return st_buf, err
	}
	return st_buf, nil
}



func EncryptAP_REQ(ap_req *AP_REQ, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(ap_req)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptAP_REQ(ap_req []byte, key []byte) (AP_REQ, error) {
	ap_req_buf := AP_REQ{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return ap_req_buf, err
	}
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return ap_req_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := ap_req[:nSize], ap_req[nSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertxt, nil)
	if err!=nil {
		return ap_req_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &ap_req_buf); err!=nil {
		return ap_req_buf, err
	}
	return ap_req_buf, nil
}


func EncryptAP_RES(ap_res *AP_RES, key []byte) ([]byte, error) {
	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err!= nil {
		return nil, err
	}

	encoded, err := proto.Marshal(ap_res)
	if err!=nil {
		return nil, err
	}

	encrypted := gcm.Seal(nil, nonce, encoded, []byte{})
	return append(nonce, encrypted...), nil
}

func DecryptAP_RES(ap_res []byte, key []byte) (AP_RES, error) {
	ap_res_buf := AP_RES{}

	hash:=sha256.Sum256(key)
	block, err := aes.NewCipher(hash[:])
	if err!=nil {
		return ap_res_buf, err
	}
	gcm, err := cipher.NewGCM(block)
	if err!=nil {
		return ap_res_buf, err
	}

	nSize := gcm.NonceSize()
	nonce, ciphertxt := ap_res[:nSize], ap_res[nSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertxt, nil)
	if err!=nil {
		return ap_res_buf, err
	}

	if err:=proto.Unmarshal(decrypted, &ap_res_buf); err!=nil {
		return ap_res_buf, err
	}
	return ap_res_buf, nil
}
