package handler

import (
	"time"
	"math/rand"
	"github.com/megakuul/kerberos-sim/shared/crypto"
)

const M_HELPSTR = `
usage:
- up  userprincipal
- sp  serviceprincipal
- tl  ticketlifetime
- sh  sayhello
`

var h_list = []string{
	"Whats up",
	"Salut",
	"Wazzzzzzzup",
	"Hello",
	"QUACK",
	"LUUKAGEM",
}

func getShellOutput(input string, st *crypto.ST) (string) {
	switch input {
	case "up":
		fallthrough
	case "userprincipal":
		return st.UserPrincipal
	case "sp":
		fallthrough
	case "serviceprincipal":
		return st.SVCPrincipal
	case "tl":
		fallthrough
	case "ticketlifetime":
		fmt_time := time.Unix(int64(st.Lifetime+st.Timestamp), 0).Format(
			"2006-01-02 15:04:05",
		)
		return fmt_time
	case "sh":
		fallthrough
	case "sayhello":
		return h_list[rand.Intn(len(h_list))]
	default:
		return M_HELPSTR
	}
	return ""
}
