package ticket

type TGT struct {
	SK_TGS string
	UserPrincipal string
	TGSPrincipal string
	IP_List []string
	Lifetime uint
	Timestamp uint
}

// Client Ticket is used for 2 and 4
type CT struct {
	SK_Service string
	ServicePrincipal string
	Timestamp uint
	Lifetime uint
}

// Authenticator is used for 3 and 5
type AUTH struct {
	UserPrincipal string
	Timestamp uint
}

type ST struct {
	UserPrincipal string
	SVCPrincipal string
	IP_List []string
	Timestamp uint
	Lifetime uint
	SK_SVC string
}
