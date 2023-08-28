package dataloader

import (
	"fmt"
	"strings"
	"errors"
	"github.com/spf13/viper"
)

const M_REALMNOTFOUND = "REALM NOT FOUND!"
const M_USERNOTTRUSTED = "USER NOT FOUND!"
const M_SVCNOTTRUSTED = "SERVICE IS NOT A TRUSTED SERVICE!"
const M_SVCNOTCROSSTRUSTED = "SERVICE IS NOT A CROSS-TRUSTED SERVICE!"

type Database struct {
	KDC_Port string `mapstructure:"kdc_port"`
	Kerberos_Token string `mapstructure:"kerberos_token"`
	Key_Bytes uint64 `mapstructure:"key_bytes"`
	Realms []Realm `mapstructure:"realms"`
}

type Realm struct {
	Name string `mapstructure:"name"`
	Max_Lifetime uint64 `mapstructure:"max_lifetime"`
	User_Principals []UserPrincipal `mapstructure:"user_principals"`
	Service_Principals []ServicePrincipal `mapstructure:"service_principals"`
	External_Service_Principals []string `mapstructure:"external_service_principals"`
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

func GetRealm(name string, db *Database) (*Realm, error) {
	// Really inefficient, in production this would use database querys to perform this
	var realm *Realm
	for _, rlm := range db.Realms {
		if strings.ToLower(rlm.Name) == strings.ToLower(name) {
			realm = &rlm
			break
		}
	}
	if realm==nil {
		return nil, errors.New(M_REALMNOTFOUND) 
	}
	return realm, nil
}

func GetUser(username string, rlm *Realm) (*UserPrincipal, error) {
	// Really inefficient, in production this would use database querys to perform this
	var user *UserPrincipal
	for _, up := range rlm.User_Principals {
		if strings.ToLower(up.Username) == strings.ToLower(username) {
			user = &up
			break
		}
	}
	if user==nil {
		return nil, errors.New(M_USERNOTTRUSTED)
	}
	return user, nil
}

func GetService(name string, rlm *Realm) (*ServicePrincipal, error) {
	// Really inefficient, in production this would use database querys to perform this
	var svc *ServicePrincipal
	for _, sp := range rlm.Service_Principals {
		if strings.ToLower(sp.SPN) == strings.ToLower(name) {
			svc = &sp
			break
		}
	}
	if svc==nil {
		return nil, errors.New(M_SVCNOTTRUSTED)
	}
	return svc, nil
}


func GetCrossRealmService(name string, svc_rlm *Realm, src_rlm *Realm) (*ServicePrincipal, error) {
	// Construct full spn [spn]@[realm]
	spn := fmt.Sprintf("%s@%s", name, svc_rlm.Name)

	// Really inefficient, in production this would use database querys to perform this
	// Especially the usage of such external list is no good practise, dont do this in production
	var svc *ServicePrincipal
	var err error
	for _,ext_sp := range src_rlm.External_Service_Principals {
		if strings.ToLower(ext_sp) == strings.ToLower(spn) {
			svc, err = GetService(name, svc_rlm)
			if err!=nil {
				return nil, err
			}
			break
		}
	}
	if svc==nil {
		return nil, errors.New(M_SVCNOTCROSSTRUSTED)
	}
	return svc, nil
}
