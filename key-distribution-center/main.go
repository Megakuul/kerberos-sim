package main

import (
	"github.com/spf13/viper"
	"fmt"
	"os"
	"net"
)

type Database struct {
	Kdc_Port string `mapstructure:"kdc_port"`
	Kerberos_Token string `mapstructure:"kerberos_token"`
	User_Principals []UserPrincipal `mapstructure:"user_principals"`
	Service_Principals []ServicePrincipal `mapstructure:"service_principals"`
}

type UserPrincipal struct {
	Userid int `mapstructure:"userid"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type ServicePrincipal struct {
	Name string `mapstructure:"name"`
	Key string  `mapstructure:"key"`
}

func LoadDatabase() (Database, error) {
	var database Database

	viper.SetConfigName("database")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

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


func main() {
	db, err := LoadDatabase()
	if err!=nil {
		fmt.Fprintf(os.Stderr, "Invalid database config [ERR]:\n%s\n", err)
		return
	}

	addr, err := net.ResolveUDPAddr("udp", db.Kdc_Port)
	if err!=nil{
		fmt.Fprintf(os.Stderr, "Failed to start server [ERR]:\n%s\n", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err!=nil {
		fmt.Fprintf(os.Stderr, "Failed to start server [ERR]:\n%s\n", err)
		return
	}
	defer conn.Close()

	fmt.Printf("Key-Distribution-Center listening on UDP [%s]\n", db_Kdc_Port)
	
	buffer := make([]byte, 1024)

	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err!=nil {
			fmt.Fprintf(os.Stderr, "Cannot read req [ERR]:\n%s\n", err)
			continue
		}

		fmt.Printf("Received %d bytes from %s: %s\n", n, addr, string(buffer[:n]))

		response := []byte("Wazzzzzup from KDC")
		_, err = conn.WriteToUDP(response, addr)
		if err!=nil {
			fmt.Fprintln(os.Stderr, "Cannot send res [ERR]:\n%s\n", err)
		}
	}
}
