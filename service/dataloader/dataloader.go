package dataloader

import (
	"github.com/spf13/viper"
)

type Database struct {
	SVC_Addr string `mapstructure:"svc_addr"`
	Shared_Secret string `mapstructure:"shared_secret"`
	SPN string `mapstructure:"spn"`
}

func LoadDatabase() (Database, error) {
	var database Database
	
	viper.SetConfigName("database")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.AddConfigPath("./database")
	viper.AddConfigPath("./service")
	
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

