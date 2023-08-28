package main

import (
	"log"
	"sync"
	"os"
	"github.com/megakuul/kerberos-sim/service/dataloader"
	"github.com/megakuul/kerberos-sim/service/listener"
)

func main() {
	db, err := dataloader.LoadDatabase()
	if err!=nil {
		log.Fatal(err)
	}

	exit := &listener.Exit{nil,0}
	
	var wg sync.WaitGroup
	errch := make(chan error)

	wg.Add(1)
	go listener.StartSVCListener(&db, &wg, errch, exit)

	go func() {
		for err := range errch {
			if err!=nil {
				log.Fatal(err)
			}
		}
	}()

	wg.Wait()

	if exit.Err!=nil{
		log.Fatal(exit.Err)
	}
	os.Exit(exit.Code)
}


