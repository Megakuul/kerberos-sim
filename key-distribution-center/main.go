package main

import (
	"os"
	"log"
	"sync"
	"github.com/megakuul/kerberos-sim/key-distribution-center/dataloader"
	"github.com/megakuul/kerberos-sim/key-distribution-center/listener"
)

func main() {
	db, err := dataloader.LoadDatabase()
	if err!=nil {
		log.Fatal(err)
		os.Exit(1)
	}

	exit := &listener.Exit{nil,0}
	
	var wg sync.WaitGroup
	errch := make(chan error)

	wg.Add(1)
	go listener.StartKDCListener(&db, &wg, errch, exit)

	// Handle Warnings at runtime
	go func() {
		for err := range errch {
			if err!=nil {
				log.Fatal(err)
			}
		}
	}()

	wg.Wait()

	if exit.Err!=nil {
		log.Fatal(exit.Err)
	}
	os.Exit(exit.Code)
}
