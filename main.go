package main

import (
	"sso/idp"
	"sso/sp"
	"time"
)

const (
	IDP_URL      = "http://localhost:8080"
	SP_URL       = "http://localhost:8081"
	SP_ENTITY_ID = "kb"
)

func main() {
	idpServer, err := idp.NewIdp(IDP_URL)
	if err != nil {
		panic(err)
	}
	idpServer.CreateDefaultUser()
	spServer, err := sp.NewSP(SP_URL, SP_ENTITY_ID)
	if err != nil {
		panic(err)
	}
	idpServer.AddSP(SP_ENTITY_ID, *spServer.GetSPMetadata())
	go idpServer.Start()
	time.Sleep(time.Second)
	spServer.SetIdpMetadata(idpServer.GetMetadata())
	spServer.Start()
}
