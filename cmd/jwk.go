package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/go-jose/go-jose/v4"
)

func GetClientPrivateJwks(filename string) jose.JSONWebKeySet {
	absPath, _ := filepath.Abs("./" + filename)
	clientJwksFile, err := os.Open(absPath)
	if err != nil {
		panic(err.Error())
	}
	defer clientJwksFile.Close()
	clientJwksBytes, err := io.ReadAll(clientJwksFile)
	if err != nil {
		panic(err.Error())
	}
	var clientJwks jose.JSONWebKeySet
	json.Unmarshal(clientJwksBytes, &clientJwks)

	return clientJwks
}
