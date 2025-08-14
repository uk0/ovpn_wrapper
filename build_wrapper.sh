#!/bin/bash

CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -o ovpn-wrapper_amd64 wrapper.go config_blob.go
go build -o ovpn-wrapper_armv8 wrapper.go config_blob.go