package main

import (
	"context"
	"net"

	"github.com/tennashi/snmp3"
)

func main() {
	e := snmp3.NewEngine(lcd{})
	ln, err := net.ListenPacket("udp", ":16200")
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	e.Serve(ctx, ln)
}

type lcd struct{}

func (_ lcd) AddUser([]byte, snmp3.USMUserEntry) error {
	return nil
}

func (_ lcd) GetUser([]byte) (*snmp3.USMUserEntry, error) {
	return &snmp3.USMUserEntry{
		Name:     "hoge",
		EngineID: snmp3.EngineID([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}),
		AuthKey:  []byte("hogehoge"),
		PrivKey:  []byte("fugafuga")}, nil
}

func (_ lcd) DeleteUser([]byte) error {
	return nil
}
