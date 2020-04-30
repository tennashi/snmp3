package main

import (
	"context"
	"fmt"
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
	r := &receiver{}
	e.RegisterNotificationReceiver(r)
	e.Serve(ctx, ln)
}

type receiver struct{}

func (r *receiver) ProcessPDU(ctx context.Context, p *snmp3.Packet) error {
	fmt.Println(p)
	return nil
}

type lcd struct{}

func (_ lcd) AddUser(snmp3.USMUserEntry) error {
	return nil
}

func (_ lcd) GetUser(engineID snmp3.EngineID, userName string) (*snmp3.USMUserEntry, error) {
	return &snmp3.USMUserEntry{
		Name:     userName,
		EngineID: engineID,
		AuthKey:  snmp3.PasswordToKey("hogehoge", engineID),
		PrivKey:  snmp3.PasswordToKey("fugafuga", engineID),
	}, nil
}

func (_ lcd) DeleteUser(snmp3.EngineID, string) error {
	return nil
}

func (_ lcd) AddTime(snmp3.EngineID, snmp3.USMTimeEntry) error {
	return nil
}

func (_ lcd) GetTime(engineID snmp3.EngineID) (*snmp3.USMTimeEntry, error) {
	return &snmp3.USMTimeEntry{
		EngineID:       engineID,
		Boot:           0,
		Time:           0,
		LatestReceived: 0,
	}, nil
}
