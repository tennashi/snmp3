package snmp3

import (
	"encoding/asn1"
	"errors"
	"math"
	"net"
)

type Packet struct {
	RemoteAddr         net.Addr
	Version            int32
	GlobalData         Header
	SecurityParameters SecurityParameters
	Data               ScopedPDU

	wholeBytes []byte
	rawData    []byte
}

func (p *Packet) Unmarshal(d []byte) error {
	p.wholeBytes = d
	raw := struct {
		Version            int
		GlobalData         asn1.RawValue
		SecurityParameters []byte
		Data               asn1.RawValue
	}{}
	if _, err := asn1.Unmarshal(d, &raw); err != nil {
		return err
	}

	if raw.Version < 0 || raw.Version > math.MaxInt32 {
		return errors.New("invalid message version")
	}

	if err := p.GlobalData.Unmarshal(raw.GlobalData.FullBytes); err != nil {
		return err
	}

	if err := p.SecurityParameters.Unmarshal(raw.SecurityParameters); err != nil {
		return err
	}

	p.Version = int32(raw.Version)

	if raw.Data.Class == asn1.ClassUniversal && raw.Data.Tag == asn1.TagOctetString {
		p.rawData = raw.Data.Bytes
		return nil
	}
	p.rawData = raw.Data.FullBytes
	return nil
}

type MessageFlag byte

const (
	MessageFlagAuth MessageFlag = 1 << iota
	MessageFlagPriv
	MessageFlagReportable
)

func NewMessageFlag(f []byte) (MessageFlag, error) {
	if len(f) == 0 {
		return 0, errors.New("invalid message flag")
	}
	msgFlag := MessageFlag(f[0])
	if msgFlag&^MessageFlagReportable == MessageFlagPriv {
		return 0, errors.New("invalid message flag")
	}
	return msgFlag, nil
}

type Header struct {
	ID            int32
	MaxSize       int32
	Flags         MessageFlag
	SecurityModel SecurityModel
}

func (h *Header) Unmarshal(d []byte) error {
	raw := struct {
		MsgID         int
		MaxSize       int
		Flags         []byte
		SecurityModel int
	}{}
	if _, err := asn1.Unmarshal(d, &raw); err != nil {
		return err
	}

	if raw.MsgID < 0 || raw.MsgID > math.MaxInt32 {
		return errors.New("invalid message ID")
	}
	if raw.MaxSize < 484 || raw.MaxSize > math.MaxInt32 {
		return errors.New("invalid message max size")
	}
	if raw.SecurityModel < 1 || raw.SecurityModel > math.MaxInt32 {
		return errors.New("invalid security model")
	}

	msgFlags, err := NewMessageFlag(raw.Flags)
	if err != nil {
		return err
	}

	h.ID = int32(raw.MsgID)
	h.MaxSize = int32(raw.MaxSize)
	h.Flags = msgFlags
	h.SecurityModel = SecurityModel(raw.SecurityModel)
	return nil
}

type SecurityParameters struct {
	AuthoritativeEngineID    EngineID
	AuthoritativeEngineBoots int32
	AuthoritativeEngineTime  int32
	UserName                 string
	AuthenticationParameters []byte
	PrivacyParameters        []byte
}

func (s *SecurityParameters) Unmarshal(data []byte) error {
	raw := struct {
		EngineID    []byte
		EngineBoots int
		EngineTime  int
		UserName    []byte
		AuthParam   []byte
		PrivParam   []byte
	}{}
	if _, err := asn1.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw.EngineBoots < 0 || raw.EngineBoots > math.MaxInt32 {
		return errors.New("invalid engine boots")
	}
	if raw.EngineTime < 0 || raw.EngineTime > math.MaxInt32 {
		return errors.New("invalid engine time")
	}
	engineID, err := NewEngineID(raw.EngineID)
	if err != nil {
		return err
	}

	s.AuthoritativeEngineID = engineID
	s.AuthoritativeEngineBoots = int32(raw.EngineBoots)
	s.AuthoritativeEngineTime = int32(raw.EngineTime)
	s.UserName = string(raw.UserName)
	s.AuthenticationParameters = raw.AuthParam
	s.PrivacyParameters = raw.PrivParam
	return nil
}
