package snmp3

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"net"
)

type PDUType int

const (
	PDUTypeGetRequest PDUType = iota
	PDUTypeGetNextRequest
	PDUTypeResponse
	PDUTypeSetRequest
	_ // obsolete
	PDUTypeGetBulkRequest
	PDUTypeInformRequest
	PDUTypeSNMPV2Trap
	PDUTypeReport
)

type ScopedPDU struct {
	ContextEngineID EngineID
	ContextName     []byte
	Data            interface{}

	typ PDUType
}

func (s *ScopedPDU) Unmarshal(d []byte) error {
	raw := struct {
		CtxEngineID []byte
		ContextName []byte
		Data        asn1.RawValue
	}{}
	if _, err := asn1.Unmarshal(d, &raw); err != nil {
		return err
	}

	engineID, err := NewEngineID(raw.CtxEngineID)
	if err != nil {
		return err
	}

	if raw.Data.Class != asn1.ClassContextSpecific {
		return errors.New("unknown PDU type")
	}

	var pdu interface {
		Unmarshal(d []byte) error
	}
	if raw.Data.Tag == int(PDUTypeGetBulkRequest) {
		pdu = &BulkPDU{}
	} else {
		pdu = &PDU{}
	}
	if err := pdu.Unmarshal(raw.Data.FullBytes); err != nil {
		return err
	}

	s.typ = PDUType(raw.Data.Tag)
	s.ContextEngineID = engineID
	s.ContextName = raw.ContextName
	s.Data = pdu
	return nil
}

type PDU struct {
	RequestID        int32
	ErrorStatus      ErrorStatus
	ErrorIndex       int32
	VariableBindings []VarBind
}

func (p *PDU) Unmarshal(b []byte) error {
	raw := struct {
		ReqID            int
		ErrStatus        int
		ErrIdx           int
		VariableBindings []asn1.RawValue
	}{}
	if _, err := asn1.UnmarshalWithParams(b, &raw, fmt.Sprintf("tag:%d", p.pduType)); err != nil {
		return err
	}

	if raw.ReqID < math.MinInt32 || raw.ReqID > math.MaxInt32 {
		return errors.New("invalid request ID")
	}
	if raw.ErrStatus < 0 || raw.ErrStatus > math.MaxInt32 {
		return errors.New("invalid error status")
	}
	if raw.ErrIdx < 0 || raw.ErrIdx > math.MaxInt32 {
		return errors.New("invalid error index")
	}

	varBinds := make([]VarBind, len(raw.VariableBindings))
	for i, rawVarBind := range raw.VariableBindings {
		if err := varBinds[i].Unmarshal(rawVarBind.FullBytes); err != nil {
			return err
		}
	}

	p.RequestID = int32(raw.ReqID)
	p.ErrorStatus = ErrorStatus(raw.ErrStatus)
	p.ErrorIndex = int32(raw.ErrIdx)
	p.VariableBindings = varBinds
	return nil
}

type BulkPDU struct {
	RequestID        int32
	NonRepeaters     int32
	MaxRepetitions   int32
	VariableBindings []VarBind

	pduType PDUType
}

func (p *BulkPDU) Unmarshal(b []byte) error {
	raw := struct {
		ReqID            int
		NonRepeaters     int
		MaxRepetitions   int
		VariableBindings []asn1.RawValue
	}{}
	if _, err := asn1.UnmarshalWithParams(b, &raw, fmt.Sprintf("tag:%d", p.pduType)); err != nil {
		return err
	}

	if raw.ReqID < math.MinInt32 || raw.ReqID > math.MaxInt32 {
		return errors.New("invalid request ID")
	}
	if raw.NonRepeaters < 0 || raw.NonRepeaters > math.MaxInt32 {
		return errors.New("invalid non repeaters")
	}
	if raw.MaxRepetitions < 0 || raw.MaxRepetitions > math.MaxInt32 {
		return errors.New("invalid max repetitions")
	}

	varBinds := make([]VarBind, len(raw.VariableBindings))
	for i, rawVarBind := range raw.VariableBindings {
		if err := varBinds[i].Unmarshal(rawVarBind.FullBytes); err != nil {
			return err
		}
	}

	p.RequestID = int32(raw.ReqID)
	p.NonRepeaters = int32(raw.NonRepeaters)
	p.MaxRepetitions = int32(raw.MaxRepetitions)
	return nil
}

type VarBind struct {
	Name  asn1.ObjectIdentifier
	Value interface{}
}

func (v *VarBind) Unmarshal(b []byte) error {
	raw := struct {
		Name  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{}
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return err
	}

	var value interface{}
	switch raw.Value.Class {
	case asn1.ClassContextSpecific:
		switch raw.Value.Tag {
		case ErrorValueNoSuchObject.Tag():
			value = ErrorValueNoSuchObject
		case ErrorValueNoSuchInstance.Tag():
			value = ErrorValueNoSuchInstance
		case ErrorValueEndOfMIBView.Tag():
			value = ErrorValueEndOfMIBView
		}
	case asn1.ClassApplication:
		switch raw.Value.Tag {
		case 0:
			if len(raw.Value.Bytes) != 4 {
				return errors.New("invalid value")
			}
			value = net.IP(raw.Value.Bytes)
		case 1, 2, 3:
			var rv int
			if _, err := asn1.UnmarshalWithParams(raw.Value.FullBytes, &rv, fmt.Sprintf("application,tag:%d", raw.Value.Tag)); err != nil {
				return err
			}
			if rv < 0 || rv > math.MaxUint32 {
				return errors.New("invalid value")
			}
			value = uint32(rv)
		case 4:
			var rv []byte
			if _, err := asn1.UnmarshalWithParams(raw.Value.FullBytes, &rv, fmt.Sprintf("application,tag:%d", raw.Value.Tag)); err != nil {
				return err
			}
			value = rv
		case 6:
			var rv uint64
			if _, err := asn1.UnmarshalWithParams(raw.Value.FullBytes, &rv, fmt.Sprintf("application,tag:%d", raw.Value.Tag)); err != nil {
				return err
			}
			value = rv
		}
	case asn1.ClassUniversal:
		switch raw.Value.Tag {
		case asn1.TagInteger:
			var rv int
			if _, err := asn1.Unmarshal(raw.Value.FullBytes, &rv); err != nil {
				return err
			}
			value = rv
		case asn1.TagOctetString:
			var rv []byte
			if _, err := asn1.Unmarshal(raw.Value.FullBytes, &rv); err != nil {
				return err
			}
			value = rv
		case asn1.TagOID:
			var rv asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(raw.Value.FullBytes, &rv); err != nil {
				return err
			}
			value = rv
		default:
			value = ErrorValueUnSpecified
		}
	}

	v.Name = raw.Name
	v.Value = value
	return nil
}

type ErrorValue int

const (
	ErrorValueUnknown ErrorValue = iota
	ErrorValueUnSpecified
	ErrorValueNoSuchObject
	ErrorValueNoSuchInstance
	ErrorValueEndOfMIBView
)

func (e ErrorValue) Tag() int {
	switch e {
	case ErrorValueNoSuchObject:
		return 0
	case ErrorValueNoSuchInstance:
		return 1
	case ErrorValueEndOfMIBView:
		return 2
	}
	return 0
}
