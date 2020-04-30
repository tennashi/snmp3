package snmp3

import (
	"fmt"
)

type MessageProcessingModel struct {
	usm *UserSecurityModel
}

func NewMessageProcessingModel(usm *UserSecurityModel) *MessageProcessingModel {
	return &MessageProcessingModel{usm: usm}
}

func (m *MessageProcessingModel) PrepareDataElements(data []byte) (*Packet, error) {
	p := Packet{}
	if err := p.Unmarshal(data); err != nil {
		return nil, err
	}
	if p.Version != 3 {
		return nil, fmt.Errorf("this SNMP version is not implemented")
	}
	if p.GlobalData.SecurityModel != 3 {
		return nil, fmt.Errorf("this security model is not implemented")
	}
	rawPDU, err := m.usm.ProcessIncomingMsg(p)
	if err != nil {
		return nil, err
	}
	p.Data = ScopedPDU{}
	if err := p.Data.Unmarshal(rawPDU); err != nil {
		return nil, err
	}
	return &p, nil
}
