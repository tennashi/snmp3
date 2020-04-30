package snmp3

import "errors"

type LocalConfigurationDatastore interface {
	USMUserTable
	USMTimeTable
}

type USMUserTable interface {
	AddUser(e USMUserEntry) error
	GetUser(engineID EngineID, userName string) (*USMUserEntry, error)
	DeleteUser(engineID EngineID, userName string) error
}

type USMTimeTable interface {
	AddTime(EngineID, USMTimeEntry) error
	GetTime(EngineID) (*USMTimeEntry, error)
}

var GenerateUSMUserKey func(SecurityParameters) []byte = generateUSMUserKey

func generateUSMUserKey(sp SecurityParameters) []byte {
	key := make([]byte, 0, len(sp.UserName)+len(sp.AuthoritativeEngineID)+1)
	key = append(key, sp.UserName...)
	key = append(key, ':')
	key = append(key, sp.AuthoritativeEngineID...)
	return key
}

var ErrCachedSecurityDataNotFound = errors.New("cached security data is not found")
