package snmp3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"math"
)

type SecurityModel int32

const (
	SecurityModelUSM SecurityModel = 3
)

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

type USMUserEntry struct {
	AuthKey  []byte
	PrivKey  []byte
	EngineID EngineID
	Name     string
}

type USMTimeEntry struct {
	EngineID       EngineID
	Boot           int32
	Time           int32
	LatestReceived int32
}

type UserSecurityModel struct {
	lcd LocalConfigurationDatastore
}

func NewUserSecurityModel(lcd LocalConfigurationDatastore) *UserSecurityModel {
	return &UserSecurityModel{lcd: lcd}
}

type SecurityLevel int

const (
	SecurityLevelNoAuthNoPriv SecurityLevel = iota
	SecurityLevelAuthNoPriv
	SecurityLevelAuthPriv
)

func NewSecurityLevel(f MessageFlag) SecurityLevel {
	switch {
	case f&MessageFlagAuth|MessageFlagPriv > 0:
		return SecurityLevelAuthPriv
	case f&MessageFlagAuth > 0:
		return SecurityLevelAuthNoPriv
	default:
		return SecurityLevelNoAuthNoPriv
	}
}

func (u *UserSecurityModel) ProcessIncomingMsg(p Packet) ([]byte, error) {
	if len(p.SecurityParameters.AuthoritativeEngineID) == 0 {
		return nil, errors.New("unknown engine ID")
	}

	t, err := u.lcd.GetTime(p.SecurityParameters.AuthoritativeEngineID)
	if err != nil {
		return nil, err
	}

	secName := p.SecurityParameters.UserName
	secLevel := NewSecurityLevel(p.GlobalData.Flags)

	if secName == "" || secLevel == SecurityLevelNoAuthNoPriv {
		return p.rawData, nil
	}

	secUser, err := u.lcd.GetUser(p.SecurityParameters.AuthoritativeEngineID, p.SecurityParameters.UserName)
	if err != nil {
		return nil, err
	}

	curUser := securityContext{
		user: secUser,
		time: t,
	}
	if secLevel >= SecurityLevelAuthNoPriv {
		if _, err := curUser.authenticateIncomingMsg(p.SecurityParameters.AuthenticationParameters, p.wholeBytes); err != nil {
			return nil, err
		}
		if err := curUser.checkTime(p.SecurityParameters.AuthoritativeEngineBoots, p.SecurityParameters.AuthoritativeEngineTime); err != nil {
			return nil, err
		}
		// TODO: save time entry
	}

	plainData, err := curUser.decryptData(p.SecurityParameters.PrivacyParameters, p.rawData)
	if err != nil {
		return nil, err
	}
	// TODO: compute max size
	return plainData, nil
}

const mega = 1 << 20

func PasswordToKey(password string, engineID []byte) []byte {
	h := sha1.New()
	p := []byte(password)
	plen := len(p)
	for i := mega / plen; i > 0; i-- {
		h.Write(p)
	}
	remain := mega % plen
	if remain > 0 {
		h.Write(p[:remain])
	}
	ku := h.Sum(nil)

	h.Reset()
	h.Write(ku)
	h.Write(engineID)
	h.Write(ku)
	return h.Sum(nil)
}

type securityContext struct {
	user *USMUserEntry
	time *USMTimeEntry
}

func (c *securityContext) authenticateIncomingMsg(authParameters, wholeMsg []byte) ([]byte, error) {
	mac := hmac.New(sha1.New, c.user.AuthKey)
	data := bytes.Replace(wholeMsg, authParameters, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 1)
	mac.Write(data)
	dd := mac.Sum(nil)[:12]
	if !hmac.Equal(authParameters, dd) {
		return nil, errors.New("unauthenticated")
	}
	return wholeMsg, nil
}

func (c securityContext) generateInitializationVector(privParams []byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, c.time.Boot)
	binary.Write(&buf, binary.BigEndian, c.time.Time)
	iv := append(buf.Bytes(), privParams...)
	return iv
}

func (c *securityContext) decryptData(privParams, encryptedData []byte) ([]byte, error) {
	key := c.user.PrivKey[:16]

	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data := make([]byte, len(encryptedData))

	iv := c.generateInitializationVector(privParams)

	m := cipher.NewCFBDecrypter(a, iv)
	m.XORKeyStream(data, encryptedData)
	return data, nil
}

func (c securityContext) checkTime(b int32, t int32) error {
	if c.time == nil {
		return errors.New("unknown engine ID")
	}

	if c.time.Boot > b || c.time.Boot == b && c.time.LatestReceived-150 > t || c.time.Boot == math.MaxInt32 {
		return errors.New("not in time window")
	}
	return nil
}
