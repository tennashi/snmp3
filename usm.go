package snmp3

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
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
	if len(f) < 1 {
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

func (u *UserSecurityModel) ProcessIncomingMsg(p Packet) ([]byte, error) {
	key := GenerateUSMUserKey(p.SecurityParameters)
	secUser, err := u.lcd.GetUser(key)
	if err != nil {
		if err != ErrCachedSecurityDataNotFound {
			return nil, err
		}
		c := USMUserEntry{
			EngineID: p.SecurityParameters.AuthoritativeEngineID,
			Name:     p.SecurityParameters.UserName,
		}
		if err := u.lcd.AddUser(key, c); err != nil {
			return nil, err
		}
	}
	if !p.SecurityParameters.AuthoritativeEngineID.Equal(secUser.EngineID) {
		return nil, errors.New("unknown engine ID")
	}
	if p.SecurityParameters.UserName != secUser.Name {
		return nil, errors.New("unknown user")
	}

	curUser := securityContext{
		user: secUser,
	}
	if p.GlobalData.Flags&MessageFlagAuth > 0 {
		if _, err := curUser.authenticateIncomingMsg(p.SecurityParameters.AuthenticationParameters, p.wholeBytes); err != nil {
			return nil, err
		}
	}
	if p.GlobalData.Flags&MessageFlagPriv > 0 {
		plainData, err := curUser.decryptData(p.SecurityParameters.PrivacyParameters, p.Data)
		if err != nil {
			return nil, err
		}
		return plainData, nil
	}
	return p.Data, nil
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
	user        *USMUserEntry
	engineBoots int32
	engineTime  int32
}

func (c *securityContext) authenticateIncomingMsg(authParameters, wholeMsg []byte) ([]byte, error) {
	key := c.user.AuthKey

	mac := hmac.New(sha1.New, key)
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
	binary.Write(&buf, binary.BigEndian, c.engineBoots)
	binary.Write(&buf, binary.BigEndian, c.engineTime)
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
