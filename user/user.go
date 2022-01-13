package user

import (
	"bytes"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/duo-labs/webauthn/protocol"
	"github.com/duo-labs/webauthn/webauthn"
)

type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

func NewUser(name string) *User {
	user := &User{}
	user.ID = randomUint64()
	user.Name = name
	user.DisplayName = name

	return user
}

// Return user credential by ID
func (u User) CredentialById(id []byte) (*webauthn.Credential, error) {
	var result *webauthn.Credential
	for _, cred := range u.Credentials {
		if bytes.Compare(cred.ID, id) == 0 {
			result = &cred
			break
		}
	}

	if result == nil {
		return nil, fmt.Errorf("Failed to find credential ID %s for User %s", id, u.Name)
	}

	return result, nil
}

func (u User) Marshal() (string, error) {
	marshaledUser, err := json.Marshal(u)
	if err != nil {
		return "", err
	}

	encodedUser := b64.StdEncoding.EncodeToString([]byte(marshaledUser))

	return encodedUser, nil
}

func UnmarshalUser(user string) (*User, error) {
	decodedUser, err := b64.StdEncoding.DecodeString(user)
	if err != nil {
		return NewUser("error"), err
	}

	unmarshaledUser := &User{}
	if err = json.Unmarshal(decodedUser, &unmarshaledUser); err != nil {
		return NewUser("error"), err
	}

	return unmarshaledUser, nil
}

// Set user registration options, such as excluding registered credentials
func (u User) UserRegistrationOptions(credCreateOptions *protocol.PublicKeyCredentialCreationOptions) {
	credExcludeList := []protocol.CredentialDescriptor{}
	for _, cred := range u.Credentials {
		descriptor := protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		}
		credExcludeList = append(credExcludeList, descriptor)
	}

	credCreateOptions.CredentialExcludeList = credExcludeList
}

func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.ID))
	return buf
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

func (u User) WebAuthnName() string {
	return u.Name
}

func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}
