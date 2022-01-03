package user

import (
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/binary"
	"encoding/json"

	"github.com/duo-labs/webauthn/webauthn"
)

// User represents the user model
type User struct {
	ID          uint64
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// NewUser creates and returns a new User
func NewUser(name string) *User {
	user := &User{}
	user.ID = randomUint64()
	user.Name = name
	user.DisplayName = name
	// user.credentials = []webauthn.Credential{}

	return user
}

func MarshalUser(user User) (string, error) {
	marshaledUser, err := json.Marshal(user)
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

// WebAuthnID returns the user's ID
func (u User) WebAuthnID() []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	binary.PutUvarint(buf, uint64(u.ID))
	return buf
}

// WebAuthnIcon is not (yet) implemented
func (u User) WebAuthnIcon() string {
	return ""
}

// WebAuthnName returns the user's username
func (u User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name
func (u User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// AddCredential associates the credential to the user
func (u *User) AddCredential(cred webauthn.Credential) {
	u.Credentials = append(u.Credentials, cred)
}

// WebAuthnCredentials returns credentials owned by the user
func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

func randomUint64() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}
