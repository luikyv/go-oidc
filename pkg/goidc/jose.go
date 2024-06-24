package goidc

import (
	"encoding/json"
	"errors"

	"github.com/go-jose/go-jose/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

type JsonWebKey struct {
	innerJwk jose.JSONWebKey
}

func (jwk JsonWebKey) GetId() string {
	return jwk.innerJwk.KeyID
}

func (jwk JsonWebKey) GetAlgorithm() string {
	return jwk.innerJwk.Algorithm
}

func (jwk JsonWebKey) GetUsage() string {
	return jwk.innerJwk.Use
}

func (jwk JsonWebKey) GetKey() any {
	return jwk.innerJwk.Key
}

func (jwk JsonWebKey) GetCertificateThumbprintSha256() []byte {
	return jwk.innerJwk.CertificateThumbprintSHA256
}

func (jwk JsonWebKey) GetCertificateThumbprintSha1() []byte {
	return jwk.innerJwk.CertificateThumbprintSHA1
}

func (jwk JsonWebKey) IsPublic() bool {
	return jwk.innerJwk.IsPublic()
}

func (jwk JsonWebKey) IsValid() bool {
	return jwk.innerJwk.Valid()
}

func (jwk JsonWebKey) GetPublic() JsonWebKey {
	return NewJsonWebKey(jwk.innerJwk.Public())
}

func (jwk JsonWebKey) MarshalJSON() ([]byte, error) {
	return jwk.innerJwk.MarshalJSON()
}

func (jwk *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	return jwk.innerJwk.UnmarshalJSON(data)
}

func (jwk JsonWebKey) MarshalBSONValue() (bsontype.Type, []byte, error) {
	data, err := json.Marshal(jwk)
	if err != nil {
		return 0, nil, err
	}
	return bson.MarshalValue(string(data))
}

func (jwk *JsonWebKey) UnmarshalBSONValue(t bsontype.Type, data []byte) error {
	if t != bson.TypeString {
		return errors.New("type is not string")
	}

	// Ignore the first 4 bytes because they specify the length of the
	// string field, which has already been trimmed for us. Ignore the
	// last byte because it is always the terminating character '\x00'.
	data = data[4 : len(data)-1]
	return json.Unmarshal(data, jwk)
}

func NewJsonWebKey(jwk jose.JSONWebKey) JsonWebKey {
	return JsonWebKey{
		innerJwk: jwk,
	}
}

type JsonWebKeySet struct {
	Keys []JsonWebKey `json:"keys"`
}

// Copied from jose.JSONWebKeySet.
func (jwks *JsonWebKeySet) Key(keyId string) []JsonWebKey {

	var keys []JsonWebKey
	for _, key := range jwks.Keys {
		if key.GetId() == keyId {
			keys = append(keys, key)
		}
	}

	return keys
}
