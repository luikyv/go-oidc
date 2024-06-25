package goidc

import (
	"encoding/json"
	"errors"

	"github.com/go-jose/go-jose/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

type SignatureAlgorithm string

const (
	EdDSA SignatureAlgorithm = "EdDSA"
	HS256 SignatureAlgorithm = "HS256" // HMAC using SHA-256
	HS384 SignatureAlgorithm = "HS384" // HMAC using SHA-384
	HS512 SignatureAlgorithm = "HS512" // HMAC using SHA-512
	RS256 SignatureAlgorithm = "RS256" // RSASSA-PKCS-v1.5 using SHA-256
	RS384 SignatureAlgorithm = "RS384" // RSASSA-PKCS-v1.5 using SHA-384
	RS512 SignatureAlgorithm = "RS512" // RSASSA-PKCS-v1.5 using SHA-512
	ES256 SignatureAlgorithm = "ES256" // ECDSA using P-256 and SHA-256
	ES384 SignatureAlgorithm = "ES384" // ECDSA using P-384 and SHA-384
	ES512 SignatureAlgorithm = "ES512" // ECDSA using P-521 and SHA-512
	PS256 SignatureAlgorithm = "PS256" // RSASSA-PSS using SHA256 and MGF1-SHA256
	PS384 SignatureAlgorithm = "PS384" // RSASSA-PSS using SHA384 and MGF1-SHA384
	PS512 SignatureAlgorithm = "PS512" // RSASSA-PSS using SHA512 and MGF1-SHA512
)

type KeyEncryptionAlgorithm string

const (
	ED25519            KeyEncryptionAlgorithm = "ED25519"
	RSA1_5             KeyEncryptionAlgorithm = "RSA1_5"             // RSA-PKCS1v1.5
	RSA_OAEP           KeyEncryptionAlgorithm = "RSA-OAEP"           // RSA-OAEP-SHA1
	RSA_OAEP_256       KeyEncryptionAlgorithm = "RSA-OAEP-256"       // RSA-OAEP-SHA256
	A128KW             KeyEncryptionAlgorithm = "A128KW"             // AES key wrap (128)
	A192KW             KeyEncryptionAlgorithm = "A192KW"             // AES key wrap (192)
	A256KW             KeyEncryptionAlgorithm = "A256KW"             // AES key wrap (256)
	DIRECT             KeyEncryptionAlgorithm = "dir"                // Direct encryption
	ECDH_ES            KeyEncryptionAlgorithm = "ECDH-ES"            // ECDH-ES
	ECDH_ES_A128KW     KeyEncryptionAlgorithm = "ECDH-ES+A128KW"     // ECDH-ES + AES key wrap (128)
	ECDH_ES_A192KW     KeyEncryptionAlgorithm = "ECDH-ES+A192KW"     // ECDH-ES + AES key wrap (192)
	ECDH_ES_A256KW     KeyEncryptionAlgorithm = "ECDH-ES+A256KW"     // ECDH-ES + AES key wrap (256)
	A128GCMKW          KeyEncryptionAlgorithm = "A128GCMKW"          // AES-GCM key wrap (128)
	A192GCMKW          KeyEncryptionAlgorithm = "A192GCMKW"          // AES-GCM key wrap (192)
	A256GCMKW          KeyEncryptionAlgorithm = "A256GCMKW"          // AES-GCM key wrap (256)
	PBES2_HS256_A128KW KeyEncryptionAlgorithm = "PBES2-HS256+A128KW" // PBES2 + HMAC-SHA256 + AES key wrap (128)
	PBES2_HS384_A192KW KeyEncryptionAlgorithm = "PBES2-HS384+A192KW" // PBES2 + HMAC-SHA384 + AES key wrap (192)
	PBES2_HS512_A256KW KeyEncryptionAlgorithm = "PBES2-HS512+A256KW" // PBES2 + HMAC-SHA512 + AES key wrap (256)
)

type ContentEncryptionAlgorithm string

const (
	A128CBC_HS256 ContentEncryptionAlgorithm = "A128CBC-HS256" // AES-CBC + HMAC-SHA256 (128)
	A192CBC_HS384 ContentEncryptionAlgorithm = "A192CBC-HS384" // AES-CBC + HMAC-SHA384 (192)
	A256CBC_HS512 ContentEncryptionAlgorithm = "A256CBC-HS512" // AES-CBC + HMAC-SHA512 (256)
	A128GCM       ContentEncryptionAlgorithm = "A128GCM"       // AES-GCM (128)
	A192GCM       ContentEncryptionAlgorithm = "A192GCM"       // AES-GCM (192)
	A256GCM       ContentEncryptionAlgorithm = "A256GCM"       // AES-GCM (256)
)

type JsonWebKey struct {
	innerJwk jose.JSONWebKey
}

func (jwk JsonWebKey) GetKeyId() string {
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

func (jwks *JsonWebKeySet) Key(keyId string) []JsonWebKey {

	var keys []JsonWebKey
	for _, key := range jwks.Keys {
		if key.GetKeyId() == keyId {
			keys = append(keys, key)
		}
	}

	return keys
}
