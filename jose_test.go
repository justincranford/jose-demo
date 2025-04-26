package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func TestJWKOperations(t *testing.T) {
	expectedDecryptedBytes := []byte("Hello World!")

	testCases := []struct {
		useJwkDecodedFromJson bool
		numJwks               int
		alg                   jwa.KeyEncryptionAlgorithm
		enc                   jwa.ContentEncryptionAlgorithm
	}{
		{useJwkDecodedFromJson: false, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A256GCM()}, // direct mode => only 1 JWK
		{useJwkDecodedFromJson: false, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A192GCM()}, // direct mode => only 1 JWK
		{useJwkDecodedFromJson: false, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A128GCM()}, // direct mode => only 1 JWK

		{useJwkDecodedFromJson: false, numJwks: 1, alg: jwa.A256GCMKW(), enc: jwa.A256GCM()},
		{useJwkDecodedFromJson: false, numJwks: 2, alg: jwa.A256GCMKW(), enc: jwa.A192GCM()},
		{useJwkDecodedFromJson: false, numJwks: 3, alg: jwa.A256GCMKW(), enc: jwa.A128GCM()},

		{useJwkDecodedFromJson: false, numJwks: 1, alg: jwa.A192GCMKW(), enc: jwa.A256GCM()},
		{useJwkDecodedFromJson: false, numJwks: 2, alg: jwa.A192GCMKW(), enc: jwa.A192GCM()},
		{useJwkDecodedFromJson: false, numJwks: 3, alg: jwa.A192GCMKW(), enc: jwa.A128GCM()},

		{useJwkDecodedFromJson: false, numJwks: 1, alg: jwa.A128GCMKW(), enc: jwa.A256GCM()},
		{useJwkDecodedFromJson: false, numJwks: 2, alg: jwa.A128GCMKW(), enc: jwa.A192GCM()},
		{useJwkDecodedFromJson: false, numJwks: 3, alg: jwa.A128GCMKW(), enc: jwa.A128GCM()},

		{useJwkDecodedFromJson: true, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A256GCM()}, // direct mode => only 1 JWK
		{useJwkDecodedFromJson: true, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A192GCM()}, // direct mode => only 1 JWK
		{useJwkDecodedFromJson: true, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A128GCM()}, // direct mode => only 1 JWK

		{useJwkDecodedFromJson: true, numJwks: 1, alg: jwa.A256GCMKW(), enc: jwa.A256GCM()},
		{useJwkDecodedFromJson: true, numJwks: 2, alg: jwa.A256GCMKW(), enc: jwa.A192GCM()},
		{useJwkDecodedFromJson: true, numJwks: 3, alg: jwa.A256GCMKW(), enc: jwa.A128GCM()},

		{useJwkDecodedFromJson: true, numJwks: 1, alg: jwa.A192GCMKW(), enc: jwa.A256GCM()},
		{useJwkDecodedFromJson: true, numJwks: 2, alg: jwa.A192GCMKW(), enc: jwa.A192GCM()},
		{useJwkDecodedFromJson: true, numJwks: 3, alg: jwa.A192GCMKW(), enc: jwa.A128GCM()},

		{useJwkDecodedFromJson: true, numJwks: 1, alg: jwa.A128GCMKW(), enc: jwa.A256GCM()},
		{useJwkDecodedFromJson: true, numJwks: 2, alg: jwa.A128GCMKW(), enc: jwa.A192GCM()},
		{useJwkDecodedFromJson: true, numJwks: 3, alg: jwa.A128GCMKW(), enc: jwa.A128GCM()},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("useJwkDecodedFromJson=[%v],numJwks=[%d],alg=[%s],enc=[%s]", tc.useJwkDecodedFromJson, tc.numJwks, tc.alg, tc.enc), func(t *testing.T) {
			jwks := []jwk.Key{}
			for range tc.numJwks {
				generatedJwk := generateAesJwk(t, tc.alg, tc.enc)

				encodedJwk, err := json.Marshal(generatedJwk) // encode for persistence (e.g. PEM file, Database BLOB); should be wrapped by a KMS, HSM, TPM, TEE, etc before storage
				require.NoError(t, err)
				t.Logf("JWK: %s\n", encodedJwk)

				if tc.useJwkDecodedFromJson {
					decodedJwk, err := jwk.ParseKey(encodedJwk) // decode from persistence
					require.NoError(t, err)                     // this should work, but I get an unexpected error => json: cannot unmarshal object into Go value of type jwk.Key
					require.Equal(t, decodedJwk, generatedJwk)

					jwks = append(jwks, decodedJwk)
				} else {
					jwks = append(jwks, generatedJwk)
				}
			}

			// Encrypt with 1 or more JWKs (aka recipients)
			jweEncryptOptions := make([]jwe.EncryptOption, 0, len(jwks))
			if len(jwks) > 1 {
				jweEncryptOptions = append(jweEncryptOptions, jwe.WithJSON()) // if more than one JWK, must use JSON instead of compact
			}
			for _, jwk := range jwks {
				jweEncryptOptions = append(jweEncryptOptions, jwe.WithKey(tc.alg, jwk))
			}

			jweMessageBytes, err := jwe.Encrypt(expectedDecryptedBytes, jweEncryptOptions...)
			require.NoError(t, err)
			t.Logf("JWE: %s\n", string(jweMessageBytes))

			// Decrypt with 1 or more JWKs (aka recipients)
			jweDecryptOptions := make([]jwe.DecryptOption, 0, len(jwks))
			for _, jwk := range jwks {
				jweDecryptOptions = append(jweDecryptOptions, jwe.WithKey(tc.alg, jwk))
			}

			actualDecryptedBytes, err := jwe.Decrypt(jweMessageBytes, jweDecryptOptions...)
			require.NoError(t, err)

			require.NoError(t, err)
			require.Equal(t, expectedDecryptedBytes, actualDecryptedBytes)
		})
	}
}

func generateAesJwk(t *testing.T, kekAlg jwa.KeyEncryptionAlgorithm, cekAlg jwa.ContentEncryptionAlgorithm) jwk.Key {
	var keySize int
	switch kekAlg {
	case jwa.DIRECT():
		switch cekAlg {
		case jwa.A256GCM():
			keySize = 32
		case jwa.A192GCM():
			keySize = 24
		case jwa.A128GCM():
			keySize = 16
		default:
			t.Fatalf("unsupported enc: %s", cekAlg)
		}
	case jwa.A256GCMKW():
		keySize = 32
	case jwa.A192GCMKW():
		keySize = 24
	case jwa.A128GCMKW():
		keySize = 16
	default:
		t.Fatalf("unsupported alg: %s", kekAlg)
	}

	aesKeyBytes := make([]byte, keySize)
	aesKeyBytesCount, err := rand.Read(aesKeyBytes)
	require.NoError(t, err)
	require.Equal(t, keySize, aesKeyBytesCount)

	jwkKey, err := jwk.Import(aesKeyBytes)
	require.NoError(t, err)

	err = jwkKey.Set(jwk.AlgorithmKey, kekAlg)
	require.NoError(t, err)
	err = jwkKey.Set("enc", cekAlg) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
	require.NoError(t, err)

	err = jwkKey.Set(jwk.KeyIDKey, uuid.Must(uuid.NewV7()).String())
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyUsageKey, "enc")
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyOpsKey, jwk.KeyOperationList{"encrypt", "decrypt"})
	require.NoError(t, err)
	err = jwkKey.Set(jwk.KeyTypeKey, jwa.OctetSeq())
	require.NoError(t, err)

	return jwkKey
}
