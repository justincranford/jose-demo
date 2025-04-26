package main

import (
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	mathRand "math/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKOperations(t *testing.T) {
	testCases := []struct {
		useParsedJwk bool
		numJwks      int
		alg          jwa.KeyEncryptionAlgorithm
		enc          jwa.ContentEncryptionAlgorithm
	}{
		{useParsedJwk: false, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A256GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: false, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A192GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: false, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A128GCM()}, // direct mode => only 1 JWK

		{useParsedJwk: false, numJwks: 1, alg: jwa.A256GCMKW(), enc: jwa.A256GCM()},
		{useParsedJwk: false, numJwks: 2, alg: jwa.A256GCMKW(), enc: jwa.A192GCM()},
		{useParsedJwk: false, numJwks: 3, alg: jwa.A256GCMKW(), enc: jwa.A128GCM()},

		{useParsedJwk: false, numJwks: 1, alg: jwa.A192GCMKW(), enc: jwa.A256GCM()},
		{useParsedJwk: false, numJwks: 2, alg: jwa.A192GCMKW(), enc: jwa.A192GCM()},
		{useParsedJwk: false, numJwks: 3, alg: jwa.A192GCMKW(), enc: jwa.A128GCM()},

		{useParsedJwk: false, numJwks: 1, alg: jwa.A128GCMKW(), enc: jwa.A256GCM()},
		{useParsedJwk: false, numJwks: 2, alg: jwa.A128GCMKW(), enc: jwa.A192GCM()},
		{useParsedJwk: false, numJwks: 3, alg: jwa.A128GCMKW(), enc: jwa.A128GCM()},

		{useParsedJwk: true, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A256GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: true, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A192GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: true, numJwks: 1, alg: jwa.DIRECT(), enc: jwa.A128GCM()}, // direct mode => only 1 JWK

		{useParsedJwk: true, numJwks: 1, alg: jwa.A256GCMKW(), enc: jwa.A256GCM()},
		{useParsedJwk: true, numJwks: 2, alg: jwa.A256GCMKW(), enc: jwa.A192GCM()},
		{useParsedJwk: true, numJwks: 3, alg: jwa.A256GCMKW(), enc: jwa.A128GCM()},

		{useParsedJwk: true, numJwks: 1, alg: jwa.A192GCMKW(), enc: jwa.A256GCM()},
		{useParsedJwk: true, numJwks: 2, alg: jwa.A192GCMKW(), enc: jwa.A192GCM()},
		{useParsedJwk: true, numJwks: 3, alg: jwa.A192GCMKW(), enc: jwa.A128GCM()},

		{useParsedJwk: true, numJwks: 1, alg: jwa.A128GCMKW(), enc: jwa.A256GCM()},
		{useParsedJwk: true, numJwks: 2, alg: jwa.A128GCMKW(), enc: jwa.A192GCM()},
		{useParsedJwk: true, numJwks: 3, alg: jwa.A128GCMKW(), enc: jwa.A128GCM()},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("useParsedJwk=[%v],numJwks=[%d],alg=[%s],enc=[%s]", tc.useParsedJwk, tc.numJwks, tc.alg, tc.enc), func(t *testing.T) {
			expectedDecryptedBytes := fmt.Appendf(nil, "Hello World %d!", 1000+mathRand.Intn(9000))
			t.Logf("Clear Bytes: %s [0x%x]\n", strings.TrimSpace(string(expectedDecryptedBytes)), expectedDecryptedBytes)

			jwks := generateAesJwks(t, tc.useParsedJwk, tc.numJwks, tc.alg, tc.enc)

			alg := tc.alg

			// Encrypt
			jweEncryptOptions := make([]jwe.EncryptOption, 0, len(jwks))
			if len(jwks) > 1 {
				jweEncryptOptions = append(jweEncryptOptions, jwe.WithJSON()) // if more than one JWK, JSON format must be used instead of compact format
			}
			uniqueCekAlgStrings := make(map[string]struct{})
			uniqueCekAlgs := make(map[jwa.ContentEncryptionAlgorithm]struct{})
			for _, jwk := range jwks {
				if tc.useParsedJwk {
					// Workaround: If using JWK decoded from JSON, get 'enc' unprotected header as type string
					var cekAlgString string
					err := jwk.Get("enc", &cekAlgString)
					require.NoError(t, err)
					uniqueCekAlgStrings[cekAlgString] = struct{}{} // record unique cekAlgString so far
					require.Equal(t, 1, len(uniqueCekAlgStrings))  // Validate 1 unique cekAlgString: JWKs can have different 'alg' headers, but all JWKs must have same 'enc' header
				} else {
					// Workaround: If using JWK generated in memory, get 'enc' unprotected header as type jwa.ContentEncryptionAlgorithm
					var cekAlg jwa.ContentEncryptionAlgorithm
					err := jwk.Get("enc", &cekAlg) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
					require.NoError(t, err)
					uniqueCekAlgs[cekAlg] = struct{}{}      // record unique cekAlgString so far
					require.Equal(t, 1, len(uniqueCekAlgs)) // Validate 1 unique cekAlgString: JWKs can have different 'alg' headers, but all JWKs must have same 'enc' header
				}
				jweEncryptOptions = append(jweEncryptOptions, jwe.WithKey(alg, jwk))
			}

			jweMessageBytes, err := jwe.Encrypt(expectedDecryptedBytes, jweEncryptOptions...)
			require.NoError(t, err)
			t.Logf("JWE Message of the Encrypted Bytes: %s\n", strings.TrimSpace(string(jweMessageBytes)))

			// Decrypt
			jweDecryptOptions := make([]jwe.DecryptOption, 0, len(jwks))
			for _, jwk := range jwks {
				jweDecryptOptions = append(jweDecryptOptions, jwe.WithKey(alg, jwk))
			}

			actualDecryptedBytes, err := jwe.Decrypt(jweMessageBytes, jweDecryptOptions...)
			require.NoError(t, err)
			require.Equal(t, expectedDecryptedBytes, actualDecryptedBytes)

			t.Logf("Decrypted Bytes: %s [0x%x]\n", strings.TrimSpace(string(expectedDecryptedBytes)), expectedDecryptedBytes)
			t.Logf("Decrypt succeeded")
		})
	}
}

func generateAesJwks(t *testing.T, useParsedJwk bool, numJwks int, alg jwa.KeyEncryptionAlgorithm, enc jwa.ContentEncryptionAlgorithm) []jwk.Key {
	var jwks []jwk.Key
	for range numJwks {
		generatedJwk := generateAesJwk(t, alg, enc)

		encodedJwk, err := json.Marshal(generatedJwk) // encode for persistence (e.g. Database BLOB, DER or PEM file); n.b. this value should be encrypted at rest (e.g. HSM, TPM, TEE, KMS, etc)
		require.NoError(t, err)
		t.Logf("Generated JWK: %s\n", strings.TrimSpace(string(encodedJwk)))

		if useParsedJwk {
			decodedJwk, err := jwk.ParseKey(encodedJwk) // decode from persistence
			require.NoError(t, err)
			assert.Equal(t, decodedJwk, generatedJwk, "Decoded JWK didn't match original clear JWK, due to ParseKey handling 'enc' header as string instead of expected jwa.ContentEncryptionAlgorithm")

			jwks = append(jwks, decodedJwk)
		} else {
			jwks = append(jwks, generatedJwk)
		}
	}
	return jwks
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
	aesKeyBytesCount, err := cryptoRand.Read(aesKeyBytes)
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
