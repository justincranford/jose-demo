package main

import (
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	mathRand "math/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
	joseJwa "github.com/lestrrat-go/jwx/v3/jwa"
	joseJwe "github.com/lestrrat-go/jwx/v3/jwe"
	joseJwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWKOperations(t *testing.T) {
	testCases := []struct {
		useParsedJwk                  bool
		jwkKeyEncryptionAlgorithmss   []joseJwa.KeyEncryptionAlgorithm
		jwkContentEncryptionAlgorithm joseJwa.ContentEncryptionAlgorithm
	}{
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.DIRECT()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.DIRECT()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.DIRECT()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()}, // direct mode => only 1 JWK

		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()},
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A256GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()},
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A192GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()},

		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A192GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()},
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A192GCMKW(), joseJwa.A192GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()},
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A192GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()},

		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()},
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A128GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()},
		{useParsedJwk: false, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A192GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()},

		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.DIRECT()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.DIRECT()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()}, // direct mode => only 1 JWK
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.DIRECT()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()}, // direct mode => only 1 JWK

		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()},
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A256GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()},
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A192GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()},

		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A192GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()},
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A192GCMKW(), joseJwa.A192GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()},
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A192GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()},

		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A256GCM()},
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A128GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A192GCM()},
		{useParsedJwk: true, jwkKeyEncryptionAlgorithmss: []joseJwa.KeyEncryptionAlgorithm{joseJwa.A256GCMKW(), joseJwa.A192GCMKW(), joseJwa.A128GCMKW()}, jwkContentEncryptionAlgorithm: joseJwa.A128GCM()},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("useParsedJwk=[%v],algs=%v,enc=[%s]", tc.useParsedJwk, tc.jwkKeyEncryptionAlgorithmss, tc.jwkContentEncryptionAlgorithm), func(t *testing.T) {
			expectedDecryptedBytes := fmt.Appendf(nil, "Hello World %d!", 1000+mathRand.Intn(9000))
			t.Logf("Clear Bytes: %s [0x%x]\n", strings.TrimSpace(string(expectedDecryptedBytes)), expectedDecryptedBytes)

			jwks := generateAesJwks(t, tc.useParsedJwk, tc.jwkKeyEncryptionAlgorithmss, tc.jwkContentEncryptionAlgorithm)

			// Encrypt
			jweEncryptOptions := make([]joseJwe.EncryptOption, 0, len(jwks))
			if len(jwks) > 1 {
				jweEncryptOptions = append(jweEncryptOptions, joseJwe.WithJSON()) // if more than one JWK, JSON format must be used instead of compact format
			}
			uniqueCekAlgStrings := make(map[string]struct{})
			uniqueCekAlgs := make(map[joseJwa.ContentEncryptionAlgorithm]struct{})
			for _, jwk := range jwks {
				var kekAlg joseJwa.KeyEncryptionAlgorithm
				err := jwk.Get(joseJwk.AlgorithmKey, &kekAlg) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
				require.NoError(t, err)
				if tc.useParsedJwk {
					// Workaround: If using JWK decoded from JSON, get 'enc' unprotected header as type string
					var cekAlgString string
					err := jwk.Get("enc", &cekAlgString)
					require.NoError(t, err)
					uniqueCekAlgStrings[cekAlgString] = struct{}{} // record unique cekAlgString so far
					require.Equal(t, 1, len(uniqueCekAlgStrings))  // Validate 1 unique cekAlgString: JWKs can have different 'alg' headers, but all JWKs must have same 'enc' header
				} else {
					// Workaround: If using JWK generated in memory, get 'enc' unprotected header as type jwa.ContentEncryptionAlgorithm
					var cekAlg joseJwa.ContentEncryptionAlgorithm
					err := jwk.Get("enc", &cekAlg) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
					require.NoError(t, err)
					uniqueCekAlgs[cekAlg] = struct{}{}      // record unique cekAlgString so far
					require.Equal(t, 1, len(uniqueCekAlgs)) // Validate 1 unique cekAlgString: JWKs can have different 'alg' headers, but all JWKs must have same 'enc' header
				}
				jweEncryptOptions = append(jweEncryptOptions, joseJwe.WithKey(kekAlg, jwk))
			}

			jweMessageBytes, err := joseJwe.Encrypt(expectedDecryptedBytes, jweEncryptOptions...)
			require.NoError(t, err)
			t.Logf("JWE Message of the Encrypted Bytes: %s\n", strings.TrimSpace(string(jweMessageBytes)))

			// Decrypt
			jweDecryptOptions := make([]joseJwe.DecryptOption, 0, len(jwks))
			for _, jwk := range jwks {
				var keyEncryptionAlgorithm joseJwa.KeyEncryptionAlgorithm
				err := jwk.Get(joseJwk.AlgorithmKey, &keyEncryptionAlgorithm) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
				require.NoError(t, err)
				jweDecryptOptions = append(jweDecryptOptions, joseJwe.WithKey(keyEncryptionAlgorithm, jwk))
			}

			actualDecryptedBytes, err := joseJwe.Decrypt(jweMessageBytes, jweDecryptOptions...)
			require.NoError(t, err)
			require.Equal(t, expectedDecryptedBytes, actualDecryptedBytes)

			t.Logf("Decrypted Bytes: %s [0x%x]\n", strings.TrimSpace(string(expectedDecryptedBytes)), expectedDecryptedBytes)
			t.Logf("Decrypt succeeded")
		})
	}
}

func generateAesJwks(t *testing.T, useParsedJwk bool, jwkKeyEncryptionAlgs []joseJwa.KeyEncryptionAlgorithm, jwkContentEncryptionAlg joseJwa.ContentEncryptionAlgorithm) []joseJwk.Key {
	var jwks []joseJwk.Key
	for _, jwkKeyEncryptionAlg := range jwkKeyEncryptionAlgs {
		generatedJwk := generateAesJwk(t, jwkKeyEncryptionAlg, jwkContentEncryptionAlg)

		encodedJwk, err := json.Marshal(generatedJwk) // encode for persistence (e.g. Database BLOB, DER or PEM file); n.b. this value should be encrypted at rest (e.g. HSM, TPM, TEE, KMS, etc)
		require.NoError(t, err)
		t.Logf("Generated JWK: %s\n", strings.TrimSpace(string(encodedJwk)))

		if useParsedJwk {
			decodedJwk, err := joseJwk.ParseKey(encodedJwk) // decode from persistence
			require.NoError(t, err)
			assert.Equal(t, decodedJwk, generatedJwk, "Decoded JWK didn't match original clear JWK, due to ParseKey handling 'enc' header as string instead of expected jwa.ContentEncryptionAlgorithm")

			jwks = append(jwks, decodedJwk)
		} else {
			jwks = append(jwks, generatedJwk)
		}
	}
	return jwks
}

func generateAesJwk(t *testing.T, kekAlg joseJwa.KeyEncryptionAlgorithm, cekAlg joseJwa.ContentEncryptionAlgorithm) joseJwk.Key {
	var keySize int
	switch kekAlg {
	case joseJwa.DIRECT():
		switch cekAlg {
		case joseJwa.A256GCM():
			keySize = 32
		case joseJwa.A192GCM():
			keySize = 24
		case joseJwa.A128GCM():
			keySize = 16
		default:
			t.Fatalf("unsupported enc: %s", cekAlg)
		}
	case joseJwa.A256GCMKW():
		keySize = 32
	case joseJwa.A192GCMKW():
		keySize = 24
	case joseJwa.A128GCMKW():
		keySize = 16
	default:
		t.Fatalf("unsupported alg: %s", kekAlg)
	}

	aesKeyBytes := make([]byte, keySize)
	aesKeyBytesCount, err := cryptoRand.Read(aesKeyBytes)
	require.NoError(t, err)
	require.Equal(t, keySize, aesKeyBytesCount)

	jwkKey, err := joseJwk.Import(aesKeyBytes)
	require.NoError(t, err)

	err = jwkKey.Set(joseJwk.AlgorithmKey, kekAlg)
	require.NoError(t, err)
	err = jwkKey.Set("enc", cekAlg) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
	require.NoError(t, err)

	err = jwkKey.Set(joseJwk.KeyIDKey, uuid.Must(uuid.NewV7()).String())
	require.NoError(t, err)
	err = jwkKey.Set(joseJwk.KeyUsageKey, "enc")
	require.NoError(t, err)
	err = jwkKey.Set(joseJwk.KeyOpsKey, joseJwk.KeyOperationList{"encrypt", "decrypt"})
	require.NoError(t, err)
	err = jwkKey.Set(joseJwk.KeyTypeKey, joseJwa.OctetSeq())
	require.NoError(t, err)

	return jwkKey
}
