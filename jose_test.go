package main

import (
	cryptoRand "crypto/rand"
	"encoding/json"
	"fmt"
	mathRand "math/rand"
	"testing"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

var (
	// Symmetric jwa.KeyEncryptionAlgorithm
	DIRECT    = jwa.DIRECT()
	A256GCMKW = jwa.A256GCMKW()
	A192GCMKW = jwa.A192GCMKW()
	A128GCMKW = jwa.A128GCMKW()
	A256KW    = jwa.A256KW()
	A192KW    = jwa.A192KW()
	A128KW    = jwa.A128KW()

	// Symmetric jwa.ContentEncryptionAlgorithm
	A256GCM       = jwa.A256GCM()
	A192GCM       = jwa.A192GCM()
	A128GCM       = jwa.A128GCM()
	A256CBC_HS512 = jwa.A256CBC_HS512()
	A192CBC_HS384 = jwa.A192CBC_HS384()
	A128CBC_HS256 = jwa.A128CBC_HS256()
)

// Questions:
// 1) Why is 'enc' not included in JWE protected headers?
// 2) Why no variables cleared for "enc" in jwk and jwa packages? There are jwk.AlgorithmKey='alg' and jwa.KeyEncryptionAlgorithm='alg', but nothing for 'enc.
// 3) When I serialize a JWK with 'enc' jwa.ContentEncryptionAlgorithm header, why does ParseKey return JWK with 'enc' string header? I have to convert to jwa.ContentEncryptionAlgorithm.
// 4) Why does encrypt fail for enc=A192CBC_HS384 and enc=A128CBC_HS256? Only enc=A256CBC_HS512 seems to be working for me.

// TestAesJWKsEncryptDecryptCombinations Show how serialize+deserialize returns JWK with different 'enc' header type; in-memory 'enc' is jwa.ContentEncryptionAlgorithm, deserialized 'enc' is string
// useWorkaroundForParsedJwk is used in
func TestAesJWKsEncryptDecryptCombinations(t *testing.T) {
	testCases := []struct {
		doSerDes             bool                           // false: use in-memory generated JWK for encrypt+decrypt, true: serialize+deserialize JWK before using for encrypt+decrypt
		contentEncryptionAlg jwa.ContentEncryptionAlgorithm // 1 content encrypt algorithm
		keyEncryptionAlgs    []jwa.KeyEncryptionAlgorithm   // N keyEncryptionAlgs => N recipient JWKs
	}{
		//////////////////////////////////////////////////////////////////////////////////////
		// doSerDes=false tests => Use in-memory generated JWK as-is for encryption+decryption
		//////////////////////////////////////////////////////////////////////////////////////

		{doSerDes: false, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // JWE alg=dir => only 1 JWK is allowed
		{doSerDes: false, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // JWE alg=dir => only 1 JWK is allowed
		{doSerDes: false, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // JWE alg=dir => only 1 JWK is allowed
		{doSerDes: false, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}},
		// {doSerDes: false, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // Fails
		// {doSerDes: false, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // Fails

		{doSerDes: false, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW}},
		{doSerDes: false, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},
		{doSerDes: false, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}},
		{doSerDes: false, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW}},
		// {doSerDes: false, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}}, // Fails
		// {doSerDes: false, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}}, // Fails

		{doSerDes: false, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW}},
		{doSerDes: false, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},
		{doSerDes: false, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}},
		{doSerDes: false, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW}},
		// {doSerDes: false, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}}, // Fails
		// {doSerDes: false, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}}, // Fails

		{doSerDes: false, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A128GCMKW}},
		{doSerDes: false, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},
		{doSerDes: false, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}},
		{doSerDes: false, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A128GCMKW}},
		// {doSerDes: false, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},                                       // Fails
		// {doSerDes: false, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}}, // Fails

		/////////////////////////////////////////////////////////////////////////////////////////////////////////
		// doSerDes=true tests => Serialize+deserialize the JWK and use that parsed key for encryption+decryption
		/////////////////////////////////////////////////////////////////////////////////////////////////////////

		// direct => only 1 keyEncryptionAlgs allowed => only 1 JWK allowed
		{doSerDes: true, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // JWE alg=dir => only 1 JWK is allowed
		{doSerDes: true, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // JWE alg=dir => only 1 JWK is allowed
		{doSerDes: true, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // JWE alg=dir => only 1 JWK is allowed
		{doSerDes: true, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}},
		// {doSerDes: true, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // Fails
		// {doSerDes: true, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{DIRECT}}, // Fails

		{doSerDes: true, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW}},
		{doSerDes: true, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},
		{doSerDes: true, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}},
		{doSerDes: true, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW}},
		// {doSerDes: true, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},                                       // Fails
		// {doSerDes: true, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}}, // Fails

		{doSerDes: true, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW}},
		{doSerDes: true, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},
		{doSerDes: true, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}},
		{doSerDes: true, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW}},
		// {doSerDes: true, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},                                       // Fails
		// {doSerDes: true, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}}, // Fails

		{doSerDes: true, contentEncryptionAlg: A256GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A128GCMKW}},
		{doSerDes: true, contentEncryptionAlg: A192GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},
		{doSerDes: true, contentEncryptionAlg: A128GCM, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}},
		{doSerDes: true, contentEncryptionAlg: A256CBC_HS512, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A128GCMKW}},
		// {doSerDes: true, contentEncryptionAlg: A192CBC_HS384, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A192GCMKW, A192KW}},                                       // Fails
		// {doSerDes: true, contentEncryptionAlg: A128CBC_HS256, keyEncryptionAlgs: []jwa.KeyEncryptionAlgorithm{A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW}}, // Fails
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("doSerDes=[%v],enc=[%s],algs=%v", tc.doSerDes, tc.contentEncryptionAlg, tc.keyEncryptionAlgs), func(t *testing.T) {
			clearBytes := fmt.Appendf(nil, "Hello World %d!", 1000+mathRand.Intn(9000)) // EX: "Hello World 9999!"
			t.Logf("Clear Bytes: %s [0x%x]\n", string(clearBytes), clearBytes)

			aesJwks := generateAesJwks(t, tc.doSerDes, tc.contentEncryptionAlg, tc.keyEncryptionAlgs) // doSerDes=true tells function to serialized+deserialized each JWK

			encryptedBytes := jweEncrypt(t, tc.doSerDes, aesJwks, clearBytes) // doSerDes=true tells function to use 'enc' convert workaround from string to jwa.ContentEncryptionAlgorithm
			decryptedBytes := jweDecrypt(t, aesJwks, encryptedBytes)          // doSerDes flag not needed for decryption

			require.Equal(t, clearBytes, decryptedBytes)

			t.Logf("Decrypted Bytes: %s [0x%x]\n", string(clearBytes), clearBytes)
			t.Logf("Decrypt succeeded!!!\n\n\n")
		})
	}
}

func jweEncrypt(t *testing.T, doSerDes bool, aesJwks []jwk.Key, clearBytes []byte) []byte {
	jweEncryptOptions := make([]jwe.EncryptOption, 0, len(aesJwks))
	if len(aesJwks) > 1 {
		jweEncryptOptions = append(jweEncryptOptions, jwe.WithJSON()) // if more than one JWK, JSON format must be used instead of compact format
	}
	uniqueCekAlgs := make(map[jwa.ContentEncryptionAlgorithm]struct{})
	for _, aesJwk := range aesJwks {
		// get KeyEncryptionAlgorithm from current AES JWK (e.g. dir, A256GCMKW, A192GCMKW, A128GCMKW, A256KW, A192KW, A128KW)
		var kekAlg jwa.KeyEncryptionAlgorithm
		err := aesJwk.Get(jwk.AlgorithmKey, &kekAlg)
		require.NoError(t, err)

		// get ContentEncryptionAlgorithm from current AES JWK (e.g. A256GCM, A192GCM, A128GCM, A256CBC-HS512, A192CBC-HS384, A128CBC-HS256)
		var cekAlg jwa.ContentEncryptionAlgorithm // If in-memory JWK, 'enc' type is jwa.ContentEncryptionAlgorithm. If deserialized JWK, 'enc' type is string.
		if doSerDes {
			var cekAlgString string // Workaround: Deserialized JWK 'enc' header is type string
			err := aesJwk.Get("enc", &cekAlgString)
			require.NoError(t, err)
			cekAlg = jwa.NewContentEncryptionAlgorithm(cekAlgString) // convert to jwa.ContentEncryptionAlgorithm, so it is same type as in-memory JWK
		} else {
			err := aesJwk.Get("enc", &cekAlg) // in-memory JWK 'enc' header is type jwa.ContentEncryptionAlgorithm, no need to convert
			require.NoError(t, err)
		}

		if len(uniqueCekAlgs) == 0 {
			jweEncryptOptions = append(jweEncryptOptions, jwe.WithContentEncryption(cekAlg)) // Content is encrypted once-and-only-once, so only add WithContentEncryption once
		}
		uniqueCekAlgs[cekAlg] = struct{}{}      // record unique cekAlgString so far
		require.Equal(t, 1, len(uniqueCekAlgs)) // Content is encrypted once-and-only-once, so all unique JWK 'enc' headers must be the same

		jweEncryptOptions = append(jweEncryptOptions, jwe.WithKey(kekAlg, aesJwk))
	}

	jweMessageBytes, err := jwe.Encrypt(clearBytes, jweEncryptOptions...)
	require.NoError(t, err)
	t.Logf("JWE Message of the Encrypted Bytes: %s\n", string(jweMessageBytes))
	return jweMessageBytes
}

func jweDecrypt(t *testing.T, aesJwks []jwk.Key, jweMessageBytes []byte) []byte {
	jweDecryptOptions := make([]jwe.DecryptOption, 0, len(aesJwks))
	for _, aesJwk := range aesJwks {
		var keyEncryptionAlgorithm jwa.KeyEncryptionAlgorithm
		err := aesJwk.Get(jwk.AlgorithmKey, &keyEncryptionAlgorithm) // Questions: 1) Why no variable for "enc"? 2) Why unprotected header instead of protected header?
		require.NoError(t, err)
		jweDecryptOptions = append(jweDecryptOptions, jwe.WithKey(keyEncryptionAlgorithm, aesJwk))
	}

	actualDecryptedBytes, err := jwe.Decrypt(jweMessageBytes, jweDecryptOptions...)
	require.NoError(t, err)
	return actualDecryptedBytes
}

func generateAesJwks(t *testing.T, useWorkaroundForParsedJwk bool, jwkContentEncryptionAlg jwa.ContentEncryptionAlgorithm, jwkKeyEncryptionAlgs []jwa.KeyEncryptionAlgorithm) []jwk.Key {
	var aesJwks []jwk.Key
	for _, jwkKeyEncryptionAlg := range jwkKeyEncryptionAlgs {
		generatedJwk := generateAesJwk(t, jwkKeyEncryptionAlg, jwkContentEncryptionAlg)

		encodedJwk, err := json.Marshal(generatedJwk) // serialized (and encrypted) for persistence; encryption would be done with HSM, KMS, TPM, TEE, YubiKey, or etc
		require.NoError(t, err)
		t.Logf("Generated JWK: %s\n", string(encodedJwk))

		if useWorkaroundForParsedJwk {
			decodedJwk, err := jwk.ParseKey(encodedJwk) // (decrypted and) deserialized from persistence
			require.NoError(t, err)
			// IMPORTANT: Uncomment to see decrypt succeeds, but decodedJwk==generatedJwkJWK assertion fails due to 'enc' header type mismatch; enc value is the same, but type is different
			// assert.Equal(t, decodedJwk, generatedJwk, "Decoded JWK didn't match in-memory JWK, check if 'enc' header type is different")
			aesJwks = append(aesJwks, decodedJwk) // 'enc' is 1) unprotected header, and 2) type string
		} else {
			aesJwks = append(aesJwks, generatedJwk) // 'enc' is 1) unprotected header, and 2) type jwa.ContentEncryptionAlgorithm
		}
	}
	return aesJwks
}

func generateAesJwk(t *testing.T, kekAlg jwa.KeyEncryptionAlgorithm, cekAlg jwa.ContentEncryptionAlgorithm) jwk.Key {
	var keySize int
	switch kekAlg {
	case jwa.DIRECT():
		switch cekAlg {
		case A256GCM, A256CBC_HS512:
			keySize = 32
		case A192GCM, A192CBC_HS384:
			keySize = 24
		case A128GCM, A128CBC_HS256:
			keySize = 16
		default:
			t.Fatalf("unsupported enc: %s", cekAlg)
		}
	case A256GCMKW, A256KW:
		keySize = 32
	case A192GCMKW, A192KW:
		keySize = 24
	case A128GCMKW, A128KW:
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
