package decryption

import (
	"encoding/base64"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"testing"
)

const (
	keyURI = "gcp-kms://projects/testproject/locations/testlocation/keyRings/testkeyring/cryptoKeys/testkey"
	// Relative path
	credFile                = "testdata/credential.json"
	testEncryptedPrivateKey = "AcGnH1kAAACTCiQAVzM30n0rVQ0jfU2T7ircbHPQGFtsNcFZOqVwlHucIb4G/oESawBuaF97LIsxUDa8h6aDmfJF4qWHSIDwdQKlxStOcPWm5v0OQpNY2EmdUXnMiHvRRzwcU3+scXrPOsyuHfMveQCAq9J+505qwe46fNGtop4d3Nw0+tS55V1HBnBzY94lz9v6I88V8A7PU0GKr70+noJBXxLVt9GiF8xWCDdr919ffOYGrE1k+nThMBdMuOn1RWNtJAwlr4KH9DdAYEBcCW3f3XrL7dg7KrgmAiu09/zSe+27VIoWFV/somAjlYgTmuVJcOPU15eEXDNFjGb1OkszaHrlyvZ6FtYY2gcTjZ47mK9VTHLsYPMUbm2MYSWrTgZVvJ1RYyDHlGVfv4wawitBVCHya8FVgxNj29SpQFqH4AUqtCquTeWlXsSe4W48A1mOhbw65FuYMptZeDYCoIswkQtimNmRN5S0sy/SgWa9fJ0AK1nPw2bW4+9NxXCp6ZuAN/Gbs4iVEhIGfeYuHN7RuU1zVzIJXBx0Lmf+9dT8ywdJ8IwS3JQlvfNPBh8lXfZV0HUp05e771dKnpfr29cLuJLlYT0kxASR3mf8sIRQJo886xAJIURWuysWAzLFaFQUAKcjUy6ynXhn7IaRyTmR7+Xc2AD/ngI7vjqBg2wm5+2rLeOiZar+0WM31Jc3TAhm+Mfe1mJFUToQrHWKXt8w5IXHJXERu9WwEWS+vJ/70BMGKUqXS+jdZ/2Ap9UcDMp9WivCwIW3riBLuGJyDvIfiFKKNxdInx0GkF82XeRLlg5q2ZxP1MLXnGFXyyyvRf6St2HM3X4VwjK7yQmRO9aXznEyn0VtXHWa3XNw7kv9H5qODfFv1milM4E903ioXvSPF8wfK2k5ltkb0JUOTBqXyXsJX4MBzK/4uHDP/rePFRwlGfY/Bv1iELRW4dZ0iWbEobUVDU0fnj2k+/W9u0WneVCpJ6rUDpoX3SpfzLLa8S7ebTnMgMemfCz1Imu7VexGzOkblVjCuS3+TkosMKk+enrF9YsWoYQSq4tJ106kuYVjatzUTY/97qkBPqmAbJ2LHhNHM7BzEOpLuN+QihKsNWoPKA=="
)

func TestGetRegisteredGcpClientSuccess(t *testing.T) {
	if err := GetRegisteredGcpClient("testproject", "testlocation", "testkeyring", "testkey", credFile); err != nil {
		t.Fatalf("Unexpected error occurred creating GCP: %v", err)
	}
}

func TestGetRegisteredGcpClientBadCreds(t *testing.T) {
	if err := GetRegisteredGcpClient("testproject", "testlocation", "testkeyring", "testkey", "bad/file/path"); err == nil {
		t.Fatalf("Expected error, got success.")
	}
}

func TestCreateGcpAeadSuccess(t *testing.T) {
	if err := GetRegisteredGcpClient("testproject", "testlocation", "testkeyring", "testkey", credFile); err != nil {
		t.Fatalf("Error occurred creating GCP: %v", err)
	}
	_, err := CreateGcpAead(keyURI)
	if err != nil {
		t.Fatalf("Error occurred creating AEAD from GCP: %v", err)
	}
}

func TestCreateHybridDecryptEncryptedKeyset(t *testing.T) {
	kh, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("Unexpected error occurred creating handle: %v", err)
	}
	privkh := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(kh, privkh); err != nil {
		t.Fatalf("unexpected error writing keyset: %v", err)
	}
	aeadkh, err := keyset.NewHandle(aead.AES128CTRHMACSHA256KeyTemplate())
	if err != nil {
		t.Fatalf("unexpected error creating keyset handle: %v", err)
	}
	a, err := aead.New(aeadkh)
	if err != nil {
		t.Fatalf("unexpected error creating AEAD: %v", err)
	}
	ct, err := a.Encrypt([]byte(privkh.Keyset.String()), nil)
	if err != nil {
		t.Fatalf("unexpected error encrypting handle: %v", err)
	}
	_, err = CreateHybridDecryptEncryptedKeyset(base64.StdEncoding.EncodeToString(ct), &a)
	if err != nil {
		t.Fatalf("unexpected error creating hybrid decrypt: %v", err)
	}
}

func TestDecryptBase64StrSuccess(t *testing.T) {
	kh, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		t.Fatalf("Unexpected error occurred creating handle: %v", err)
	}
	khPub, err := kh.Public()
	if err != nil {
		t.Fatalf("Unexpected error occurred getting public key: %v", err)
	}
	he, err := hybrid.NewHybridEncrypt(khPub)
	if err != nil {
		t.Fatalf("Unexpected error occurred creating hybrid encrypt: %v", err)
	}
	const str = "String to be encrypted"
	encByte, err := he.Encrypt([]byte(str), nil)
	if err != nil {
		t.Fatalf("Unexpected error occurred encrypting: %v", err)
	}
	hd, err := hybrid.NewHybridDecrypt(kh)
	if err != nil {
		t.Fatalf("Unexpected error occurred creating hybrid decrypt: %v", err)
	}
	decByte, err := DecryptBase64Str(base64.StdEncoding.EncodeToString(encByte), &hd)
	if err != nil {
		t.Fatalf("Unexpected error occurred decrypting: %v", err)
	}
	if string(decByte) != str {
		t.Fatalf("Decrypted content doesn't equal original")
	}
}
