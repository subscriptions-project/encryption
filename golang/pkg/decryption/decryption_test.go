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
	credFile = "testdata/credential.json"
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
