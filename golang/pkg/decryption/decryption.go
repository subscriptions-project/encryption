/* Copyright 2019 The Subscribe with Google Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS-IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package decryption

import (
	"encoding/base64"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// Creates a Tink GCP Client and registers it.
func GetRegisteredGcpClient(project, location, keyring, key, credentialsFile string) error {
	keyURI := fmt.Sprintf(
		"gcp-kms://projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		project,
		location,
		keyring,
		key)
	gcpclient, err := gcpkms.NewGCPClient(keyURI)
	if err != nil {
		return err
	}
	if credentialsFile != "" {
		_, err = gcpclient.LoadCredentials(credentialsFile)
	} else {
		_, err = gcpclient.LoadDefaultCredentials()
	}
	if err != nil {
		return err
	}
	registry.RegisterKMSClient(gcpclient)
	return nil
}

// Creates an AEAD using GCP keys found at the input keyURI.
func CreateGcpAead(keyURI string) (tink.AEAD, error) {
	dek := aead.AES128CTRHMACSHA256KeyTemplate()
	khgcs, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	if err != nil {
		return nil, err
	}
	return aead.New(khgcs)
}

// Decrypts the encryptedKeyset with the input AEAD.
// Makes and returns a HybridDecrypt from the decrypted keyset.
func CreateHybridDecryptEncryptedKeyset(encryptedKeyset string, tinkAead *tink.AEAD) (tink.HybridDecrypt, error) {
	encBytes, err := base64.StdEncoding.DecodeString(encryptedKeyset)
	if err != nil {
		return nil, err
	}
	decBytes, err := (*tinkAead).Decrypt(encBytes, nil)
	if err != nil {
		return nil, err
	}
	ksproto := &tinkpb.Keyset{}
	proto.UnmarshalText(string(decBytes), ksproto)
	kh := insecurecleartextkeyset.KeysetHandle(ksproto)
	return hybrid.NewHybridDecrypt(kh)
}

// Decrypts the base64 encoded string with the HybridDecrypt object.
func DecryptBase64Str(encStr string, hd *tink.HybridDecrypt) ([]byte, error) {
	encBytes, err := base64.StdEncoding.DecodeString(encStr)
	if err != nil {
		return nil, err
	}
	return (*hd).Decrypt(encBytes, nil)
}
