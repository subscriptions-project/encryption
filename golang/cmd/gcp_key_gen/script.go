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
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/integration/gcpkms"
	"github.com/google/tink/go/keyset"
	"log"
	"os"
)

var (
	project        = flag.String("project", "", "GCP Project ID")
	location       = flag.String("location", "", "GCP Keyring Location")
	keyring        = flag.String("keyring", "", "GCP Keyring ID")
	key            = flag.String("key", "", "GCP Key ID")
	outFilePrivate = flag.String("outfilePrivate", "", "Output file for private key.")
	outFilePublic  = flag.String("outfilePublic", "", "Output file for public key.")
)

func main() {
	flag.Parse()
	keyURI := fmt.Sprintf(
		"gcp-kms://projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		*project,
		*location,
		*keyring,
		*key)

	// Gets a client to access the keys at the URI above.
	gcpclient, err := gcpkms.NewGCPClient(keyURI)
	if err != nil {
		log.Fatal(err)
	}

	// Looks for credentials JSON file in GOOGLE_APPLICATION_CREDENTIALS variable.
	_, err = gcpclient.LoadDefaultCredentials()
	if err != nil {
		log.Fatal(err)
	}

	// Register GCP client.
	registry.RegisterKMSClient(gcpclient)

	// Create an AEAD that uses the GCP key.
	dek := aead.AES128CTRHMACSHA256KeyTemplate()
	khgcs, err := keyset.NewHandle(aead.KMSEnvelopeAEADKeyTemplate(keyURI, dek))
	if err != nil {
		log.Fatal(err)
	}

	a, err := aead.New(khgcs)
	if err != nil {
		log.Fatal(err)
	}

	// Create a Tink Hybrid key handle to encrypt document keys.
	kh, err := keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		log.Fatal(err)
	}
	exported := &keyset.MemReaderWriter{}
	if err := insecurecleartextkeyset.Write(kh, exported); err != nil {
		log.Fatal("unexpected error writing keyset: ", err)
	}

	// Encrypt the Tink key with the GCP AEAD
	ct, err := a.Encrypt([]byte(exported.Keyset.String()), nil)
	if err != nil {
		log.Fatal(err)
	}

	// Write the encrypted Tink private key to the output file.
	f, err := os.Create(*outFilePrivate)
	if err != nil {
		log.Fatal(err)
	}
	f.WriteString(base64.StdEncoding.EncodeToString(ct))
	log.Println("Private keyset writen to file: ", *outFilePrivate)

	// Get the public Tink Hybrid key handle.
	khPub, err := kh.Public()
	if err != nil {
		log.Fatal(err)
	}

	buf := new(bytes.Buffer)
	exportedPub := keyset.NewJSONWriter(buf)
	if err = khPub.WriteWithNoSecrets(exportedPub); err != nil {
		log.Fatal(err)
	}

	// Write the public key to the output file.
	pf, err := os.Create(*outFilePublic)
	if err != nil {
		log.Fatal(err)
	}
	pf.Write(buf.Bytes())
	log.Println("Public keyset writen to file: ", *outFilePrivate)
}