// MIT License

// Copyright (c) 2020 Apoorv Mote https://apoorv.blog

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/hybrid"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/integration/awskms"
	"github.com/google/tink/go/keyset"
)

var (
	region         = flag.String("region", "us-east-1", "AWS Region for created key")
	account        = flag.String("account", "", "AWS account ID")
	key            = flag.String("key", "", "AWS KMS Key ID")
	outFilePrivate = flag.String("outfilePrivate", "", "Output file for private key.")
	outFilePublic  = flag.String("outfilePublic", "", "Output file for public key.")
)

func main() {
	flag.Parse()
	keyURI := fmt.Sprintf(
		"aws-kms://arn:aws:kms:%s:%s:key/%s",
		*region,
		*account,
		*key,
	)

	// Gets a client to access the keys at the URI above.
	awsclient, err := awskms.NewClient(keyURI)
	if err != nil {
		log.Fatal(err)
	}

	// Register AWS client.
	registry.RegisterKMSClient(awsclient)

	// Create an AEAD that uses the AWS key.
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

	// Encrypt the Tink key with the AWS AEAD
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
	log.Println("Public keyset writen to file: ", *outFilePublic)
}
