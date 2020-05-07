# Script to Create Tink Hybrid Keys using Envelope Encryption with GCP

This script creates a [Tink Hybrid](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#hybrid-encryption) ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) with AEAD) key and outputs the public key in plaintext to an output file, as well as the encrypted private key to another output file. The private key is encrypted using a key hosted on
Google Cloud (GCP). This method is commonly referred to as [Envelope Encryption](https://cloud.google.com/kms/docs/envelope-encryption).

This script was inspired by the Medium post [Google Cloud KMS & Tink](https://medium.com/google-cloud/google-cloud-kms-tink-1e106156bb4e). Please read that post for more information about setting up GCP keys.

## Installation:

```shell
# Go get the script
go get -u github.com/subscriptions-project/encryption/golang/cmd/gcp_key_gen
```

## Example Usage:

```shell
go run github.com/subscriptions-project/encryption/golang/cmd/gcp_key_gen \
    --project=$GCP_PROJECT_ID \
    --location=$GCP_PROJECT_REGION \
    --keyring=$GCP_KEYRING_NAME \
    --key=$GCP_KEY_NAME \
    --outfilePrivate=$PRIVATE_KEY_FILE \
    --outfilePublic=$PUBLIC_KEY_FILE
```
