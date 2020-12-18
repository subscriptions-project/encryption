# Script to Create Tink Hybrid Keys using Envelope Encryption with AWS

This script creates a [Tink Hybrid](https://github.com/google/tink/blob/master/docs/PRIMITIVES.md#hybrid-encryption) ([ECIES](https://en.wikipedia.org/wiki/Integrated_Encryption_Scheme) with AEAD) key and outputs the public key in plaintext to an output file, as well as the encrypted private key to another output file. The private key is encrypted using a key hosted on Amazon Web Services (AWS). This method is commonly referred to as [Envelope Encryption](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#enveloping).

This script was inspired by the Medium post [Google Cloud KMS & Tink](https://medium.com/google-cloud/google-cloud-kms-tink-1e106156bb4e). Please read that post for more information.

## Installation:

```shell
# Go get the script
go get -u github.com/subscriptions-project/encryption/golang/cmd/aws_key_gen
```

## Example Usage:

For aws credentials make sure you have `awscli` installed and you have configured it by running `aws configure` and make sure you have created credentials with default profile NOT NAMED profile.

```shell
go run github.com/subscriptions-project/encryption/golang/cmd/aws_key_gen \
    --region=$AWS_KMS_REGION \
    --account=$AWS_ACCOUNT_ID \
    --key=$AWS_KMS_KEY_ID \
    --outfilePrivate=$PRIVATE_KEY_FILE \
    --outfilePublic=$PUBLIC_KEY_FILE
```
