## ssl.log
- **TLS Version**: `version` = `"SSLv3"`
- **Cipher Suite**: `cipher` = `"TLS_RSA_WITH_AES_256_CBC_SHA"`
- **Server Name (SNI)**: `server_name` = *(omitted/null in SSLv3 sample)*
- **Certificate Fingerprints**: `cert_chain_fps` = `["de8f38faec1be5667274e3df0b6ef86a308e8f77e48fcdee3bb16d80b11939c3"]`

## x509.log
- **Certificate Fingerprint**: `fingerprint` = `"de8f38faec1be5667274e3df0b6ef86a308e8f77e48fcdee3bb16d80b11939c3"`
- **Subject**: `certificate.subject` = `"emailAddress=www@snakeoil.dom,CN=www.snakeoil.dom,OU=Webserver Team,O=Snake Oil\\, Ltd,L=Snake Town,ST=Snake Desert,C=XY"`
- **Issuer**: `certificate.issuer` = `"emailAddress=ca@snakeoil.dom,CN=Snake Oil CA,OU=Certificate Authority,O=Snake Oil\\, Ltd,L=Snake Town,ST=Snake Desert,C=XY"`
- **Expiration Date**: `certificate.not_valid_after` = `1204562865.0`
- **Key Length**: `certificate.key_length` = `1024`
- **Signature Algorithm**: `certificate.sig_alg` = `"md5WithRSAEncryption"`
- **Certificate Version**: `certificate.version` = `3`
