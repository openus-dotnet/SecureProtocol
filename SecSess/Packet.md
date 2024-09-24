# SecSess Architecture

e.g. AES & HMAC Key Exchange from RSA

- Assume that the RSA publik key on the server is already guaranteed by other means.

1. Client -> Server: ⓐ: (RSA(S_PUBLIC_KEY, AES_KEY + HMAC_KEY))
2. Server:	          RSA(S_PRIVATE_KEY, ⓐ) -> AES_KEY + HMAC_KEY
3. Server -> Client: AES(AES_KEY, HMAC(HMAC_KEY, AES_KEY + HMAC_KEY))
4. Client:           Check HMAC

e.g. RSA-AES(CBC) Mode SecSess Packet

ⓑ: (IV + AES(AES_KEY, NONCE + MSG_LENGTH + MSG)) + HMAC(HMAC_KEY, ⓑ)

- AES_KEY, HMAC_KEY use the exchange in the initial key exchange during the SecSess.
- IV is randomly generated for each communication
- NONCE uses the last read NONCE, increasing by 1 to 10 in each Write, and when reading, if the NONCE did not increase based on its NONCE, it is judged as an incorrect packet.
- Data integrity and Authentication through HMAC.
- Data confidentiality through AES(CBC).