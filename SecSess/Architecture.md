# SecSess Architecture

## 1st. AES & HMAC Key Exchange from SecSess-RSA

- Assume that the RSA public key on the server is already guaranteed by other means.

|#|Location|Work|
|-|--------|----|
|1|Client side|**Generate** `AES_KEY` and `HMAC_KEY`|
|2|Client ↣ Server|`RSA(S_PUBLIC_KEY, AES_KEY + HMAC_KEY)`|
|3|Server side|`RSA(S_PRIVATE_KEY, ⓐ)` → `AES_KEY + HMAC_KEY`|
|4|Server ↣ Client|`SecSess-TCP(AES_KEY, HMAC(HMAC_KEY, ⓑ))`|
|5|Client side|`SecSess-TCP(AES_KEY, ⓒ)` → `ⓓ`|
|6|Client side|**Compare** `ⓓ` and `HMAC(HMAC_KEY, ⓑ)`|

> - `ⓐ`: `RSA(S_PUBLIC_KEY, AES_KEY + HMAC_KEY)`
>   - ≓ Keys for SecSess-TCP is only can read Server
> - `ⓑ`: `AES_KEY + HMAC_KEY`
>   - ≓ Keys for SecSess-TCP
> - `ⓒ`: `SecSess-TCP(AES_KEY, HMAC(HMAC_KEY, ⓑ))`
>   - ≓ Encrypted authentication hash message in SecSess-TCP
> - `ⓓ`: `SecSess-TCP(AES_KEY, ⓒ)`
>   - ≓ Decrypted authentication hash message in SecSess-TCP

## 2nd. SecSess-TCP(TCP-AES-CBC) Packet Sent Structure

- Def. `(IV + AES(AES_KEY, NONCE + MSG_LENGTH + MSG))` is `α` so, the `α` is same encrypted packet.
- Write AES packet is only structure that `α + HMAC(HMAC_KEY, α)`

> - Data *confidentiality* through **AES(CBC)**.
> - Data *integrity* and *Authentication* through **HMAC**.

> - AES_KEY, HMAC_KEY use the exchange in the initial key exchange during the SecSess.
> - IV is randomly generated for each communication.
> - NONCE uses the last read NONCE, increasing by 1 to 10 in each Write, and when Reading, if the NONCE did not increase based on its NONCE, it is judged as an incorrect packet.

## 3rd. Usage

### Key Generator

```cs
/// You must have RSA key pair before communication.
/// Don't worry. We provide RSA key pair generator!

using SecSess.Key;

KeyPair pair = KeyPair.GenerateRSA();

pair.PublicKey.Save("key.pub");
pair.PrivateKey.Save("key.priv");

```

### SecSess Server

```cs
/// This is the Server side.

using SecSess.Key;
using SecSess.Secure.Algorithm;
using SecSess.Tcp;

/// Load Private key
PrivateKey privkey = PrivateKey.Load(Asymmetric.RSA, "key.priv");

/// Algorithm set to use
Set set = new Set()
{
    Asymmetric = Asymmetric.RSA,
    Symmetric = Symmetric.AES,
    Hash = Hash.SHA256,
};

Server server = Server.Create(IPEndPoint.Parse($"127.0.0.1:12345"), privkey, set);
server.Start();

Server.Client accept = server.AcceptClient();

for (int i = 0; i < 100; i++)
{
    byte[] buffer = accept.Read();
    accept.Write(buffer);

    accept.FlushStream();
}

server.Stop();
```

### SecSess Client

```cs
/// This is the Client side.

using SecSess.Key;
using SecSess.Secure.Algorithm;
using SecSess.Tcp;

/// Load Public key
PublicKey pubkey = PublicKey.Load(Asymmetric.RSA, "key.pub");

/// Algorithm set to use
Set set = new Set()
{
    Asymmetric = Asymmetric.RSA,
    Symmetric = Symmetric.AES,
    Hash = Hash.SHA256,
};

Client client = Client.Create(pubkey, set);
client.Connect(IPEndPoint.Parse($"127.0.0.1:12345"));

byte[] buffer = new byte[1024];
new Random().NextBytes(buffer);

byte[] check = (byte[])buffer.Clone();

for (int i = 0; i < 100; i++)
{
    client.Write(buffer);
    buffer = client.Read();

    client.FlushStream();
}

for (int i = 0; i < buffer.Length; i++)
{
    if (buffer[i] != check[i])
        throw new Exception("buffer is corrupted");
}

client.Close();
```

- This example is like repeated 100 times Ping-Pong, through SecSess-RSA & TCP.
- And last, check that message is corrupted.
