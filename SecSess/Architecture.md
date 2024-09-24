# SecSess Architecture

- Assume algorithm set is follow that.
  - Symmetric key algorithm is using AES.
  - Asymmetric key algorithm is using RSA.
  - Hash and HMAC algorithm is using SHA256.

## 1st. AES & HMAC Key Exchange from SecSess-RSA

- Assume that the RSA public key on the server is already guaranteed by other means.

|#|Location|Work|
|-|--------|----|
|01|Client side|**Generate** `AES_KEY` and `HMAC_KEY` → **Get** `🔑`|
|02|Client side|`RSA(S_PUBLIC_KEY, 🔑)` → **Encrypt to** `🔐`|
|03|Client ↣ Server|**Send** `🔐`|
|04|Server side|`RSA(S_PRIVATE_KEY, 🔐)` → **Decrypt to** `🔑`|
|05|Server side|`🔑` → **Get** `AES_KEY` and `HMAC_KEY`|
|06|Server side|`HMAC(HMAC_KEY, 🔑)` → **Hash to** `📜`|
|07|Server side|`SecSess-TCP(AES_KEY, 📜)` → **Encrypt to** `🔏`|
|08|Server ↣ Client|**Send** `🔏`|
|09|Client side|`SecSess-TCP(AES_KEY, 🔏)` → **Decrypt to** `❓`|
|10|Client side|`HMAC(HMAC_KEY, 🔑)` → **Hash to** `📜`|
|11|Client side|**Compare** `❓` is `📜`|

> - `🔑`: `AES_KEY + HMAC_KEY`
>   - ≓ Keys for SecSess-TCP
> - `🔐`: `RSA(S_PUBLIC_KEY, 🔑)`
>   - ≓ Encrypted keys for SecSess-TCP, and this can decrypt only Server
> - `📜`: `HMAC(HMAC_KEY, 🔑)`
>   - ≓ Authentication hash message in SecSess-TCP
> - `🔏`: `SecSess-TCP(AES_KEY, 📜)`
>   - ≓ Encrypted authentication hash message in SecSess-TCP

## 2nd. SecSess-TCP(TCP-AES-CBC) Packet Sent Structure

- Define `IV + AES(AES_KEY, NONCE + MSG_LENGTH + MSG)` is `α` so, the `α` mean encrypted packet.
- Write AES packet is only follow the structure that `α + HMAC(HMAC_KEY, α)`

> - Data *confidentiality* through **AES(CBC)**.
> - Data *integrity* and *Authentication* through **HMAC**.

> - AES_KEY, HMAC_KEY generate and exchange in the before time(in RSA) during the SecSess.
> - IV is randomly generated for each communication.
> - Used the last read NONCE, Write increased NONCE by 1 to 10 in each write, and when Reading, if the NONCE did not increase based on last read NONCE, it is judged as an incorrect packet.

## 3rd. Usage Example

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
