# Secure Protocol

## Information

The project **Secure Protocol**'s goal is to build a **Simple**, **Secure**, and **Fast** Transport Layer Module with C#.

## Tech Stack

|Transport Layer|Tech Type                                              |Implementation |
|---------------|-------------------------------------------------------|---------------|
|TCP            |General Unsecure                                       |**O**          |
|UDP            |General Unsecure                                       |**O**          |
|TCP            |Hybrid Crypto-system(for Generate and Exchange Keys)   |**O**          |
|TCP            |Session KeySet & Ticket based Crypto-system            |**O**          |
|UDP            |Session KeySet based Crypto-system                     |**O**          |
|TCP            |Secure Service Model                                   |**X**          |

- **O**: Completed works
- **?**: Need more check
- **X**: Have only plan

## Secure Protocol Example and Architecture

- Assume algorithm set is follow that.
  - Symmetric key algorithm is using AES.
  - Asymmetric key algorithm is using RSA.
  - Hash and HMAC algorithm is using SHA256.

### 1st. Exchange AES Key & HMAC Key from RSA/TCP

- Assume that the RSA public key on the server is already guaranteed by other means.

|# |Location        |Work                                                 |
|--|----------------|-----------------------------------------------------|
|01|Client side     |**Generate** `AES_KEY` and `HMAC_KEY` → **Get** `🔑` |
|02|Client side     |`RSA(S_PUBLIC_KEY, 🔑)` → **Encrypt to** `🔐`        |
|03|Client to Server|**Send** `🔐`                                        |
|04|Server side     |`RSA(S_PRIVATE_KEY, 🔐)` → **Decrypt to** `🔑`       |
|05|Server side     |`🔑` → **Get** `AES_KEY` and `HMAC_KEY`              |
|06|Server side     |`HMAC(HMAC_KEY, 🔑)` → **Hash to** `📜ⓢ`            |
|07|Server side     |`SP-AES(AES_KEY, 📜ⓢ)` → **Encrypt to** `🔏ⓢ`      |
|08|Server to Client|**Send** `🔏ⓢ`                                      |
|09|Client side     |`SP-AES(AES_KEY, 🔏ⓢ)` → **Decrypt to** `📜ⓢ`      |
|10|Client side     |`HMAC(HMAC_KEY, 🔑)` → **Hash to** `📜ⓒ`            |
|11|Client side     |**Compare** `📜ⓢ` and `📜ⓒ`                        |

> - `🔑`: `AES_KEY + HMAC_KEY`
>   - ≓ Session Key for SP-AES
> - `🔐`: `RSA(S_PUBLIC_KEY, 🔑)`
>   - ≓ RSA Encrypted session keys for SP-AES, and this can decrypt only Server
> - `📜`: `HMAC(HMAC_KEY, 🔑)`
>   - ≓ Hashed message for initail authentication
> - `🔏`: `SP-AES(AES_KEY, 📜)`
>   - ≓ AES Encrypted hashed message for initail authentication

### 2nd. SP-AES Packet Structure
> The **SP** is **Secure Protocol**
> SP-AES is using CBC, and over the TCP/UDP

- Define `IV + AES(AES_KEY, NONCE + MSG_LENGTH + MSG)` to `α`. 
  - So, the `α` mean encrypted message part.
- Write SP-AES packet is only follow the structure that `α + HMAC(HMAC_KEY, α)`

#### More Structure Information

- Remember, in this case...
  - AES block size is 128 bits.
  - HMAC hashed data size is 256 bits.

```
+----------+--------------------------------------------+------------------------------------+
|    IV    |            AES Encrypted Message           |                HMAC                |
| 128 bits |                  128n bits                 |              256 bits              |
|          |+---------+------------+-------------------+|+----------+-----------------------+|
|          ||  Nonce  | MSG Length |      Message      |||    IV    | AES Encrypted Message ||
|          || 32 bits |  32 bits   | m bits(Z-Padding) ||| 128 bits |       128n bits       ||
|          |+---------+------------+-------------------+|+----------+-----------------------+|
+----------+--------------------------------------------+------------------------------------+
```

#### Provide from Structure

- Data ***Confidentiality*** through **AES(CBC)**.
- Data ***Integrity*** and ***Authentication*** through **HMAC**.
- In now, has plan that provide simple ***Availability*** like support blacklist system.

> - `AES_KEY`, `HMAC_KEY` generate and exchange in the before time(in RSA) during the secure session.
> - `IV` is randomly generated for each communication.
> - Use the `NONCE` increased by 1 ~ 5 from last used, using in each write.
>   - When read, if the `NONCE` did not increase based on last read `NONCE`, it is judged as an incorrect packet.
>   - So, the write `NONCE` and the read `NONCE` are separated (v0.4~)

### 3rd. Usage Example

#### Key Generator

```cs
/// You must have RSA key pair before communication.
/// Don't worry. We provide RSA key pair generator!

using Openus.SecureProtocol.Key.Asymmetric;

KeyPair pair = KeyPair.GenerateRSA();

pair.PublicKey.Save("key.pub");
pair.PrivateKey.Save("key.priv");

```

#### Secure TCP Server

```cs
/// This is the Server side.

using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Transport.Tcp;
using System.Net;

/// Load Private key
PrivateKey privkey = PrivateKey.Load(Asymmetric.RSA, "key.priv");

/// Algorithm set to use
Set set = new Set()
{
    Asymmetric = Asymmetric.RSA,
    Symmetric = Symmetric.AES,
    Hash = Hash.SHA256,
};

TcpServer server = TcpServer.Create(IPEndPoint.Parse($"127.0.0.1:12345"), privkey, set);
server.Start();

TcpServer.Client accept = server.AcceptClient()!;

for (int i = 0; i < 100; i++)
{
    byte[] buffer = accept.Read();
    accept.Write(buffer);

    accept.FlushStream();
}

server.Stop();
```

### Secure TCP Client

```cs
/// This is the Client side.

using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Transport.Tcp;
using System.Net;

/// Load Public key
PublicKey pubkey = PublicKey.Load(Asymmetric.RSA, "key.pub");

/// Algorithm set to use
Set set = new Set()
{
    Asymmetric = Asymmetric.RSA,
    Symmetric = Symmetric.AES,
    Hash = Hash.SHA256,
};

TcpClient client = TcpClient.Create(pubkey, set);
client.InitialConnect(IPEndPoint.Parse($"127.0.0.1:12345"));

byte[] buffer = new byte[1024];
new Random().NextBytes(buffer);

byte[] check = (byte[])buffer.Clone();

for (int i = 0; i < 100; i++)
{
    client.Write(buffer);
    buffer = client.Read();

    client.FlushStream();
}

if (buffer.SequenceEqual(check) == false)
    throw new Exception("buffer is corrupted");

client.Close();
```

- This example is like repeated 100 times Ping-Pong, through SecSess RSA-AES over the TCP.
- And last, the program check that message is corrupted.
