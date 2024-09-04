using SecSess.Key;
using SecSess.Tcp;

var pair = KeyPair.GenerateRSA();
Server server = Server.Create("127.0.0.1", 3000, pair.PrivateKey);

pair.PublicKey.Save("test.pubkey");
pair.PrivateKey.Save("test.privkey");

pair.PublicKey = PublicKey.Load("test.pubkey");
pair.PrivateKey = PrivateKey.Load("test.privkey");

//pair.PrivateKey = PrivateKey.Load("test.pubkey");
//pair.PublicKey = PublicKey.Load("test.privkey");
