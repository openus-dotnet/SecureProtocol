using Openus.Net.SecSess.Key.Asymmetric;
using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Transport.Tcp;
using System.Net;

internal class Program
{
    private const int Retry = 100;

    private static void Main(string[] args)
    {
        if (args.Length > 0)
        {
            var keys = KeyPair.GenerateRSA();

            keys.PublicKey.Save("test.pub");
            keys.PrivateKey.Save("test.priv");
        }

        PublicKey pubkey = PublicKey.Load(AsymmetricType.RSA, "test.pub");
        PrivateKey privkey = PrivateKey.Load(AsymmetricType.RSA, "test.priv");

        Set set = new Set()
        {
            Asymmetric = AsymmetricType.RSA,
            Symmetric = SymmetricType.AES,
            Hash = HashType.SHA256,
        };


        for (int re = 0; re < Retry; re++)
        {
            Thread s = new Thread(() =>
            {
                Server server = Server.Create(IPEndPoint.Parse($"127.0.0.1:12345"), privkey, set);
                server.Start();

                Server.Client sclient = server.AcceptClient();

                for (int i = 0; i < 100; i++)
                {
                    byte[] buffer = sclient.Read();

                    sclient.Write(buffer);
                }

                server.Stop();
            });
            Thread c = new Thread(() =>
            {
                DateTime time1 = DateTime.Now;

                Client client = Client.Create(pubkey, set);
                client.Connect(IPEndPoint.Parse($"127.0.0.1:12345"), 100);

                TimeSpan span1 = DateTime.Now - time1;

                byte[] buffer = new byte[1024];
                new Random().NextBytes(buffer);

                byte[] check = (byte[])buffer.Clone();

                DateTime time2 = DateTime.Now;

                for (int i = 0; i < 100; i++)
                {
                    client.Write(buffer);

                    buffer = client.Read();
                }

                TimeSpan span2 = DateTime.Now - time2;

                for (int i = 0; i < buffer.Length; i++)
                {
                    if (buffer[i] != check[i])
                        throw new Exception("buffer is corrupted");
                }

                if ((re - 9) % 10 == 0)
                {
                    Console.WriteLine($"{re + 1}. Con. Total: {span1.TotalSeconds}s");
                    Console.WriteLine($"{re + 1}. Com. Total: {span2.TotalSeconds}s");
                }

                client.Close();
            });

            s.Start();
            c.Start();

            s.Join();
            c.Join();
        }
    }
}