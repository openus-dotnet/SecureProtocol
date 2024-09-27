using Openus.Net.SecSess.Key.Asymmetric;
using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Transport.Tcp;
using System.Net;
using System.Text.Json;

internal class Program
{
    private const int Retry = 1000;
    private static List<double> Rsa = [];
    private static List<double> Aes = [];

    private static int Repeat = 100;
    private static int Packet = 15;

    private static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "k")
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
        //Set set = new Set()
        //{
        //    Asymmetric = AsymmetricType.None,
        //    Symmetric = SymmetricType.None,
        //    Hash = HashType.SHA256,
        //};


        for (int re = 0; re < Retry; re++)
        {
            bool checker = false;
            Thread s = new Thread(() =>
            {
                if (args.Length == 0 || args.Length > 0 && args[0] == "s")
                {
                    Server server = Server.Create(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12345"),
                        set.Asymmetric == AsymmetricType.RSA ? privkey : null, set);
                    server.Start();
                    
                    checker = true;

                    Server.Client sclient = server.AcceptClient()!;
                    byte[] buffer;

                    for (int i = 0; i < Repeat; i++)
                    {
                        buffer = sclient.Read();
                        sclient.Write(buffer);

                        sclient.FlushStream();
                    }

                    server.Stop();
                }
            });
            Thread c = new Thread(() =>
            {
                if (args.Length == 0 || args.Length > 0 && args[0] == "c")
                {
                    while (checker == false) ;

                    DateTime time1 = DateTime.Now;

                    Client client = Client.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, set);
                    client.Connect(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12345"));

                    TimeSpan span1 = DateTime.Now - time1;

                    byte[] buffer = new byte[1 << Packet];
                    new Random().NextBytes(buffer);

                    byte[] check = (byte[])buffer.Clone();

                    DateTime time2 = DateTime.Now;

                    for (int i = 0; i < Repeat; i++)
                    {
                        client.Write(buffer);
                        buffer = client.Read();

                        client.FlushStream();
                    }

                    TimeSpan span2 = DateTime.Now - time2;

                    for (int i = 0; i < buffer.Length; i++)
                    {
                        if (buffer[i] != check[i])
                            throw new Exception("buffer is corrupted");
                    }

                    int term = 50;

                    if ((re - term + 1) % term == 0)
                    {
                        Rsa.Add(span1.TotalMilliseconds);
                        Aes.Add(span2.TotalMilliseconds);

                        Console.WriteLine($"{re + 1}. RSA. Total: {Rsa.Average()}ms");
                        Console.WriteLine($"{re + 1}. AES. Total: {Aes.Average()}ms");
                        Console.WriteLine();
                    }

                    client.Close();
                }
            });

            s.Start();
            c.Start();

            s.Join();
            c.Join();
        }

        Console.WriteLine(JsonSerializer.Serialize(new { Repeat, Packet, RSA = Rsa.Average(), AES = Aes.Average() }));
    }
}