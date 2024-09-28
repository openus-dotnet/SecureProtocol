using Openus.Net.SecSess.Key.Asymmetric;
using Openus.Net.SecSess.Key.Session;
using Openus.Net.SecSess.Secure.Algorithm;
using Openus.Net.SecSess.Transport.Tcp;
using Openus.Net.SecSess.Transport.Udp;
using System.Net;

internal class Program
{
    private const int Retry = 1000;
    private static List<double> Rsa = [];
    private static List<double> Aes = [];

    private static int Repeat = 100;
    private static int Packet = 10;

    private static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "k")
        {
            var keys = KeyPair.GenerateRSA();

            keys.PublicKey.Save("test.pub");
            keys.PrivateKey.Save("test.priv");

            return;
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

            Thread tcps = new Thread(() =>
            {
                if (args.Length > 0 && args[0].Contains("tcps"))
                {
                    TcpServer server = TcpServer.Create(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12345"),
                        set.Asymmetric == AsymmetricType.RSA ? privkey : null, set);
                    server.Start();

                    checker = true;

                    TcpServer.Client sclient = server.AcceptClient()!;
                    byte[] buffer;

                    for (int i = 0; i < Repeat; i++)
                    {
                        buffer = sclient.Read();
                        sclient.Write(buffer);

                        sclient.FlushStream();
                    }

                    while (checker == true) ;

                    server.Stop();
                }
            });
            Thread tcpc = new Thread(() =>
            {
                if (args.Length > 0 && args[0].Contains("tcpc"))
                {
                    while (checker == false) ;

                    DateTime time1 = DateTime.Now;

                    TcpClient client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, set);
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

                    checker = false;

                    client.Close();

                    if (buffer.SequenceEqual(check) == false)
                        throw new Exception("buffer is corrupted");

                    int term = 50;

                    if ((re - term + 1) % term == 0)
                    {
                        Rsa.Add(span1.TotalMilliseconds);
                        Aes.Add(span2.TotalMilliseconds);

                        Console.WriteLine($"TCP {re + 1, 4}: Generate Session.    Total: {Rsa.Average()}ms");
                        Console.WriteLine($"TCP {re + 1, 4}: Communicate Session. Total: {Aes.Average()}ms");
                        Console.WriteLine();
                    }
                }
            });

            Thread udps = new Thread(() =>
            {
                if (args.Length > 0 && args[0].Contains("udps"))
                {
                    TcpServer server = TcpServer.Create(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12345"),
                        set.Asymmetric == AsymmetricType.RSA ? privkey : null, set);
                    server.Start();

                    checker = true;

                    TcpServer.Client sclient = server.AcceptClient()!;
                    KeySet keySet = sclient.SessionKeySet;

                    byte[] buffer = sclient.Read();

                    while (checker == true) ;

                    server.Stop();

                    UdpClient udp = UdpClient.Craete(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12346"), keySet);

                    int valid = 0;
                    int invalid = 0;

                    var task = Task.Run(() =>
                    {
                        for (int i = 0; i < Repeat; i++)
                        {
                            if (udp.Read().Item2.SequenceEqual(buffer[0..i]) == true)
                                valid++;
                            else
                                invalid++;
                        }
                    });

                    Task.WaitAny([task], 1000);

                    int term = 50;

                    if ((re - term + 1) % term == 0)
                    {
                        Console.WriteLine($"UDP {re + 1,4}: Total: {Repeat}, Valid: {valid}, Invalid: {invalid}, Loss: {Repeat - valid - invalid}");
                        Console.WriteLine();
                    }

                    udp.Close();
                }
            });
            Thread udpc = new Thread(() =>
            {
                if (args.Length > 0 && args[0].Contains("udpc"))
                {
                    while (checker == false) ;

                    TcpClient client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, set);
                    client.Connect(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12345"));

                    KeySet keySet = client.SessionKeySet;

                    byte[] buffer = new byte[1 << Packet];
                    new Random().NextBytes(buffer);

                    client.Write(buffer);

                    checker = false;

                    client.Close();

                    UdpClient udp = UdpClient.Craete(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12347"), keySet);

                    for (int i = 0; i < Repeat; i++)
                    {
                        udp.Write(IPEndPoint.Parse(args.Length == 2 ? args[1] : "127.0.0.1:12346"), buffer[0..i]);
                    }

                    udp.Close();
                }
            });

            tcps.Start();
            tcpc.Start();
            udps.Start();
            udpc.Start();

            tcps.Join();
            tcpc.Join();
            udps.Join();
            udpc.Join();
        }
    }
}