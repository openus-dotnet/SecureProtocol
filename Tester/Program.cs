using SecSess.Key;
using SecSess.Tcp;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

const int Size = 1 << 30;
const int Repeat = 10;
const string Type = "n";

List<double> Totals = new List<double>();

switch (Type)
{
    case "s":
        for (int re = 0; re < 10; re++)
        {
            var pair = KeyPair.GenerateRSA();

            Server server = Server.Create("127.0.0.1:1234", pair.PrivateKey);
            server.Start();

            Client client = Client.Create("127.0.0.1:1234", pair.PublicKey);

            new Thread(() => client.Connect()).Start();
            Server.Client sclient = server.AcceptClient();

            DateTime time = DateTime.Now;

            for (int i = 0; i < Repeat; i++)
            {
                client.Write(new byte[Size]);
                byte[] r = sclient.Read();

                // Console.WriteLine(r.Length);
            }

            TimeSpan span = DateTime.Now - time;

            Console.WriteLine($"Total: {span.TotalSeconds}s");
            Totals.Add(span.TotalSeconds);

            server.Stop();
            client.Close();
        }
        break;

    case "n":
        for (int re = 0; re < 10; re++)
        {
            TcpListener server = new TcpListener(IPEndPoint.Parse("127.0.0.1:1234"));
            server.Start();

            TcpClient client = new TcpClient();
            
            new Thread(() => client.Connect(IPEndPoint.Parse("127.0.0.1:1234"))).Start();
            TcpClient sclient = server.AcceptTcpClient();

            DateTime time = DateTime.Now;

            for (int i = 0; i < Repeat; i++)
            {
                client.GetStream().Write(new byte[Size]);
                byte[] r = new byte[Size];

                sclient.GetStream().Read(r);

                // Console.WriteLine(r.Length);
            }

            TimeSpan span = DateTime.Now - time;

            Console.WriteLine($"Total: {span.TotalSeconds}s");
            Totals.Add(span.TotalSeconds);

            server.Stop();
            client.Close();
        }
        break;
}

using (StreamWriter sw = new StreamWriter($"{Type} - {Size} Byte for {Repeat}.txt"))
{
    sw.Write(Totals.Sum());
}

/// Benchmark Parameters
/// 
/// 1. Each packet's size [1B, 1KiB, 1MiB, 1GiB]
/// 2. Number of packets to repeat [1, 10, 100, 1000]