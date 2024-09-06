using SecSess.Key;
using SecSess.Tcp;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

int Size = 1 << int.Parse(args[1]);
int Repeat = int.Parse(args[2]);
string Type = args[0];

int Retry = 100;
List<double> Totals = new List<double>();

switch (Type)
{
    case "s":
        var pair = KeyPair.GenerateRSA();

        for (int re = 0; re < Retry; re++)
        {
            Server server = Server.Create("127.0.0.1:1234", pair.PrivateKey);
            server.Start();

            Client client = Client.Create("127.0.0.1:1234", pair.PublicKey);
            Server.Client? sclient = null;

            new Thread(() => sclient = server.AcceptClient()).Start();
            client.Connect();

            while (sclient == null) ;

            DateTime time = DateTime.Now;

            for (int i = 0; i < Repeat; i++)
            {
                client.Write(new byte[Size]);
                byte[] r = sclient!.Read();

                // Console.WriteLine(r.Length);

                client.FlushStream();
                sclient.FlushStream();
            }

            TimeSpan span = DateTime.Now - time;

            if (re % 10 == 0)
            {
                Console.WriteLine($"{re}. Total: {span.TotalSeconds}s");
            }
            if (re != 0) 
            {
                Totals.Add(span.TotalSeconds);
            }

            server.Stop();
            client.Close();
        }
        break;

    case "n":
        for (int re = 0; re < Retry; re++)
        {
            TcpListener server = new TcpListener(IPEndPoint.Parse("127.0.0.1:1234"));
            server.Start();

            TcpClient client = new TcpClient();
            TcpClient? sclient = null;
            
            new Thread(() => sclient = server.AcceptTcpClient()).Start();
            client.Connect(IPEndPoint.Parse("127.0.0.1:1234"));

            while (sclient == null) ;
            while (!client.Connected) ;
            while (!client.GetStream().CanWrite) ;
            while (!client.GetStream().CanRead) ;

            DateTime time = DateTime.Now;

            for (int i = 0; i < Repeat; i++)
            {
                client.GetStream().Write(new byte[Size], 0, Size);
                byte[] r = new byte[Size];

                sclient!.GetStream().Read(r, 0, Size);

                // Console.WriteLine(r.Length);

                client.GetStream().Flush();
                sclient.GetStream().Flush();
            }

            TimeSpan span = DateTime.Now - time;

            if (re % 10 == 0)
            {
                Console.WriteLine($"{re}. Total: {span.TotalSeconds}s");
            }
            if (re != 0) 
            {
                Totals.Add(span.TotalSeconds);
            }

            server.Stop();
            client.Close();
        }
        break;
}

using (StreamWriter sw = new StreamWriter($"output.txt", true))
{
    sw.WriteLine(JsonSerializer.Serialize(new
    {
        Type,
        Size,
        Repeat,
        Average = Totals.Sum() / Retry,
    }));
}

/// Benchmark Parameters
/// 
/// 1. Each packet's size [1B, 1KiB, 1MiB, 1GiB]
/// 2. Number of packets to repeat [1, 10, 100, 1000]