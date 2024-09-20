using SecSess.Key;
using SecSess.Secure.Algorithm;
using SecSess.Tcp;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

internal class Program
{
    private const int Retry = 100;

    private static void Main(string[] args)
    {
        //var pair = KeyPair.GenerateRSA();
        //pair.PublicKey.Save("pub");
        //pair.PrivateKey.Save("priv");

        Set set = new Set()
        {
            Asymmetric = Asymmetric.None,
            Symmetric = Symmetric.AES,
            Hash = Hash.SHA256,
        };

        string RoleAndType = args[0];
        int Size = 1 << int.Parse(args[1]);
        int Repeat = int.Parse(args[2]);
        string Ip = args[3];

        List<double> ConnectTotals = new List<double>();
        List<double> CommunicateTotals = new List<double>();
        int port = 1234;

        switch (RoleAndType)
        {
            case "ss":
                for (int re = 0; re < Retry; re++)
                {
                    Server server = Server.Create(IPEndPoint.Parse($"{Ip}:{port}"), PrivateKey.Load("test.priv"), set);
                    server.Start();

                    Server.Client sclient = server.AcceptClient();

                    for (int i = 0; i < Repeat; i++)
                    {
                        byte[] buffer = sclient.Read();
                        sclient.Write(buffer);

                        sclient.FlushStream();
                    }

                    server.Stop();
                }

                break;

            case "sc":
                for (int re = 0; re < Retry; re++)
                {
                    DateTime time1 = DateTime.Now;

                    Client client = Client.Create(PublicKey.Load("test.pub"), set);
                    client.Connect(IPEndPoint.Parse($"{Ip}:{port}"));

                    TimeSpan span1 = DateTime.Now - time1;

                    byte[] buffer = new byte[Size];
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

                    if ((re - 9) % 10 == 0)
                    {
                        Console.WriteLine($"{re + 1}. Con. Total: {span1.TotalSeconds}s");
                        Console.WriteLine($"{re + 1}. Com. Total: {span2.TotalSeconds}s");
                    }
                    if (re != 0)
                    {
                        ConnectTotals.Add(span1.TotalSeconds);
                        CommunicateTotals.Add(span2.TotalSeconds);
                    }

                    client.Close();
                }

                using (StreamWriter sw = new StreamWriter($"output.txt", true))
                {
                    sw.WriteLine(JsonSerializer.Serialize(new
                    {
                        RoleAndType,
                        Size,
                        Repeat,
                        ConAverage = ConnectTotals.Sum() / Retry,
                        ComAverage = CommunicateTotals.Sum() / Retry,
                    }));
                }

                break;

            case "ns":
                for (int re = 0; re < Retry; re++)
                {
                    TcpListener server = new TcpListener(IPEndPoint.Parse($"{Ip}:{port}"));
                    server.Start();

                    TcpClient sclient = server.AcceptTcpClient();

                    for (int i = 0; i < Repeat; i++)
                    {
                        byte[] buffer = new byte[Size];

                        int s = 0;
                        while (s < Size) s += sclient.GetStream().Read(buffer, s, Size - s);
                        sclient.GetStream().Write(buffer);

                        sclient.GetStream().Flush();
                    }

                    server.Stop();
                }

                break;

            case "nc":
                for (int re = 0; re < Retry; re++)
                {
                    DateTime time1 = DateTime.Now;

                    TcpClient client = new TcpClient();
                    client.Connect(IPEndPoint.Parse($"{Ip}:{port}"));

                    TimeSpan span1 = DateTime.Now - time1;

                    byte[] buffer = new byte[Size];
                    new Random().NextBytes(buffer);

                    byte[] check = (byte[])buffer.Clone();

                    DateTime time2 = DateTime.Now;

                    for (int i = 0; i < Repeat; i++)
                    {
                        client.GetStream().Write(buffer);

                        int s = 0;
                        while (s < Size) s += client.GetStream().Read(buffer, s, Size - s);

                        client.GetStream().Flush();
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
                    if (re != 0)
                    {
                        ConnectTotals.Add(span1.TotalSeconds);
                        CommunicateTotals.Add(span2.TotalSeconds);
                    }

                    client.Close();
                }

                using (StreamWriter sw = new StreamWriter($"output.txt", true))
                {
                    sw.WriteLine(JsonSerializer.Serialize(new
                    {
                        RoleAndType,
                        Size,
                        Repeat,
                        ConAverage = ConnectTotals.Sum() / Retry,
                        ComAverage = CommunicateTotals.Sum() / Retry,
                    }));
                }

                break;
        }
    }
}