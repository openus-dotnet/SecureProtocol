using SecSess.Key;
using SecSess.Secure.Algorithm;
using SecSess.Tcp;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
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
            Asymmetric = Asymmetric.RSA,
            Symmetric = Symmetric.AES,
            Hash = Hash.SHA256,
        };

        string RoleAndType = args[0];
        int Size = 1 << int.Parse(args[1]);
        int Repeat = int.Parse(args[2]);
        string Ip = args[3];

        List<double> Totals = new List<double>();

        switch (RoleAndType)
        {
            case "ss":
                for (int re = 0; re < Retry; re++)
                {
                    Server server = Server.Create($"{Ip}:1234", PrivateKey.Load("test.priv"), set);
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
                    Client client = Client.Create($"{Ip}:1234", PublicKey.Load("test.pub"), set);
                    client.Connect();

                    byte[] buffer = new byte[Size];
                    new Random().NextBytes(buffer);

                    byte[] check = (byte[])buffer.Clone();

                    DateTime time = DateTime.Now;

                    for (int i = 0; i < Repeat; i++)
                    {
                        client.Write(buffer);
                        buffer = client.Read();

                        client.FlushStream();
                    }

                    TimeSpan span = DateTime.Now - time;

                    for (int i = 0; i < buffer.Length; i++)
                    {
                        if (buffer[i] != check[i])
                            throw new Exception("buffer is corrupted");
                    }

                    if ((re - 9) % 10 == 0)
                    {
                        Console.WriteLine($"{re + 1}. Total: {span.TotalSeconds}s");
                    }
                    if (re != 0)
                    {
                        Totals.Add(span.TotalSeconds);
                    }

                    client.Close();

                    using (StreamWriter sw = new StreamWriter($"output.txt", true))
                    {
                        sw.WriteLine(JsonSerializer.Serialize(new
                        {
                            RoleAndType,
                            Size,
                            Repeat,
                            Average = Totals.Sum() / Retry,
                        }));
                    }
                }
                break;

            case "ns":
                for (int re = 0; re < Retry; re++)
                {
                    TcpListener server = new TcpListener(IPEndPoint.Parse($"{Ip}:1234"));
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
                    TcpClient client = new TcpClient();
                    client.Connect(IPEndPoint.Parse($"{Ip}:1234"));

                    byte[] buffer = new byte[Size];
                    new Random().NextBytes(buffer);

                    byte[] check = (byte[])buffer.Clone();

                    DateTime time = DateTime.Now;

                    for (int i = 0; i < Repeat; i++)
                    {
                        client.GetStream().Write(buffer);

                        int s = 0;
                        while (s < Size) s += client.GetStream().Read(buffer, s, Size - s);

                        client.GetStream().Flush();
                    }

                    TimeSpan span = DateTime.Now - time;

                    for (int i = 0; i < buffer.Length; i++)
                    {
                        if (buffer[i] != check[i])
                            throw new Exception("buffer is corrupted");
                    }

                    if ((re - 9) % 10 == 0)
                    {
                        Console.WriteLine($"{re + 1}. Total: {span.TotalSeconds}s");
                    }
                    if (re != 0)
                    {
                        Totals.Add(span.TotalSeconds);
                    }

                    client.Close();

                    using (StreamWriter sw = new StreamWriter($"output.txt", true))
                    {
                        sw.WriteLine(JsonSerializer.Serialize(new
                        {
                            RoleAndType,
                            Size,
                            Repeat,
                            Average = Totals.Sum() / Retry,
                        }));
                    }
                }
                break;

        }
    }
}