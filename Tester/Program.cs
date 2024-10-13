﻿using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Key.Session;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Transport.Tcp;
using Openus.SecureProtocol.Transport.Udp;
using System;
using System.Net;
using System.Text;

internal class Program
{
    private static List<double> Rsa = [];
    private static List<double> Aes = [];

    private static int Repeat = 1000;
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
            Hash = HashType.SHA512,
        };
        //Set set = new Set()
        //{
        //    Asymmetric = AsymmetricType.None,
        //    Symmetric = SymmetricType.None,
        //    Hash = HashType.SHA256,
        //};

        List<Thread> threads = new List<Thread>();

        Thread tcps = new Thread(async () =>
        {
            if (args.Length > 0 && args[0].Contains("tcps"))
            {
                TcpServer server = TcpServer.Create(new IPEndPoint(IPAddress.Parse(args[1]), 12345),
                    set.Asymmetric == AsymmetricType.RSA ? privkey : null, set);
                server.Start();

                TcpServer.Client sclient = server.AcceptClient()!;
                byte[] buffer;

                for (int i = 0; i < Repeat; i++)
                {
                    buffer = sclient.Read();
                    sclient.Write(buffer);

                    sclient.FlushStream();
                }

                await Task.Delay(5000);

                server.Stop();
            }
        });
        Thread tcpc = new Thread(() =>
        {
            if (args.Length > 0 && args[0].Contains("tcpc"))
            {
                DateTime time1 = DateTime.Now;

                TcpClient client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, set);
                client.InitialConnect(new IPEndPoint(IPAddress.Parse(args[2]), 12345));

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

                client.Close();

                if (buffer.SequenceEqual(check) == false)
                    throw new Exception("buffer is corrupted");

                Rsa.Add(span1.TotalMilliseconds);
                Aes.Add(span2.TotalMilliseconds);

                Console.WriteLine($"TCP: Generate Session.    Total: {Rsa.Average()}ms");
                Console.WriteLine($"TCP: Communicate Session. Total: {Aes.Average()}ms");
            }
        });

        Thread udps = new Thread(() =>
        {
            if (args.Length > 0 && args[0].Contains("udps"))
            {
                TcpServer server = TcpServer.Create(new IPEndPoint(IPAddress.Parse(args[1]), 12345),
                    set.Asymmetric == AsymmetricType.RSA ? privkey : null, set);
                server.Start();

                TcpServer.Client sclient = server.AcceptClient()!;
                KeySet keySet = sclient.SessionKeySet;

                byte[] buffer = sclient.Read();

                server.Stop();

                UdpClient udp = UdpClient.Create(new IPEndPoint(IPAddress.Parse(args[1]), 12346), keySet);

                var task = Task.Run(async () =>
                {
                    for (int i = 0; i < Repeat; i++)
                    {
                        udp.Write(new IPEndPoint(IPAddress.Parse(args[2]), 12347), buffer);
                    }

                    await Task.Delay(5000);
                });

                Task.WaitAny([task], 5000);

                udp.Close();
            }
        });
        Thread udpc = new Thread(() =>
        {
            if (args.Length > 0 && args[0].Contains("udpc"))
            {
                TcpClient client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, set);
                client.InitialConnect(new IPEndPoint(IPAddress.Parse(args[2]), 12345));

                KeySet keySet = client.SessionKeySet;

                byte[] buffer = new byte[1 << Packet];
                new Random().NextBytes(buffer);

                client.Write(buffer);

                client.Close();

                UdpClient udp = UdpClient.Create(new IPEndPoint(IPAddress.Parse(args[1]), 12347), keySet);

                int valid = 0;
                int invalid = 0;

                IPEndPoint remote = new IPEndPoint(IPAddress.Parse(args[2]), 12346);

                var task = Task.Run(() =>
                {
                    for (int i = 0; i < Repeat; i++)
                    {
                        try
                        {
                            if (udp.Read(ref remote).SequenceEqual(buffer) == true)
                                valid++;
                            else
                                invalid++;
                        }
                        catch
                        {
                            invalid++;
                        }
                    }
                });

                Task.WaitAny([task], 5000);

                Console.WriteLine($"UDP: Total: {Repeat}, Valid: {valid}, Invalid: {invalid}, Loss: {Repeat - valid - invalid}");

                udp.Close();
            }
        });


        Thread tcprs = new Thread(async () =>
        {
            if (args.Length > 0 && args[0].Contains("tcprs"))
            {
                TcpServer server = TcpServer
                    .Create(new IPEndPoint(IPAddress.Parse(args[1]), 12345),
                        set.Asymmetric == AsymmetricType.RSA ? privkey : null, set)
                    // .WithEnableTicket(TimeSpan.FromSeconds(1))
                    ;
                server.Start();

                TcpServer.Client sclient1 = server.AcceptClient()!;
                TcpServer.Client sclient2 = server.AcceptClient()!;

                sclient2.Write(sclient2.Read());

                try
                {
                    TcpServer.Client sclient3 = server.AcceptClient()!;
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex);
                }

                TcpServer.Client sclient4 = server.AcceptClient()!;

                sclient4.Write(sclient4.Read());

                await Task.Delay(5000);

                server.Stop();
            }
        });
        Thread tcprc = new Thread(() =>
        {
            if (args.Length > 0 && args[0].Contains("tcprc"))
            {
                TcpClient client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, set);
                client.InitialConnect(new IPEndPoint(IPAddress.Parse(args[2]), 12345));

                KeySet keyset = client.SessionKeySet;
                Ticket ticket = client.Ticket;

                client.Close();

                client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, keyset, ticket);
                client.ReConnect(new IPEndPoint(IPAddress.Parse(args[2]), 12345));

                Ticket reticket = client.Ticket;

                byte[] buffer = Encoding.UTF8.GetBytes("Hello, world!");

                client.Write(buffer);

                if (client.Read().SequenceEqual(buffer) == false)
                    throw new Exception("buffer is corrupted");

                client.Close();

                client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, keyset, ticket);
                Task.WaitAny([Task.Run(() => client.ReConnect(new IPEndPoint(IPAddress.Parse(args[2]), 12345)))], 5000);

                client = TcpClient.Create(set.Asymmetric == AsymmetricType.RSA ? pubkey : null, keyset, reticket);
                client.ReConnect(new IPEndPoint(IPAddress.Parse(args[2]), 12345));

                client.Write(buffer);

                if (client.Read().SequenceEqual(buffer) == false)
                    throw new Exception("buffer is corrupted");

                Console.WriteLine("Sucess");

                client.Close();
            }
        });

        threads.Add(tcps);
        threads.Add(tcpc);
        threads.Add(tcprs);
        threads.Add(tcprc);
        threads.Add(udps);
        threads.Add(udpc);

        foreach (var thread in threads)
        {
            thread.Start();
        }
        foreach (var thread in threads)
        {
            thread.Join();
        }
    }
}