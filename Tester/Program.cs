using SecSess.Key;
using SecSess.Tcp;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

const int Size = 102400;
int total = 0;

switch (args[0])
{
    case "s":
        {
            var pair = KeyPair.GenerateRSA();

            Server server = Server.Create("127.0.0.1:1234", pair.PrivateKey);
            server.Start();

            Client client = Client.Create("127.0.0.1:1234", pair.PublicKey);
            Server.Client? sclient = null;

            new Thread(() => client.Connect()).Start();
            new Thread(() => sclient = server.AcceptClient()).Start();

            Task.Delay(1000).Wait();

            for (int i = 0; i < 1000; i++)
            {
                DateTime time = DateTime.Now;

                client.Write(new byte[Size]);
                byte[] r = sclient!.Read();

                // Console.WriteLine(r.Length);

                TimeSpan span = DateTime.Now - time;

                Console.WriteLine(span.Microseconds);
                total+= span.Microseconds;
            }
        }
        break;

    case "n":
        {
            TcpListener server = new TcpListener(IPEndPoint.Parse("127.0.0.1:1234"));
            server.Start();

            TcpClient client = new TcpClient();
            TcpClient? sclient = null;

            new Thread(() => client.Connect(IPEndPoint.Parse("127.0.0.1:1234"))).Start();
            new Thread(() => sclient = server.AcceptTcpClient()).Start();

            Task.Delay(1000).Wait();

            for (int i = 0; i < 1000; i++)
            {
                DateTime time = DateTime.Now;

                client.GetStream().Write(new byte[Size]);
                byte[] r = new byte[Size];

                sclient!.GetStream().Read(r);

                // Console.WriteLine(r.Length);

                TimeSpan span = DateTime.Now - time;

                Console.WriteLine(span.Microseconds);
                total += span.Microseconds;
            }
        }
        break;
}

Console.WriteLine(total);