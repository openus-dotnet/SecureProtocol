using Openus.SecureProtocol.Key.Asymmetric;
using Openus.SecureProtocol.Secure.Algorithm;
using Openus.SecureProtocol.Transport.Option;
using Openus.SecureProtocol.Transport.Tcp;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Unicode;

namespace TestProject
{
    [TestFixture]
    public class TcpConnectivity
    {
        public KeyPair TestKeyPair;
        public Set TestAlgorithmSet;

        [SetUp]
        public void KeyGenerate()
        {
            TestKeyPair = KeyPair.GenerateRSA();
            TestAlgorithmSet = new Set()
            {
                Symmetric = SymmetricType.AES,
                Asymmetric = AsymmetricType.RSA,
                Hash = HashType.SHA512,
            };
        }

        [TestCase("Hello")]
        [TestCase("æ»≥Á«œººø‰?")]
        public void UnsecureMode(string input)
        {
            TcpServer server = TcpServer.Craete(IPEndPoint.Parse("127.0.0.1:12346"));
            server.Start();

            TcpClient client = TcpClient.Craete();

            Task task = client.InitialConnectAsync((IPEndPoint)server.LocalEP);
            TcpServer.Client? sclient = server.AcceptClient();

            while (task.IsCompleted == false) ;

            Assert.IsTrue(client.CanUseStream(StreamState.All) && sclient != null, "[Unsecure mode] TcpClient.InitialConnect");

            client.Write(Encoding.UTF8.GetBytes(input));
            string msg1 = Encoding.UTF8.GetString(sclient!.Read()!);

            Assert.IsTrue(input == msg1, "[Unsecure mode] TcpClient.Write & TcpServer.Client.Read");

            client.Write(Encoding.UTF8.GetBytes(input));
            string msg2 = Encoding.UTF8.GetString(sclient.Read()!);

            Assert.IsTrue(input == msg2, "[Unsecure mode] TcpServer.Client.Write & TcpClient.Read");

            client.Close();
            server.Stop();

            Assert.IsTrue(true, "[Unsecure mode] TcpServer.Close & TcpClient.Stop");
        }
    }
}