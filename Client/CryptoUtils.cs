using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace CryptoUtilsLib
{
    public class CryptoUtils
    {
        public static BigInteger generatePrimeWithLength(int length = 128)
        {
            BigInteger n = RandomIntegerBelow((BigInteger)Math.Pow(2, length));
            while (!isPrime(n))
            {
                n++;
            }
            return n;
        }
        public static BigInteger RandomIntegerBelow(BigInteger N)
        {
            Random random = new Random();
            byte[] bytes = N.ToByteArray();
            BigInteger R;

            do
            {
                random.NextBytes(bytes);
                bytes[bytes.Length - 1] &= (byte)0x7F; //force sign bit to positive
                R = new BigInteger(bytes);
            } while (R >= N);

            return R;
        }
        public static Boolean isPrime(BigInteger num)
        {
            for (int i = 2; i <= 10000; i++)
            {
                var n = BigInteger.ModPow(i, num - 1, num);
                if (n != 1)
                {
                    return false;
                }

            }
            return true;     
        }
        public static (byte[], byte[]) genSignature()
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            return (rsa.ExportCspBlob(false), rsa.ExportCspBlob(true));

        }

        public static Dictionary<string, object> signData(object data, byte[] signature)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            Dictionary<string, object> signedData = new Dictionary<string, object>();
            signedData.Add("packet", data);
            byte[] hashValue;
            using (SHA256 hash = SHA256.Create())
            {
                MemoryStream stream = new MemoryStream();
                formatter.Serialize(stream, data);

                hashValue = hash.ComputeHash(stream.ToArray());
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(signature);
                signedData.Add("signed", rsa.Encrypt(hashValue, true));
            }
            return signedData;
        }
        public static bool verifyData(Dictionary<string, object> signedData, byte[] signature)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            byte[] hashValue;
            byte[] signedHash = null;
            using (SHA256 hash = SHA256.Create())
            {
                MemoryStream stream = new MemoryStream();
                formatter.Serialize(stream, signedData["packet"]);
                hashValue = hash.ComputeHash(stream.ToArray());
            }
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportCspBlob(signature);
                try
                {
                    signedHash = rsa.Decrypt((byte[])signedData["signed"], true);
                }
                catch (Exception e)
                { Console.WriteLine("{0} " + e.Message + "\n" + e.StackTrace, DateTime.Now.TimeOfDay.ToString().Remove(8)); }
            }
            return Convert.ToBase64String(signedHash) == Convert.ToBase64String(hashValue) ? true : false;
        }
    }

    public class MTI
    {
        public class Parameters
        {
            public BigInteger p { get; set; }
            public BigInteger g { get; set; }
            public (BigInteger, BigInteger) keys { get; set; }
            public BigInteger R { get; set; }
            public BigInteger gR { get; set; }
            public BigInteger sessionKey { get; set; }
        }
        public static BigInteger get_p(int length = 128)
        {
            Console.WriteLine("{0} Generating p", DateTime.Now.TimeOfDay.ToString().Remove(8));
            return CryptoUtils.generatePrimeWithLength(length);
        }

        public static BigInteger get_g(BigInteger p)
        {
            Console.WriteLine("{0} Generating g", DateTime.Now.TimeOfDay.ToString().Remove(8));
            BigInteger g = CryptoUtils.RandomIntegerBelow(p);
            while (BigInteger.ModPow(g, p - 1, p) != 1)
                g = CryptoUtils.RandomIntegerBelow(p);
            return g;
        }

        public static (BigInteger, BigInteger) get_keys(BigInteger p, BigInteger g)
        {
            Console.WriteLine("{0} Generating keys", DateTime.Now.TimeOfDay.ToString().Remove(8));
            BigInteger privateKey = CryptoUtils.RandomIntegerBelow((BigInteger)Math.Pow(2, 128));
            BigInteger publicKey = BigInteger.ModPow(g, privateKey, p);
            return (publicKey, privateKey);
        }

        public static BigInteger get_R(BigInteger p)
        {
            Console.WriteLine("{0} Generating R", DateTime.Now.TimeOfDay.ToString().Remove(8));
            return CryptoUtils.RandomIntegerBelow(p); ;
        }
        public static BigInteger get_gR(BigInteger p, BigInteger g, BigInteger R)
        {
            return BigInteger.ModPow(g, R, p);
        }

        public static BigInteger get_sessionkey(BigInteger p, BigInteger g, BigInteger yourR, BigInteger gR, BigInteger interlocutorPublicKey, BigInteger yourPrivateKey)
        {
            Console.WriteLine("{0} Calculating session key", DateTime.Now.TimeOfDay.ToString().Remove(8));
            return BigInteger.ModPow(gR, yourPrivateKey, p) * BigInteger.ModPow(interlocutorPublicKey, yourR, p);
        }

    }

    public class MTIExchange
    {
        public class clientExchange
        {
            static byte[] signature;
            static byte[] verify;
            static string serverIP;
            static int serverPort;
            static MTI.Parameters parameters;
            static NetworkStream stream;
            static TcpClient tcpClient;
            
            public static void exchangeClient(string ip, int port, byte[] hisSign, byte[] mySign)
            {
                try
                {
                    tcpClient = new TcpClient();
                    serverIP = ip;
                    serverPort = port;
                    signature = mySign;
                    verify = hisSign;
                    tcpClient.Connect(serverIP, serverPort);
                    Console.WriteLine("{0} Starting key exchange.", DateTime.Now.TimeOfDay.ToString().Remove(8));
                    stream = tcpClient.GetStream();
                    BinaryFormatter formatter = new BinaryFormatter();
                    Dictionary<string, object> data = new Dictionary<string, object>();
                    parameters = new MTI.Parameters();
                    Task receive = Task.Run(() => clientReceiveMessage());
                    parameters.p = MTI.get_p();
                    Console.WriteLine("{1} p = {0}", parameters.p, DateTime.Now.TimeOfDay.ToString().Remove(8));
                    parameters.g = MTI.get_g(parameters.p);
                    Console.WriteLine("{1} g = {0}", parameters.g, DateTime.Now.TimeOfDay.ToString().Remove(8));
                    parameters.R = MTI.get_R(parameters.p);
                    Console.WriteLine("{1} R = {0}", parameters.R, DateTime.Now.TimeOfDay.ToString().Remove(8));
                    parameters.keys = MTI.get_keys(parameters.p, parameters.g);
                    Console.WriteLine("{2} pubK = {0}\n{2} pvtK = {1}", parameters.keys.Item1, parameters.keys.Item2, DateTime.Now.TimeOfDay.ToString().Remove(8));
                    parameters.gR = MTI.get_gR(parameters.p, parameters.g, parameters.R);
                    data.Add("p", parameters.p);
                    data.Add("g", parameters.g);
                    data.Add("k", parameters.keys.Item1);
                    data.Add("gR", parameters.gR);
                    Console.WriteLine("{0} Sending data...", DateTime.Now.TimeOfDay.ToString().Remove(8));
                    formatter.Serialize(stream, CryptoUtils.signData(data, signature));
                    return;
                }
                catch
                {

                }
            }
            static void clientReceiveMessage()
            {
                while (true)
                {
                    try
                    {
                        BinaryFormatter formatter = new BinaryFormatter();
                        Dictionary<string, object> data = (Dictionary<string, object>)formatter.Deserialize(stream); // буфер для получаемых данных
                        Dictionary<string, object> packet = (Dictionary<string, object>)data["packet"];
                        Console.Write("{0} Recieved data: ", DateTime.Now.TimeOfDay.ToString().Remove(8));
                        Console.WriteLine(CryptoUtils.verifyData(data, verify) ? "packet verified" : "packet not verified");
                        parameters.sessionKey = MTI.get_sessionkey(parameters.p, parameters.g, parameters.R, (BigInteger)packet["gR"], (BigInteger)packet["k"], parameters.keys.Item2);
                        Console.WriteLine("{1} session key = {0}",parameters.sessionKey, DateTime.Now.TimeOfDay.ToString().Remove(8));
                        Console.WriteLine("{0} Disconnecting from the key exchange server...", DateTime.Now.TimeOfDay.ToString().Remove(8));
                        tcpClient.Close();
                        stream.Close();
                        return;
                    }
                    catch
                    {
                        Console.WriteLine("{0} Подключение прервано!", DateTime.Now.TimeOfDay.ToString().Remove(8)); //соединение было прервано
                        Console.ReadLine();
                    }
                }
            }
        }
        public class serverExchange
        {
            static byte[] signature;
            static byte[] verify;
            static int serverPort;
            static MTI.Parameters parameters;
            static NetworkStream stream;
            public static void exchangeServer(int port, byte[] hisSign, byte[] mySign)
            {
                signature = mySign;
                verify = hisSign;
                serverPort = port;
                ServerObject server = new ServerObject();
                Task listen = Task.Run(() => server.Listen());
                listen.Wait();
                

            }
            public class ServerObject
            {
                static TcpListener tcpListener;

                protected internal void Listen()
                {
                    try
                    {
                        tcpListener = new TcpListener(IPAddress.Any, serverPort);
                        tcpListener.Start();
                        Console.WriteLine("{1} Key exchange server has started on port {0}", serverPort, DateTime.Now.TimeOfDay.ToString().Remove(8));

                        while (true)
                        {
                            TcpClient tcpClient = tcpListener.AcceptTcpClient();
                            Console.WriteLine("{0} Starting key exchange.", DateTime.Now.TimeOfDay.ToString().Remove(8));
                            ClientObject clientObject = new ClientObject(tcpClient, this);
                            Task clientTask = Task.Run(() => clientObject.Process());
                            clientTask.Wait();
                                Console.WriteLine("{0} Shutting down the key exchange server...", DateTime.Now.TimeOfDay.ToString().Remove(8));
                                break;
                        }
                        tcpListener.Stop();
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message + "\n" + e.StackTrace);
                        tcpListener.Stop();
                    }
                }
            }


            public class ClientObject
            {
                protected internal NetworkStream Stream { get; private set; }
                TcpClient client;
                byte[] signVerify;
                byte[] sign;
                ServerObject server;
                public ClientObject(TcpClient tcpClient, ServerObject serverObject)
                {
                    client = tcpClient;
                    server = serverObject;
                    signVerify = verify;
                    sign = signature;
                }

                public void Process()
                {
                    stream = client.GetStream();
                    BinaryFormatter formatter = new BinaryFormatter();

                    while (true)
                    {
                        try
                        {
                            Dictionary<string, object> data = (Dictionary<string, object>)formatter.Deserialize(stream);
                            Dictionary<string, object> packet = (Dictionary<string, object>)data["packet"];
                            Console.Write("{0} Received data: ", DateTime.Now.TimeOfDay.ToString().Remove(8));
                            Console.WriteLine(CryptoUtils.verifyData(data, signVerify) ? "packet verified" : "packet not verified");
                            MTI.Parameters parameters = new MTI.Parameters();
                            parameters.p = (BigInteger)packet["p"];
                            Console.WriteLine("{1} p = {0}", parameters.p, DateTime.Now.TimeOfDay.ToString().Remove(8));
                            parameters.g = (BigInteger)packet["g"];
                            Console.WriteLine("{1} g = {0}", parameters.g, DateTime.Now.TimeOfDay.ToString().Remove(8));
                            parameters.R = MTI.get_R(parameters.p);
                            Console.WriteLine("{1} R = {0}", parameters.R, DateTime.Now.TimeOfDay.ToString().Remove(8));
                            parameters.gR = MTI.get_gR(parameters.p, parameters.g, parameters.R);
                            parameters.keys = MTI.get_keys(parameters.p, parameters.g);
                            Console.WriteLine("{2} pubK = {0}\n{2} pvtK = {1}", parameters.keys.Item1, parameters.keys.Item2, DateTime.Now.TimeOfDay.ToString().Remove(8));
                            parameters.sessionKey = MTI.get_sessionkey(parameters.p, parameters.g, parameters.R, (BigInteger)packet["gR"], (BigInteger)packet["k"], parameters.keys.Item2);
                            Console.WriteLine("{1} session key = {0}",parameters.sessionKey, DateTime.Now.TimeOfDay.ToString().Remove(8));
                            data.Clear();
                            data.Add("gR", MTI.get_gR(parameters.p, parameters.g, parameters.R));
                            data.Add("k", parameters.keys.Item1);
                            Console.WriteLine("Sending data...");
                            formatter.Serialize(stream, CryptoUtils.signData(data, sign));
                            client.Close();
                            stream.Dispose();
                            return;
                        }
                        catch
                        {

                        }
                    }
                }
            }
        }
    }
}
