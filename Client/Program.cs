using System;
using System.Threading;
using System.Net.Sockets;
using System.Text;
using System.Collections.Generic;
using System.Runtime.Serialization.Formatters.Binary;
using System.Net;
using System.Threading.Tasks;
using CryptoUtilsLib;
using System.Security.Cryptography;

namespace KeyExchangeClient
{
    class Program
    {
        static string userName;
        private const string host = "127.0.0.1";
        private const int port = 8888;
        static TcpClient client;
        static NetworkStream stream;
        static byte[] signK;
        static byte[] signVerK;
        static List<string> requests = new List<string>();
        static Dictionary<string, byte[]> signDic = new Dictionary<string, byte[]>();
        static void Main(string[] args)
        {
            (byte[], byte[]) signKeys = CryptoUtils.genSignature();
            signK = signKeys.Item1;
            signVerK = signKeys.Item2;
            Console.Write("Введите свое имя: ");
            userName = Console.ReadLine();
            client = new TcpClient();
            try
            {
                client.Connect(host, port); //подключение клиента
                stream = client.GetStream(); // получаем поток
                BinaryFormatter formatter = new BinaryFormatter();

                Dictionary<string, object> data = new Dictionary<string, object>();
                data.Add("command", "connect");
                data.Add("username", userName);
                data.Add("signVerK", signVerK);
                formatter.Serialize(stream, data);
                Task task = Task.Run(() => ReceiveMessage());
                Console.WriteLine("Добро пожаловать, {0}", userName);
                Console.WriteLine("Commands:");
                while (true)
                {
                    string command = Console.ReadLine();
                    data.Clear();
                    switch (command)
                    {
                        case "show connections":
                            {
                                
                                data.Add("command", command);
                                formatter.Serialize(stream, data);
                                break;
                            }
                        case "say":
                            {
                                data.Add("command", command);
                                Console.Write("Enter your message:");
                                string message = Console.ReadLine();
                                data.Add("message", message);
                                formatter.Serialize(stream, data);
                                break;
                            }
                        case "key exchange":
                            {
                                data.Add("command", command);
                                Console.WriteLine("Who do you want to exchange the keys with?");
                                string client = Console.ReadLine();
                                data.Add("client", client);
                                formatter.Serialize(stream, data);
                                break;
                            }
                        case "show requests":
                            {
                                Console.WriteLine("Your current requests:");
                                foreach (string request in requests)
                                    Console.WriteLine(request);
                                break;
                            }
                        case "accept":
                            {
                                Console.WriteLine("Your current requests:");
                                foreach (string request in requests)
                                    Console.WriteLine(request);
                                Console.WriteLine("Which one you would like to accept?");
                                string client = Console.ReadLine();
                                Random randPort = new Random();
                                int port = randPort.Next(10000, 65535);
                                data.Add("command", command);
                                data.Add("client", client);
                                data.Add("port", port);
                                formatter.Serialize(stream, data);
                                requests.Remove(client);

                                Task startServer = Task.Run(() => MTIExchange.serverExchange.exchangeServer(port, signDic[client], signK));
                                break;
                            }
                        default:
                            {
                                Console.WriteLine("Unknown command");
                                break;
                            }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                Disconnect();
            }
        }
        // получение сообщений
        static void ReceiveMessage()
        {
            while (true)
            {
                try
                {
                    BinaryFormatter formatter = new BinaryFormatter();
                    Dictionary<string, object> data = (Dictionary<string, object>)formatter.Deserialize(stream); // буфер для получаемых данных
                    Console.WriteLine("{0} {1}",DateTime.Now.TimeOfDay.ToString().Remove(8), data["message"]);
                    switch ((string)data["command"])
                    {
                        case "newconnection":
                            {
                                List<string> clientList = (List<string>)data["clientList"];
                                Console.WriteLine("{0} Connections update:", DateTime.Now.TimeOfDay.ToString().Remove(8));
                                foreach (string client in clientList)
                                    Console.WriteLine(client);
                                break;
                            }
                        case "show connections":
                            {
                                List<string> clientList = (List<string>)data["clientList"];
                                foreach (string client in clientList)
                                    Console.WriteLine(client);
                                break;
                            }
                        case "key exchange":
                            {
                                requests = ((List<string>)data["requests"]);
                                if (!signDic.TryAdd((string)data["username"], (byte[])data["signVerK"]))
                                    signDic[(string)data["username"]] = (byte[])data["signVerK"];
                                break;
                            }
                        case "accept":
                            {
                                if (!signDic.TryAdd((string)data["username"], (byte[])data["signVerK"]))
                                    signDic[(string)data["username"]] = (byte[])data["signVerK"];
                                MTIExchange.clientExchange.exchangeClient((string)data["ip"], (int)data["port"], (byte[])data["signVerK"], signK);
                                break;
                            }
                        default:
                            {
                                break;
                            }
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Подключение прервано!\n{0}\n{1}", e.Message, e.StackTrace); //соединение было прервано
                    Console.ReadLine();
                    Disconnect();
                }
            }
        }

        static void Disconnect()
        {
            if (stream != null)
                stream.Close();//отключение потока
            if (client != null)
                client.Close();//отключение клиента
            Environment.Exit(0); //завершение процесса
        }
    }
}