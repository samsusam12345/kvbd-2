using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;

namespace KeyExchangeServer
{
    public class ClientObject
    {
        protected internal string Id { get; private set; }
        protected internal NetworkStream Stream { get; private set; }
        protected internal string userName;
        TcpClient client;
        byte[] signVerify;
        string ip;
        int port;
        ServerObject server; // объект сервера

        public ClientObject(TcpClient tcpClient, ServerObject serverObject)
        {
            Id = Guid.NewGuid().ToString();
            client = tcpClient;
            server = serverObject;
            serverObject.AddConnection(this);
        }

        public void Process()
        {
            try
            {
                string message;
                Stream = client.GetStream();
                BinaryFormatter formatter = new BinaryFormatter();
                List<string> requests = new List<string>();

                while (true)
                {
                    try
                    {
                        Dictionary<string, object> data = (Dictionary<string, object>)formatter.Deserialize(Stream);
                        switch ((string)data["command"])
                        {
                            case "connect":
                                {

                                    userName = (string)data["username"];
                                    signVerify = (byte[])data["signVerK"];
                                    ip = client.Client.RemoteEndPoint.ToString();
                                    ip = ip.Remove(ip.IndexOf(':'));
                                    message = "Connections update:\n";
                                    data.Clear();
                                    data.Add("command", "newconnection");
                                    data.Add("message", $"{userName} ({ip}) has connected.");
                                    List<string> clientList = new List<string>();
                                    foreach (ClientObject user in ServerObject.clients)
                                        clientList.Add(user.userName);
                                    data.Add("clientList", clientList);
                                    server.BroadcastMessage(data, this.Id);
                                    break;
                                }

                            case "show connections":
                                {
                                    data.Clear();
                                    data.Add("command", "show connections");
                                    data.Add("message", "Current connections:");
                                    List<string> clientList = new List<string>();
                                    foreach (ClientObject user in ServerObject.clients)
                                        clientList.Add(user.userName);
                                    data.Add("clientList", clientList);
                                    formatter.Serialize(Stream, data);
                                    break;
                                }
                            case "say":
                                {
                                    message = (string)data["message"];
                                    data["message"] = $"{userName}: {data["message"]}";
                                    server.BroadcastMessage(data, this.Id);
                                    break;
                                }
                            case "key exchange":
                                {
                                    requests.Add(userName);
                                    data.Add("message", $"{userName} requests a key exchange with you.\nEnter \"accept\" to accept.");
                                    data.Add("signVerK", signVerify);
                                    data.Add("username", userName);
                                    data.Add("requests", requests);
                                    formatter.Serialize(ServerObject.clients.Find(x => x.userName == (string)data["client"]).Stream, data);
                                    break;
                                }
                            case "accept":
                                {
                                    requests.Remove((string)data["client"]);
                                    data.Add("message", $"{userName} has accepted your request.");
                                    data.Add("signVerK", this.signVerify);
                                    data.Add("username", userName);
                                    data.Add("ip", this.ip);
                                    formatter.Serialize(ServerObject.clients.Find(x => x.userName == (string)data["client"]).Stream, data);
                                    break;
                                }
                            default:
                                {
                                    Console.WriteLine("Unknown command...");
                                    break;
                                }
                        }
                    }
                    catch
                    {
                        Dictionary<string, object> data = new Dictionary<string, object>();
                        data.Add("command", "client disconnect");
                        data.Add("message", $"{userName} ({ip}) has disconnected.");
                        server.BroadcastMessage(data, this.Id);
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message + "\n" + e.StackTrace);
            }
            finally
            {
                server.RemoveConnection(this.Id);
                Close();
            }
        }
        // закрытие подключения
        protected internal void Close()
        {
            if (Stream != null)
                Stream.Close();
            if (client != null)
                client.Close();
        }
    }
}