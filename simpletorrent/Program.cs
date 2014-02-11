//
//  Program.cs
//
//  Copyright (C) 2014  senditu <https://github.com/senditu/simpletorrent>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as
//  published by the Free Software Foundation, either version 3 of the
//  License, or (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.
//
//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Threading;

using MonoTorrent.Common;
using MonoTorrent.Client;
using MonoTorrent.BEncoding;
using MonoTorrent.Client.Encryption;
using MonoTorrent.Client.Tracker;
using MonoTorrent.Dht;
using MonoTorrent.Dht.Listeners;
using MonoTorrent;

using uhttpsharp;
using uhttpsharp.Handlers;
using uhttpsharp.Headers;
using uhttpsharp.Listeners;
using uhttpsharp.RequestProviders;
using System.Net.Sockets;
using System.Web;

namespace simpletorrent
{
    class Program
    {
        static void Main(string[] args)
        {
            Program prog = new Program();
            prog.Start();
            prog.Stop();
        }

        ClientEngine engine;
        List<TorrentManager> torrents;
        List<SimpleMessage> messages;

        string dhtNodeFile;
        string torrentsPath;
        string fastResumeFile;
        string downloadsPath;
        DriveInfo downloadsPathDrive;
        TorrentSettings torrentDefaults;

        Dictionary<string, TorrentInformation> torrentInformation = new Dictionary<string, TorrentInformation>();

        void Start()
        {
            //Start Torrent Engine
            torrents = new List<TorrentManager>();
            messages = new List<SimpleMessage>();

            string basePath = Environment.CurrentDirectory;
            dhtNodeFile = Path.Combine(basePath, "DhtNodes");
            torrentsPath = Path.Combine(basePath, @"L:\simpletorrent\Torrents");
            fastResumeFile = Path.Combine(torrentsPath, "fastresume.data");
            downloadsPath = Path.Combine(basePath, @"L:\simpletorrent\Downloads");
            downloadsPathDrive = null;

            foreach (var drive in DriveInfo.GetDrives())
            {
                if (drive.RootDirectory.FullName.ToLower()
                    == Path.GetPathRoot(downloadsPath).ToLower())
                {
                    downloadsPathDrive = drive;
                    break;
                }
            }

            EngineSettings engineSettings = new EngineSettings(downloadsPath, 6888);
            engineSettings.PreferEncryption = true;
            engineSettings.AllowedEncryption = EncryptionTypes.RC4Full;
            engineSettings.GlobalMaxConnections = 500;

            torrentDefaults = new TorrentSettings(4, 500, 0, 0);
            engine = new ClientEngine(engineSettings);
            engine.ChangeListenEndpoint(new IPEndPoint(IPAddress.Any, 6888));

            byte[] nodes = null;
            try
            {
                nodes = File.ReadAllBytes(dhtNodeFile);
            }
            catch
            {
                Console.WriteLine("No existing dht nodes could be loaded");
            }

            DhtListener dhtListner = new DhtListener(new IPEndPoint(IPAddress.Any, 6888));
            DhtEngine dht = new DhtEngine(dhtListner);
            engine.RegisterDht(dht);
            dhtListner.Start();
            engine.DhtEngine.Start(nodes);

            // If the SavePath does not exist, we want to create it.
            if (!Directory.Exists(engine.Settings.SavePath))
                Directory.CreateDirectory(engine.Settings.SavePath);

            // If the torrentsPath does not exist, we want to create it
            if (!Directory.Exists(torrentsPath))
                Directory.CreateDirectory(torrentsPath);

            foreach (var torrent in Directory.GetFiles(torrentsPath, "*.torrent"))
            {
                Torrent t = Torrent.Load(torrent);

                if (engine.Torrents.Where(i => i.InfoHash == t.InfoHash).Count() == 0)
                {
                    TorrentManager tm = new TorrentManager(t, downloadsPath, torrentDefaults);
                    engine.Register(tm);
                    SetupTorrent(tm);
                }
            }

            BEncodedDictionary fastResume;
            try
            {
                fastResume = BEncodedValue.Decode<BEncodedDictionary>(File.ReadAllBytes(fastResumeFile));
            }
            catch
            {
                fastResume = new BEncodedDictionary();
            }

            using (var httpServer = new HttpServer(new HttpRequestProvider()))
            {
                Console.WriteLine("simpletorrent: Starting SSL listener...");
                httpServer.Use(new TcpListenerAdapter(new TcpListener(IPAddress.Any, 82)));
                httpServer.Use(new ListenerSslDecorator(new TcpListenerAdapter(new TcpListener(IPAddress.Any, 4343)), SSLSelfSigned.GenerateSelfSignedCert()));

                Console.WriteLine("simpletorrent: Running...");

                httpServer.Use((context, next) =>
                {
                    context.Response = ProcessRequest(context);

                    return Task.Factory.GetCompleted();
                });

                httpServer.Start();

                Console.ReadLine();
            }
        }
        
        void SetupTorrent(TorrentManager manager)
        {
            // Every time a piece is hashed, this is fired.
            manager.PieceHashed += delegate(object o, PieceHashedEventArgs e)
            {
                var tm = (TorrentManager)o;
                lock (this)
                {
                    if (tm.State != TorrentState.Hashing)
                        Console.WriteLine(string.Format("Piece Hashed: {0} - {1}", e.PieceIndex, e.HashPassed ? "Pass" : "Fail"));
                }
            };

            // Every time the state changes (Stopped -> Seeding -> Downloading -> Hashing) this is fired
            manager.TorrentStateChanged += delegate(object o, TorrentStateChangedEventArgs e)
            {
                var tm = (TorrentManager)o;

                var name = !tm.HasMetadata ? "Magnet" : tm.Torrent.Name;

                lock (this)
                        Console.WriteLine("[{2}] OldState: {0}, NewState: {1}",
                            e.OldState.ToString(), e.NewState.ToString(),
                            name);

                if (e.NewState == TorrentState.Stopped)
                {
                    try
                    {
                        var ti = torrentInformation[tm.InfoHash.ToHex()];
                        if (ti.ToRemove != null)
                        {
                            if (tm.HasMetadata && tm.Torrent != null)
                            {
                                File.Delete(tm.Torrent.TorrentPath);
                            }
                            engine.Unregister(tm);
                            torrentInformation.Remove(manager.InfoHash.ToHex());
                        }

                        if (ti.ToRemove == "delete-torrent-and-data")
                        {
                            if (Directory.Exists(tm.SavePath + "\\" + tm.Torrent.Name))
                            {
                                Directory.Delete(tm.SavePath + "\\" + tm.Torrent.Name, true);
                            }
                            else
                            {
                                File.Delete(tm.SavePath + "\\" + tm.Torrent.Name);
                            }
                        }
                    }
                    catch
                    {

                    }
                }
                else
                {
                    try
                    {
                        var ti = torrentInformation[tm.InfoHash.ToHex()];
                        ti.CreationDateTime = File.GetCreationTime(tm.Torrent.TorrentPath);
                    }
                    catch
                    {

                    }
                }
            };

            // Every time the tracker's state changes, this is fired
            foreach (TrackerTier tier in manager.TrackerManager)
            {
                foreach (MonoTorrent.Client.Tracker.Tracker t in tier.Trackers)
                {
                    t.AnnounceComplete += delegate(object sender, AnnounceResponseEventArgs e)
                    {
                        Console.WriteLine(string.Format("{0}: {1}", e.Successful, e.Tracker.ToString()));
                    };
                }
            }

            try
            {
                torrentInformation.Remove(manager.InfoHash.ToHex());
            }
            catch
            {

            }

            TorrentInformation nTi = new TorrentInformation();

            try
            {
                nTi.CreationDateTime = File.GetCreationTime(manager.Torrent.TorrentPath);
            }
            catch
            {

            }

            torrentInformation.Add(manager.InfoHash.ToHex(), nTi);

            // Start the torrentmanager. The file will then hash (if required) and begin downloading/seeding
            manager.Start();
        }

        void Stop()
        {
            File.WriteAllBytes(dhtNodeFile, engine.DhtEngine.SaveNodes());

            BEncodedDictionary fastResume = new BEncodedDictionary();
            for (int i = 0; i < torrents.Count; i++)
            {
                torrents[i].Stop();
                try
                {
                    long count = 0;
                    while (torrents[i].State != TorrentState.Stopped && count < 5000)
                    {
                        Console.WriteLine("{0} is {1}", torrents[i].Torrent.Name, torrents[i].State);
                        count += 250;
                        Thread.Sleep(250);
                    }
                }
                catch
                {
                }

                fastResume.Add(torrents[i].Torrent.InfoHash.ToHex(), torrents[i].SaveFastResume().Encode());
            }

            File.WriteAllBytes(fastResumeFile, fastResume.Encode());
            engine.Dispose();
            System.Threading.Thread.Sleep(2000);
        }

        HttpResponse ProcessRequest(IHttpContext context)
        {
            string diskPath = context.Request.Uri.OriginalString.TrimStart('/').Replace("/", @"\");
            Console.WriteLine("Requesting: {0}", diskPath);

            if (diskPath == "simple.potato")
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                sb.Append("<simpletorrent>");

                sb.Append(string.Format("<dht>{0}</dht>", engine.DhtEngine.TotalNodes));

                long freeSpace = -1;

                if (downloadsPathDrive != null)
                {
                    freeSpace = downloadsPathDrive.AvailableFreeSpace;
                }

                sb.Append(string.Format("<freespace>{0}</freespace>", freeSpace));

                foreach (var manager in engine.Torrents)
                {
                    var ti = torrentInformation[manager.InfoHash.ToHex()];

                    bool metaDataMode = manager.Torrent == null;
                    sb.Append("<torrent>");
                    sb.Append(string.Format("<state>{0}</state>", manager.State.ToString()));
                    sb.Append(string.Format("<name{0}>{1}</name>", metaDataMode ? " MetaDataMode=\"true\"" : "", 
                        metaDataMode ? "" : WebUtility.HtmlEncode(manager.Torrent.Name)));
                    sb.Append(string.Format("<size>{0}</size>", metaDataMode ? -1 : manager.Torrent.Size));
                    sb.Append(string.Format("<progress>{0}</progress>", manager.Progress));
                    sb.Append(string.Format("<download>{0}</download>", manager.Monitor.DownloadDataSpeed));
                    sb.Append(string.Format("<upload>{0}</upload>", manager.Monitor.UploadDataSpeed));
                    sb.Append(string.Format("<leech>{0}</leech>", manager.Peers.Leechs));
                    sb.Append(string.Format("<seed>{0}</seed>", manager.Peers.Seeds));
                    sb.Append(string.Format("<infohash>{0}</infohash>", manager.InfoHash.ToHex()));

                    if (ti.CreationDateTime.HasValue)
                    {
                        sb.Append(string.Format("<starttime>{0}</starttime>", 
                            ti.CreationDateTime.Value.ToJavaScriptMilliseconds().ToString()));
                        sb.Append(string.Format("<starttimeago>{0}</starttimeago>",
                            Math.Floor((DateTime.Now - ti.CreationDateTime.Value).TotalMilliseconds).ToString()));
                    }

                    sb.Append("</torrent>");
                }

                lock (messages)
                {
                    foreach (var message in messages)
                    {
                        sb.Append("<message>");
                        sb.Append(string.Format("<title>{0}</title>", WebUtility.HtmlEncode(message.Title)));
                        sb.Append(string.Format("<payload>{0}</payload>", WebUtility.HtmlEncode(message.Message)));
                        sb.Append(string.Format("<type>{0}</type>", WebUtility.HtmlEncode(message.Type.ToString())));
                        sb.Append(string.Format("<id>{0}</id>", WebUtility.HtmlEncode(Guid.NewGuid().ToString("N"))));
                        sb.Append("</message>");
                    }

                    messages.Clear();
                }

                sb.Append("</simpletorrent>");

                return new HttpResponse("text/plain", new MemoryStream(Encoding.UTF8.GetBytes(sb.ToString())),
                    context.Request.Headers.KeepAliveConnection());
            }
            else if (diskPath == "simple-action.potato")
            {
                try
                {
                    var data = Encoding.UTF8.GetString(context.Request.Post).Split(new string[] { ":" }, 2, StringSplitOptions.None);
                    var action = data[0].ToLower();
                    var payload = data[1];

                    if (action == "add-torrent-links")
                    {
                        foreach (var i in payload.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            try
                            {
                                if (i.Trim().Length > 0)
                                {
                                    if (i.StartsWith("magnet"))
                                    {
                                        MagnetLink ml = new MagnetLink(i);
                                        if (engine.Torrents.Where(torrent => torrent.InfoHash == ml.InfoHash).Count() == 0)
                                        {
                                            TorrentManager tm = new TorrentManager(ml, downloadsPath, torrentDefaults, torrentsPath);
                                            engine.Register(tm);
                                            SetupTorrent(tm);
                                        }
                                    }
                                    else
                                    {
                                        var guid = torrentsPath + @"\" + Guid.NewGuid().ToString("N") + ".torrent";
                                        Torrent t = Torrent.Load(new Uri(i), guid);
                                        if (engine.Torrents.Where(torrent => torrent.InfoHash == t.InfoHash).Count() == 0)
                                        {
                                            TorrentManager tm = new TorrentManager(t, downloadsPath, torrentDefaults);
                                            engine.Register(tm);
                                            SetupTorrent(tm);
                                        }
                                        else
                                        {
                                            try
                                            {
                                                System.Threading.Thread.Sleep(100);
                                                File.Delete(guid);
                                            }
                                            catch
                                            {

                                            }
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                new SimpleMessage()
                                {
                                    Message = ex.ToString(),
                                    Type = SimpleMessageType.Exception,
                                    Title = "Exception: add-torrent-links"
                                }.AddMessage(messages);
                            }
                        }
                    }
                    else if (action == "delete-torrent")
                    {
                        try
                        {
                            var torrent = engine.Torrents.Where(a => a.InfoHash.ToHex().ToLower()
                                == payload.ToLower().Trim()).First();
                            File.WriteAllBytes(dhtNodeFile, engine.DhtEngine.SaveNodes());
                            var ti = torrentInformation[torrent.InfoHash.ToHex()];
                            ti.ToRemove = "delete-torrent";
                            torrent.Stop();
                        }
                        catch (Exception ex)
                        {
                            new SimpleMessage()
                            {
                                Message = ex.ToString(),
                                Type = SimpleMessageType.Exception,
                                Title = "Exception: delete-torrent"
                            }.AddMessage(messages);
                        }
                    }
                    else if (action == "delete-torrent-and-data")
                    {
                        try
                        {
                            var torrent = engine.Torrents.Where(a => a.InfoHash.ToHex().ToLower()
                                == payload.ToLower().Trim()).First();
                            File.WriteAllBytes(dhtNodeFile, engine.DhtEngine.SaveNodes());
                            var ti = torrentInformation[torrent.InfoHash.ToHex()];
                            ti.ToRemove = "delete-torrent-and-data";
                            torrent.Stop();
                        }
                        catch (Exception ex)
                        {
                            new SimpleMessage()
                            {
                                Message = ex.ToString(),
                                Type = SimpleMessageType.Exception,
                                Title = "Exception: delete-torrent"
                            }.AddMessage(messages);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("EXCEPTY: {0}", ex.ToString());
                }
            }
            else
            {
                if (File.Exists(@"web\" + diskPath))
                {
                    var mime = new Dictionary<string, string>
                            {
                                {".css", "text/css"},
                                {".gif", "image/gif"},
                                {".htm", "text/html"},
                                {".html", "text/html"},
                                {".jpg", "image/jpeg"},
                                {".js", "application/javascript"},
                                {".png", "image/png"},
                                {".xml", "application/xml"},
                                {".svg", "image/svg+xml"}
                            };

                    var mimetype = "text/plain";
                    mime.TryGetValue(Path.GetExtension(diskPath), out mimetype);

                    return new HttpResponse(mimetype, File.OpenRead(@"web\" + diskPath),
                        context.Request.Headers.KeepAliveConnection());
                }
            }

            return new HttpResponse(HttpResponseCode.Ok, "", context.Request.Headers.KeepAliveConnection());
        }

        void WriteToStream(Stream stream, string s)
        {
            byte[] b = System.Text.UTF8Encoding.UTF8.GetBytes(s);
            stream.Write(b, 0, b.Length);
        }

        enum SimpleMessageType
        {
            Exception,
            Informational
        }

        struct SimpleMessage
        {
            public string Title;
            public string Message;
            public SimpleMessageType Type;
            public string id;

            public void AddMessage(List<SimpleMessage> lsm)
            {
                lock (lsm)
                {
                    lsm.Add(this);
                }
            }
        }

        class TorrentInformation
        {
            public DateTime? CreationDateTime;
            public string ToRemove;

            public TorrentInformation()
            {
                CreationDateTime = null;
                ToRemove = null;
            }
        }
    }
}
