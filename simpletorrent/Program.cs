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
using System.Net.Sockets;
using System.Web;

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

namespace simpletorrent
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                bool startMainApp = true;

                NDesk.Options.OptionSet p = new NDesk.Options.OptionSet()
                    .Add("p", pass =>
                    {
                        startMainApp = false;
                        SimpleConfiguration config = null;

                        try
                        {
                            config = new SimpleConfiguration("simple.cfg");
                            if (!config.HasValue("SimpleSalt")) throw new Exception();
                        }
                        catch
                        {
                            Console.WriteLine("simpletorrent: ERROR! Either \"simple.cfg\" does not exist, or the SimpleSalt value has not been defined."
                                + " Please fix this issue before creating a password.");
                            return;
                        }

                        Console.Write("Password (Press enter when done): ");
                        string password = Utilities.ReadLine();

                        Console.WriteLine("simpletorrent: Benchmarking SCrypt...");
                        int its;
                        Utilities.SCryptBenchmark(out its);
                        Console.WriteLine();

                        Console.WriteLine(its + ":" + Convert.ToBase64String(
                            Org.BouncyCastle.Crypto.Generators.SCrypt.Generate(Encoding.UTF8.GetBytes(password),
                            Encoding.UTF8.GetBytes(config.GetValue("SimpleSalt")), its, 8, 1, 32)));
                    });
                p.Parse(args);

                if (startMainApp)
                {
                    Program prog = new Program();
                    prog.Start();
                    prog.Stop();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Console.WriteLine("==============================\n");
                Console.WriteLine("Message: {0}", ex.Message);
                Console.ReadLine();
            }
        }

        SimpleTorrentOperatingMode simpleOperatingSystem;
        DebugWriter debugWriter;

        ClientEngine engine;
        List<TorrentManager> torrents;
        List<SimpleMessage> messages;
        SimpleConfiguration config;

        System.Timers.Timer seedingLimitTimer; 
        List<Tuple<DateTime, TorrentManager>> seedingLimitTorrents;

        string dhtNodeFile;
        string torrentsPath;
        string fastResumeFile;
        string downloadsPath;
        string sslCertificatePath;
        bool useECDSA = false;
        bool requireProtocolEncryption = false;
        DriveInfo downloadsPathDrive;
        TorrentSettings torrentDefaults;

        int sessionLimit;
        int? seedingLimit;

        readonly string VERSION = "v0.41 ('counteraction rising')";

        Dictionary<string, TorrentInformation> torrentInformation = new Dictionary<string, TorrentInformation>();

        void Start()
        {
            //Start Torrent Engine
            torrents = new List<TorrentManager>();
            messages = new List<SimpleMessage>();

            //Torrents to remove
            seedingLimitTorrents = new List<Tuple<DateTime, TorrentManager>>();

            Console.WriteLine("simpletorrent: version {0}", VERSION);
            Console.WriteLine("simpletorrent: Reading configuration file (simple.cfg)...");

            config = new SimpleConfiguration("simple.cfg");
            string basePath = Path.GetDirectoryName(System.Reflection.Assembly.GetEntryAssembly().Location);
            Console.WriteLine("simpletorrent: ApplicationPath (derived) {0}", basePath);

            if (config.HasValue("Debug"))
            {
                debugWriter = new DebugWriter(true);
                Console.WriteLine("simpletorrent: Debugging Enabled!");
            }
            else
            {
                debugWriter = new DebugWriter(false);
            }

            PlatformID os = Environment.OSVersion.Platform;

            if (os == PlatformID.MacOSX)
            {
                Console.WriteLine("simpletorrent: We think we're on MacOSX");
                simpleOperatingSystem = SimpleTorrentOperatingMode.MacOSX;
            }
            else if (os == PlatformID.Unix)
            {
                Console.WriteLine("simpletorrent: We think we're on *nix");
                simpleOperatingSystem = SimpleTorrentOperatingMode.StarNix;
            }
            else
            {
                Console.WriteLine("simpletorrent: We think we're on Windows");
                simpleOperatingSystem = SimpleTorrentOperatingMode.Windows;
            }
            
            torrentsPath = Path.GetFullPath(config.GetValue("TorrentPath", Path.Combine(basePath, "Torrents")));
            downloadsPath = Path.GetFullPath(config.GetValue("DownloadPath", Path.Combine(basePath, "Downloads")));
            sslCertificatePath = Path.GetFullPath(config.GetValue("SslCertificatePath", Path.Combine(basePath, "simple.pfx")));
            useECDSA = config.HasValue("SslCertificateECDSA");
            fastResumeFile = Path.Combine(torrentsPath, "fastresume.data");
            dhtNodeFile = Path.Combine(torrentsPath, "dht.data");

            requireProtocolEncryption = config.HasValue("RequireProtocolEncryption");

            sessionLimit = config.GetValueInt("SessionLimit", 20);
            seedingLimit = config.GetValueInt("SeedingLimit");

            // If the SavePath does not exist, we want to create it.
            if (!Directory.Exists(downloadsPath))
                Directory.CreateDirectory(downloadsPath);

            // If the torrentsPath does not exist, we want to create it
            if (!Directory.Exists(torrentsPath))
                Directory.CreateDirectory(torrentsPath);
            
            downloadsPathDrive = null;
            string myRootPath = Path.GetPathRoot(downloadsPath).ToLower();

            if (simpleOperatingSystem == SimpleTorrentOperatingMode.StarNix)
            {
                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.EnableRaisingEvents = false;
                proc.StartInfo.FileName = "bash";
                proc.StartInfo.Arguments = "-c \"df -h " + downloadsPath + " | awk '{print $6}' | tail -1\"";
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd().Trim().ToLower();
                proc.WaitForExit();
                
                if (proc.ExitCode == 0)
                {
                    myRootPath = output;
                    debugWriter.WriteLine("*nix override (bash -c 'df -h <path>') - \"" + output + "\"");
                }
            }
            else if (simpleOperatingSystem == SimpleTorrentOperatingMode.MacOSX)
            {
                System.Diagnostics.Process proc = new System.Diagnostics.Process();
                proc.EnableRaisingEvents = false;
                proc.StartInfo.FileName = "bash";
                proc.StartInfo.Arguments = "-c \"df -h " + downloadsPath + " | awk '{print $9}' | tail -1\"";
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.Start();
                string output = proc.StandardOutput.ReadToEnd().Trim().ToLower();
                proc.WaitForExit();

                if (proc.ExitCode == 0)
                {
                    myRootPath = output;
                    debugWriter.WriteLine("*nix override (bash -c 'df -h <path>') - \"" + output + "\"");
                }
            }

            foreach (var drive in DriveInfo.GetDrives())
            {
                debugWriter.WriteLine("Enemerating Drives - " + drive.RootDirectory.FullName.ToString());

                if (drive.RootDirectory.FullName.ToLower()
                    == myRootPath)
                {
                    downloadsPathDrive = drive;
                    break;
                }
            }

            Console.WriteLine("simpletorrent: TorrentPath {0}", torrentsPath);
            Console.WriteLine("simpletorrent: DownloadPath {0}", downloadsPath);
            Console.WriteLine("simpletorrent: DownloadRootPath (derived) {0}", downloadsPathDrive);
            Console.WriteLine("simpletorrent: SslCertificatePath {0}", sslCertificatePath);
            Console.WriteLine("simpletorrent: SslCertificateECDSA {0}", useECDSA ? "Yes" : "No");
            Console.WriteLine("simpletorrent: RequireProtocolEncryption {0}", requireProtocolEncryption ? "Yes" : "No");
            Console.WriteLine("simpletorrent: SessionLimit {0}", sessionLimit);
            Console.WriteLine("simpletorrent: SeedingLimit {0}", seedingLimit.HasValue ? seedingLimit.Value.ToString() : "No");

            int? torrentListenPort = config.GetValueInt("TorrentListenPort");

            if (!torrentListenPort.HasValue)
            {
                throw new SimpleTorrentException("Configuration does not have a proper 'TorrentListenPort' value defined", null);
            }

            Console.WriteLine("simpletorrent: TorrentListenPort {0}", torrentListenPort);

            EngineSettings engineSettings = new EngineSettings(downloadsPath, torrentListenPort.Value);
            engineSettings.PreferEncryption = true;
            engineSettings.AllowedEncryption = requireProtocolEncryption ? EncryptionTypes.RC4Full : EncryptionTypes.All;
            engineSettings.GlobalMaxConnections = 500;

            torrentDefaults = new TorrentSettings(4, 500, 0, 0);
            engine = new ClientEngine(engineSettings);
            engine.ChangeListenEndpoint(new IPEndPoint(IPAddress.Any, torrentListenPort.Value));

            byte[] nodes = null;
            try
            {
                nodes = File.ReadAllBytes(dhtNodeFile);
            }
            catch
            {
                Console.WriteLine("simpletorrent: No existing DHT nodes could be loaded");
            }

            DhtListener dhtListner = new DhtListener(new IPEndPoint(IPAddress.Any, torrentListenPort.Value));
            DhtEngine dht = new DhtEngine(dhtListner);
            engine.RegisterDht(dht);
            dhtListner.Start();
            engine.DhtEngine.Start(nodes);

            foreach (var torrent in Directory.GetFiles(torrentsPath, "*.torrent"))
            {
                Torrent t = Torrent.Load(torrent);

                if (engine.Torrents.Where(i => i.InfoHash == t.InfoHash).Count() == 0)
                {
                    TorrentManager tm = new TorrentManager(t, downloadsPath, torrentDefaults);
                    engine.Register(tm);
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

            if (seedingLimit.HasValue)
            {
                Console.WriteLine("simpletorrent: Starting seeding limits watchdog timer...");
                seedingLimitTimer = new System.Timers.Timer();
                seedingLimitTimer.AutoReset = true;
                seedingLimitTimer.Interval = 60 * 1000;
                seedingLimitTimer.Elapsed += (s, e) =>
                {
                    lock(seedingLimitTorrents)
                    {
                        var torrentsToRemove = seedingLimitTorrents.Where(a => (DateTime.Now - a.Item1).TotalSeconds >= seedingLimit).ToArray();
                        foreach (var i in torrentsToRemove)
                        {
                            try
                            {
                                seedingLimitTorrents.Remove(i);

                                if (i != null && i.Item2.State == TorrentState.Seeding)
                                {
                                    Console.WriteLine("simpletorrent: Automatically removing \"{0}\"...",
                                        i.Item2.Torrent.Name);
                                    torrentInformation[i.Item2.InfoHash.ToHex()].ToRemove = "delete-torrent";
                                    i.Item2.Stop();
                                }
                            }
                            catch
                            {
                            }
                        }
                    }
                };
                seedingLimitTimer.Start();
            }

            using (var httpServer = new HttpServer(new HttpRequestProvider()))
            {
                Console.WriteLine("simpletorrent: Starting HTTP(S) server...");
                bool listeningOne = false;

                Console.WriteLine("simpletorrent: Creating session manager...");
                httpServer.Use(new SessionHandler<SimpleTorrentSession>(() => 
                    new SimpleTorrentSession(), sessionLimit));

                foreach (var ip in config.GetValues("Listen"))
                {
                    try
                    {
                        TcpListener tl = getTcpListener(ip);
                        httpServer.Use(new TcpListenerAdapter(tl));
                        Console.WriteLine("simpletorrent: Listening for HTTP on {0}...", tl.LocalEndpoint);
                        listeningOne = true;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("simpletorrent: ({0}) " + ex.Message, ip);
                    }
                }


                System.Security.Cryptography.X509Certificates.X509Certificate2 cert = null;
                if (config.HasValue("ListenSsl"))
                {
                    cert = SSLSelfSigned.GetCertOrGenerate(sslCertificatePath, useECDSA);
                }

                foreach (var ip in config.GetValues("ListenSsl"))
                {
                    try
                    {
                        TcpListener tl = getTcpListener(ip);
#if MONO
                        httpServer.Use(new ListenerSslDecorator(new TcpListenerAdapter(tl), cert, System.Security.Authentication.SslProtocols.Tls));
#else
                        httpServer.Use(new ListenerSslDecorator(new TcpListenerAdapter(tl), cert, System.Security.Authentication.SslProtocols.Tls11 
                            | System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls));
#endif


                        Console.WriteLine("simpletorrent: Listening for HTTPS on {0}...", tl.LocalEndpoint);
                        listeningOne = true;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("simpletorrent: ({0}) " + ex.Message, ip);
                    }
                }

                if (!listeningOne)
                {
                    throw new SimpleTorrentException("simpletorrent was unable to bind to a single port.");
                }

                Console.WriteLine("simpletorrent: Running...");

                httpServer.Use((context, next) =>
                {
                    context.Response = ProcessRequest(context);

                    return Task.Factory.GetCompleted();
                });

                foreach (var tm in engine.Torrents)
                {
                    SetupTorrent(tm);
                }

                httpServer.Start();

                Console.ReadLine();
            }
        }

        TcpListener getTcpListener(string ipPortPair)
        {
            int port;
            IPAddress ip;

            try
            {
                int portPos = ipPortPair.LastIndexOf(":");
                port = int.Parse(ipPortPair.Substring(portPos + 1));
                ip = IPAddress.Parse(ipPortPair.Substring(0, portPos));
            }
            catch
            {
                throw new SimpleTorrentException("Unable to parse ip/port: " + ipPortPair);
            }

            return new TcpListener(ip, port);
        }
        
        void SetupTorrent(TorrentManager manager)
        {
            // Every time a piece is hashed, this is fired.
            manager.PieceHashed += delegate(object o, PieceHashedEventArgs e)
            {
                var tm = (TorrentManager)o;
                /*lock (this)
                {
                    if (tm.State != TorrentState.Hashing)
                        Console.WriteLine(string.Format("Piece Hashed: {0} - {1}", e.PieceIndex, e.HashPassed ? "Pass" : "Fail"));
                }*/
            };

            // Every time the state changes (Stopped -> Seeding -> Downloading -> Hashing) this is fired
            manager.TorrentStateChanged += delegate(object o, TorrentStateChangedEventArgs e)
            {
                var tm = (TorrentManager)o;

                var name = !tm.HasMetadata ? "Magnet" : tm.Torrent.Name;

                lock (this)
                        Console.WriteLine("simpletorrent: [{1}] {0}",
                            e.NewState.ToString(), name);

                lock (seedingLimitTorrents)
                {
                    if (e.NewState == TorrentState.Seeding && seedingLimit.HasValue
                        && seedingLimitTorrents.Where(a => a.Item2 == tm).Count() == 0)
                    {
                        Console.WriteLine("simpletorrent: Queuing \"{0}\" for automatic removal...", name);
                        seedingLimitTorrents.Add(new Tuple<DateTime, TorrentManager>(DateTime.Now, tm));
                    }
                }

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
                            System.Threading.Thread.Sleep(200);
                            if (Directory.Exists(Path.Combine(tm.SavePath, tm.Torrent.Name)))
                            {
                                Directory.Delete(Path.Combine(tm.SavePath, tm.Torrent.Name), true);
                            }
                            else
                            {
                                File.Delete(Path.Combine (tm.SavePath, tm.Torrent.Name));
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        debugWriter.WriteLine("Exception when attempting to stop torrent: " + ex.ToString());
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
                        //Console.WriteLine(string.Format("{0}: {1}", e.Successful, e.Tracker.ToString()));
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
            string diskPath = context.Request.Uri.OriginalString.TrimStart('/');
            //Console.WriteLine("Requesting: {0}", diskPath);

            SimpleTorrentSession mySession = ((SimpleTorrentSession)context.State.Session);

            if (mySession != null && !((SimpleTorrentSession)context.State.Session).LoggedIn)
            {
                if (diskPath == "simple.potato" || diskPath == "simple-action.potato")
                {
                    if (diskPath == "simple-action.potato")
                    {
                        try
                        {
                            var data = Encoding.UTF8.GetString(context.Request.Post).Split(new string[] { ":" }, 2, StringSplitOptions.None);
                            var action = data[0].ToLower();
                            var payload = data[1];

                            if (action == "login")
                            {
                                //<username>:<pass>
                                var loginPair = payload.Split(new string[] { ":" }, 2, StringSplitOptions.None);

                                foreach (var i in config.GetValues("SimpleUser"))
                                {
                                    //<username>:<scrypt N>:<32-byte scrypt output>
                                    var configPair = i.Split(new string[] { ":" }, 3, StringSplitOptions.None);
                                    
                                    if (loginPair[0].ToLower() == configPair[0].ToLower())
                                    {
                                        string calculatedHash = 
                                            Convert.ToBase64String(Org.BouncyCastle.Crypto.Generators.SCrypt.Generate(Encoding.UTF8.GetBytes(loginPair[1]),
                                                Encoding.UTF8.GetBytes(config.GetValue("SimpleSalt")),
                                                int.Parse(configPair[1]), 8, 1, 32));

                                        if (configPair[2] == calculatedHash)
                                        {
                                            mySession.LoggedIn = true;
                                            mySession.Username = configPair[0];
                                            Console.WriteLine("simpletorrent: Login succeeded for {0}...", loginPair[0]);
                                            return new HttpResponse(HttpResponseCode.Ok, "OK", context.Request.Headers.KeepAliveConnection());
                                        }

                                        break;
                                    }
                                }

                                if (!mySession.LoggedIn)
                                {
                                    Console.WriteLine("simpletorrent: Failed login for {0}...", loginPair[0]);

                                    //Sleep to make brute force infeasable
                                    System.Threading.Thread.Sleep(1000);
                                    return new HttpResponse("text/plain; charset=utf-8",
                                                new MemoryStream(Encoding.UTF8.GetBytes("NO")),
                                                context.Request.Headers.KeepAliveConnection());
                                }
                            }
                        }
                        catch { }
                    }

                    return new HttpResponse("text/plain; charset=utf-8",
                            new MemoryStream(Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><simpletorrent Login=\"None\" />")),
                            context.Request.Headers.KeepAliveConnection());
                }
            }

            if (mySession == null)
            {
                return new HttpResponse("text/plain; charset=utf-8",
                            new MemoryStream(Encoding.UTF8.GetBytes("<?xml version=\"1.0\" encoding=\"UTF-8\"?><simpletorrent Login=\"None\" />")),
                            context.Request.Headers.KeepAliveConnection());
            }

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
                    foreach (var message in messages.Where(a => a.id == mySession.ID))
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

                return new HttpResponse("text/plain; charset=utf-8", new MemoryStream(Encoding.UTF8.GetBytes(sb.ToString())),
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
                                    Title = "Exception: add-torrent-links",
                                    id = mySession.ID
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
                                Title = "Exception: delete-torrent",
                                id = mySession.ID
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
                                Title = "Exception: delete-torrent",
                                id = mySession.ID
                            }.AddMessage(messages);
                        }
                    }
                    else if (action == "logout")
                    {
                        Console.WriteLine("simpletorrent: Logout succeeded for {0}...", mySession.Username);
                        mySession.LoggedIn = false;
                        mySession.Username = null;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine("EXCEPTY: {0}", ex.ToString());
                }
            }
            else
            {
                if (diskPath.Trim() == ""
                    || !File.Exists(Path.Combine(@"web", diskPath)))
                {
                    diskPath = "simple.htm";
                }

                if (File.Exists(Path.Combine(@"web", diskPath)))
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

                    return new HttpResponse(mimetype, File.OpenRead(Path.Combine(@"web", diskPath)),
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

        class SimpleTorrentSession : Session
        {
            public bool LoggedIn;
            public string Username;

            public string ID { get; set; }
            public DateTime LastAccessTime { get; set; }
            public IPEndPoint EndPoint { get; set; }

            public void CloseSession()
            {
                Console.WriteLine("simpletorrent: Removing expired session for ({0}{1})...", EndPoint.Address,
                    LoggedIn && Username != null ? "/" + Username : "");
            }
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

        public class SimpleTorrentException : Exception
        {
            public SimpleTorrentException(string exception)
                : base(exception)
            {

            }

            public SimpleTorrentException(string exception, Exception innerException)
                : base(exception, innerException)
            {

            }
        }

        enum SimpleTorrentOperatingMode
        {
            Windows,
            StarNix,
            MacOSX
        }
    }

    class DebugWriter
    {
        bool debug;

        public DebugWriter(bool debug)
        {
            this.debug = debug;
        }

        public void WriteLine(string debugInfo)
        {
            if (debug)
            {
                Console.WriteLine("simpletorrent: (DEBUG) " + debugInfo);
            }
        }
    }
}
