//
//  SessionManager.cs
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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Timers;
using uhttpsharp;

namespace simpletorrent
{
    internal interface Session
    {
        string ID { get; set; }
        DateTime LastAccessTime { get; set; }
        IPEndPoint EndPoint { get; set; }
        void CloseSession();
    }

    internal class SessionHandler<TSession> : IHttpRequestHandler
        where TSession : Session
    {
        private readonly Func<TSession> _sessionFactory;
        private readonly RNGCryptoServiceProvider random 
            = new RNGCryptoServiceProvider();

        Timer cleanupTimer;

        private readonly ConcurrentDictionary<string, TSession> _sessions = new ConcurrentDictionary<string, TSession>();

        public SessionHandler(Func<TSession> sessionFactory, int sessionExpireMinutes)
        {
            _sessionFactory = sessionFactory;
            cleanupTimer = new Timer();
            cleanupTimer.AutoReset = true;
            cleanupTimer.Interval = 60 * 1000;
            cleanupTimer.Elapsed += (s, e) =>
                {
                    lock (this)
                    {
                        var expiredSessions = _sessions.Where(a => (DateTime.Now - a.Value.LastAccessTime).TotalMinutes >= sessionExpireMinutes).ToArray();

                        foreach (var i in expiredSessions)
                        {
                            TSession l;
                            if (_sessions.TryRemove(i.Key, out l))
                            {
                                l.CloseSession();
                            }

                        }
                    }
                };
            Console.WriteLine("simpletorrent: Starting session watchdog timer...");
            cleanupTimer.Start();
        }

        public System.Threading.Tasks.Task Handle(IHttpContext context, Func<System.Threading.Tasks.Task> next)
        {
            string sessId = null;
            string userAgent = null;

            lock (this)
            {
                if (context.Request.Headers.TryGetByName("User-Agent", out userAgent))
                {
                    if (!context.Cookies.TryGetByName("simple-id", out sessId)
                        || (sessId != null && !_sessions.ContainsKey(sessId)))
                    {
                        byte[] key = new byte[24];

                        do
                        {
                            random.GetBytes(key);
                            sessId = Convert.ToBase64String(key).ToLower().Replace("/", "").Replace("=", "");
                        } while (_sessions.ContainsKey(sessId));

                        context.Cookies.Upsert("simple-id", sessId);
                        Console.WriteLine("simpletorrent: Generated new session for ({0})...", ((IPEndPoint)context.Request.RemoteEndPoint).Address);
                    }
                }

                if (sessId != null)
                {
                    var session = _sessions.GetOrAdd(sessId, CreateSession);
                    session.LastAccessTime = DateTime.Now;
                    session.ID = sessId;
                    session.EndPoint = (IPEndPoint)context.Request.RemoteEndPoint;
                    context.State.Session = session;
                }
                else
                {
                    context.State.Session = null;
                }
            }

            return next();
        }
        private TSession CreateSession(string sessionId)
        {
            return _sessionFactory();
        }
    }
}
