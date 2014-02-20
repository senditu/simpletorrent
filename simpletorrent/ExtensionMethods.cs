//
// ExtensionMethods.cs
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
using System.Text;
using System.Threading.Tasks;

namespace simpletorrent
{
    public static class Utilities
    {
        static Random r = new Random();

        public static string ReadLine()
        {
            ConsoleKeyInfo inf;
            StringBuilder input = new StringBuilder();
            
            inf = Console.ReadKey(true);
            
            while (inf.Key != ConsoleKey.Enter)
            {
                input.Append(inf.KeyChar);
                inf = Console.ReadKey(true);
            }

            Console.WriteLine();

            return input.ToString();
        }

        public static void SCryptBenchmark(out int iterations)
        {
            int it = 16000;
            double mils = 0;

            do
            {
                it += r.Next(1000, 2000);
                DateTime start = DateTime.Now;
                for (int i = 0; i < 3; i++)
                {
                    Org.BouncyCastle.Crypto.Generators.SCrypt.Generate(Encoding.UTF8.GetBytes("abcd"),
                                Encoding.UTF8.GetBytes("abcd"), it, 8, 1, 24);
                }
                mils = (DateTime.Now - start).TotalMilliseconds / 3d;
            } while (mils < 350);

            iterations = it;
        }
    }

    public static class DateTimeExtensions
    {
        private static readonly long DatetimeMinTimeTicks =
            (new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).Ticks;

        public static long ToJavaScriptMilliseconds(this DateTime dateTime)
        {
            return (long)((dateTime.ToUniversalTime().Ticks - DatetimeMinTimeTicks) / 10000);
        }
    }
}
