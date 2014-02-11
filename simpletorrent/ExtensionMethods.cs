using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace simpletorrent
{
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
