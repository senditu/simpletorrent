//
//  ConfigurationParser.cs
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

using System.IO;

namespace simpletorrent
{
    class SimpleConfiguration
    {
        Dictionary<string, LinkedList<string>> mainDictionary;

        public SimpleConfiguration(string path)
        {
            FileStream fs = null;

            try
            {
                fs = new FileStream(path, FileMode.Open, FileAccess.Read);
                InitializeFromStream(fs);
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                try
                {
                    fs.Dispose();
                }
                catch
                {

                }
            }
        }

        public SimpleConfiguration(Stream stream)
        {
            InitializeFromStream(stream);
        }

        void InitializeFromStream(Stream stream)
        {
            mainDictionary 
                = new Dictionary<string, LinkedList<string>>();
            int lineNumber = 0;

            StreamReader sr = new StreamReader(stream);
            try
            {
                while (sr.Peek() != -1)
                {
                    lineNumber++;
                    var line = sr.ReadLine().TrimStart();
                    if (line.StartsWith("#"))
                    {
                        //Comment
                    }
                    else if (line.Trim().Length == 0)
                    {
                        //Empty string
                    }
                    else
                    {
                        var valuePair = line.Split(null, 2);

                        if (valuePair.Length < 2)
                        {
                            AddKeyValuePair(valuePair[0].Trim(), "");
                        }
                        else
                        {
                            var key = valuePair[0].Trim();
                            var value = valuePair[1].Trim();
                            AddKeyValuePair(key, value);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new SimpleConfigurationException("Error parsing configuration file: Line " + lineNumber.ToString(), ex);
            }
        }

        public string GetValue(string key)
        {
            LinkedList<string> lls;
            if (mainDictionary.TryGetValue(key, out lls))
            {
                return lls.First.Value;
            }
            else
            {
                return null;
            }
        }

        public string GetValue(string key, string defaultValue)
        {
            string value = GetValue(key);
            if (value == null)
            {
                return defaultValue;
            }
            else
            {
                return value;
            }
        }

        public int? GetValueInt(string key)
        {
            try
            {
                return int.Parse(GetValue(key));
            }
            catch
            {
                return null;
            }
        }

        public int GetValueInt(string key, int defaultValue)
        {
            try
            {
                return int.Parse(GetValue(key));
            }
            catch
            {
                return defaultValue;
            }
        }

        public IEnumerable<string> GetValues(string key)
        {
            LinkedList<string> lls;
            if (mainDictionary.TryGetValue(key, out lls))
            {
                return lls;
            }

            return new string[] { };
        }

        public bool HasValue(string key)
        {
            return mainDictionary.ContainsKey(key);
        }

        void AddKeyValuePair(string key, string value)
        {
            LinkedList<string> lls;
            if (mainDictionary.TryGetValue(key, out lls))
            {
                lls.AddLast(value);
            }
            else
            {
                lls = new LinkedList<string>();
                lls.AddLast(value);
                mainDictionary.Add(key, lls);
            }
        }

        public class SimpleConfigurationException : Exception
        {
            public SimpleConfigurationException(string exception, Exception innerException)
                : base(exception, innerException)
            {

            }
        }
    }
}
