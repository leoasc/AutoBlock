using System;
using System.Collections.Generic;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

namespace AutoBlock
{
    class Program
    {
        static int checkIntervalSeconds = 0;
        static List<Record> records = new List<Record>();
        static Dictionary<int, int> BlockSettings = new Dictionary<int, int>();
        static string RuleName = "AutoBlock";
        static ushort Port = 0;
        static void Main(string[] args)
        {

            Console.WriteLine("Reading configs ...");
            int.TryParse(ConfigurationManager.AppSettings["checkIntervalSeconds"],out checkIntervalSeconds);
            Console.WriteLine($"check interval:{checkIntervalSeconds} seconds");
            
            RuleName = ConfigurationManager.AppSettings["ruleName"];
            Console.WriteLine($"fire wall rule name:{RuleName}");
            ushort.TryParse(ConfigurationManager.AppSettings["port"], out Port);
            Console.WriteLine($"fire wall rule port:{Port}");
            Console.WriteLine("block settings:");
            var allKeys = ConfigurationManager.AppSettings.AllKeys.Where(i => i.StartsWith("block"));
            if (allKeys != null && allKeys.Any())
            {
                foreach (var key in allKeys)
                {
                    int.TryParse(key.Replace("block", ""), out int range);
                    if (range > 0)
                    {
                        int.TryParse(ConfigurationManager.AppSettings.Get(key), out int threshold);
                        BlockSettings.Add(range, threshold);
                        Console.WriteLine($"time range:{range} seconds,block threshold:{threshold}");
                    }
                }
            }
            Console.WriteLine("config loaded,auto block is online.");
            while (true)
            {                
                try
                {
                    ReadLog();
                    CheckAndBlock();
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
                System.Threading.Thread.Sleep(checkIntervalSeconds * 1000);
            }
            Console.ReadLine();
        }

        private static void ReadLog()
        {
            EventLogEntry entry;
            var startTime = DateTime.Now.AddSeconds(-1*checkIntervalSeconds);
            Dictionary<string, int> ipCount = new Dictionary<string, int>();
            
            EventLog eventLog = new EventLog("Security");
            for (int i = eventLog.Entries.Count - 1; i >= 0; i--)
            {
                entry = eventLog.Entries[i];
                if (entry.TimeWritten < startTime)
                    break;
                if (eventLog.Entries[i].InstanceId == 4625)
                {
                    string pattern = "((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}";
                    var ip = Regex.Match(entry.Message, pattern).Value;
                    if (string.IsNullOrEmpty(ip))
                        continue;
                    if (!ipCount.ContainsKey(ip))
                        ipCount[ip] = 1;
                    else
                        ipCount[ip]++;
                }
            }
            
            foreach (var kv in ipCount)
                records.Add(new Record { Ip = kv.Key,Count = kv.Value,Time = DateTime.Now });


        }

        static void CheckAndBlock()
        {
            var ips = new List<string>();
            var blockedIp = new List<string>();
            var overTime = DateTime.Now.AddSeconds(-1 * BlockSettings.Keys.Max());
            records.RemoveAll(i => i.Time < overTime);
            
            foreach (var kv in BlockSettings)
            {
                var countByIP = records.Where(i => i.Time > DateTime.Now.AddSeconds(-1 * kv.Key)).GroupBy(i => i.Ip).Select(g => new{ip = g.Key, total = g.Sum(i => i.Count) });
                foreach (var record in countByIP)
                {
                    if (record.total > kv.Value && !ips.Contains(record.ip))
                    {
                        Console.WriteLine($"{DateTime.Now}: block IP：{record.ip},attack times:{record.total},by rule：block{kv.Key}:{kv.Value}");
                        ips.Add(record.ip);
                        records.RemoveAll(i => i.Ip == record.ip);
                    }
                }                
            }
            if(ips.Count>0)
                Firewall.AddFirewallRule(RuleName, Port, ips);            
        }
    }
}
