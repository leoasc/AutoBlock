using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using WindowsFirewallHelper;
using WindowsFirewallHelper.Addresses;
using WindowsFirewallHelper.FirewallRules;

namespace AutoBlock
{
    class Firewall
    {
        public static void AddFirewallRule(string name,ushort port,IList<string> ips)
        {
            FirewallWASRule rule = (FirewallWASRule)FirewallManager.Instance.Rules.FirstOrDefault(r => r.Name == name);
            if (rule == null) // if no rule,create one
            {
                rule = new FirewallWASRule(
                    name,
                    port,
                    FirewallAction.Block,
                    FirewallDirection.Inbound,
                    FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public
                )
                {
                    Description = "test rule",
                    Protocol = FirewallProtocol.TCP
                };
                var addressList = new List<IAddress>();
                foreach (var ip in ips)
                {
                    addressList.Add(new SingleIP(IPAddress.Parse(ip)));
                }
                rule.RemoteAddresses = addressList.ToArray();
                FirewallWAS.Instance.Rules.Add(rule); // add new rule
            }
            else // if rule exists, inherit blocked ips
            {
                var ruleNew = new FirewallWASRule(
                    name,
                    port,
                    FirewallAction.Block,
                    FirewallDirection.Inbound,
                    FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public
                )
                {
                    Description = "test rule",
                    Protocol = FirewallProtocol.TCP
                };
                
                var addressList = new List<IAddress>();
                if (rule.RemoteAddresses != null)
                    addressList = rule.RemoteAddresses.ToList();
                var ipsOld = rule.RemoteAddresses.Select(i => i.ToString());
                foreach (var ip in ips)
                {
                    if (!ipsOld.Contains(ip))
                    {
                        addressList.Add(new SingleIP(IPAddress.Parse(ip)));
                    }
                }
                rule.RemoteAddresses = addressList.ToArray();
                FirewallWAS.Instance.Rules.Remove(rule); // remove old rule
                ruleNew.RemoteAddresses = addressList.ToArray();
                FirewallWAS.Instance.Rules.Add(ruleNew); // add new rule
            }
        }
    }
}
