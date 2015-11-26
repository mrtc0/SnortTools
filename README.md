# SnortTools

Snort Utility Tools

---
## u2reader.py

Snort and Suricata unified2 log file reader.

```
$ ./u2reader.py merged.log --help
usage: rd.py [-h] [-g GEN_MAP] [-s SID_MAP] [-c CLASSFICATION] [-p PRIORITY] [-v] logfile

Snort Unified2 Log Parser

positional arguments:
  logfile

optional arguments:
  -h, --help            show this help message and exit
  -g GEN_MAP, --gen-map GEN_MAP		A gen-msg.map
  -s SID_MAP, --sid-map SID_MAP		A sid-msg.map
  -c CLASSFICATION, --classfication CLASSFICATION	A classification.config
  -p PRIORITY, --priority PRIORITY	Priority
  -v, --verbose         Verbose mode
```

#### Example
```
$ ./u2reader.py merged.log
16099   2015-11-16 20:28:09     178.XXX.XXX.196:60114 => 153.XXX.XXX.79:22        TCP     2
16100   2015-11-16 20:29:10     178.XXX.XXX.196:60114 => 153.XXX.XXX.79:22        TCP     4
16101   2015-11-16 20:29:51     212.XXX.XXX.243:5185 => 153.XXX.XXX.79:5060      UDP     2
16102   2015-11-16 20:29:51     212.XXX.XXX.243:5185 => 153.XXX.XXX.79:5060      UDP     2
16103   2015-11-16 20:30:12     178.XXX.XXX.196:60114 => 153.XXX.XXX.79:22        TCP     2
16104   2015-11-16 20:31:13     178.XXX.XXX.196:60114 => 153.XXX.XXX.79:22        TCP     3
16105   2015-11-16 20:32:14     178.XXX.XXX.196:60114 => 153.XXX.XXX.79:22        TCP     2
```

```
$ ./u2reader.py merged.log -p 3 -v
10640   2015-11-09 11:26:54     173.XXX.XXX.237:61268 => 153.XXX.XXX.79:80      TCP     3
        http_inspect: UNKNOWN METHOD    None    None
        unknown Unknown Traffic
16470   2015-11-17 10:50:09     75.XXX.XXX.105:58834 => 153.XXX.XXX.79:3389     TCP     3
        ET SCAN Behavioral Unusually fast Terminal Server Traffic, Potential Scan or Infection (Inbound)        None    ['url,doc.emergingthreats.net/2001972']
        network-scan    Detection of a Network Scan
16497   2015-11-17 21:00:41     75.XXX.XXX.105:60990 => 153.XXX.XXX.79:3389     TCP     3
        ET SCAN Behavioral Unusually fast Terminal Server Traffic, Potential Scan or Infection (Inbound)        None    ['url,doc.emergingthreats.net/2001972']
        network-scan    Detection of a Network Scan
16511   2015-11-18 07:11:39     75.XXX.XXX.105:61851 => 153.XXX.XXX.79:3389     TCP     3
        ET SCAN Behavioral Unusually fast Terminal Server Traffic, Potential Scan or Infection (Inbound)        None    ['url,doc.emergingthreats.net/2001972']
        network-scan    Detection of a Network Scan
16532   2015-11-18 17:21:39     75.XXX.XXX.105:50989 => 153.XXX.XXX.79:3389     TCP     3
        ET SCAN Behavioral Unusually fast Terminal Server Traffic, Potential Scan or Infection (Inbound)        None    ['url,doc.emergingthreats.net/2001972']
        network-scan    Detection of a Network Scan
16539   2015-11-19 03:41:59     75.XXX.XXX.105:58763 => 153.XXX.XXX.79:3389     TCP     3
        ET SCAN Behavioral Unusually fast Terminal Server Traffic, Potential Scan or Infection (Inbound)        None    ['url,doc.emergingthreats.net/2001972']
        network-scan    Detection of a Network Scan
```

---

## Todo

めっちゃある

