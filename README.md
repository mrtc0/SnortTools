# SnortTools

Snort Utility Tools

---
## u2reader.py

Snort and Suricata unified2 log file reader.

```
usage: u2reader.py [-h] [-g GEN_MAP] [-s SID_MAP] [-c CLASSFICATION]
                   [-p PRIORITY] [-v]
                   logfile

Snort Unified2 Log Parser

positional arguments:
  logfile

optional arguments:
  -h, --help            show this help message and exit
  -g GEN_MAP, --gen-map GEN_MAP
                        Snort gen-msg.map file. Default ./gen-msg.map
  -s SID_MAP, --sid-map SID_MAP
                        Snort sid-msg.map file. Default ./sid-map.map
  -c CLASSFICATION, --classfication CLASSFICATION
                        Snort classification.config file. Default ./classification.config
  -p PRIORITY, --priority PRIORITY
                        Priority
  -v, --verbose         Verbose mode

```

出力フォーマットは以下のようになっています.  
-vオプションを使用しない場合
```
Event ID        Event Time      Source IP:Source Port => Destination IP:Destination Port        Protocol        Priority
```

-vオプションを使用した場合
```
Event ID        Event Time      Source IP:Source Port => Destination IP:Destination Port        Protocol        Priority
Siganature Message      Signature Class Signature Reference(URL)
Classification Name     Description     %s
```

#### Example

```
$ ./u2reader.py -g /etc/snort/gen-msg.map -s /etc/snort/sid-msg.map -c /etc/snort/classification.config samples/snort.unified2
...
10      2015-11-27 18:13:37     192.168.3.35:1034 => 195.2.253.92:80    TCP     1
11      2015-11-27 18:13:37     192.168.3.35:1035 => 66.96.224.213:80   TCP     1
12      2015-11-27 18:13:38     192.168.3.35:1036 => 195.2.253.92:80    TCP     1
13      2015-11-27 18:13:38     192.168.3.35:1036 => 195.2.253.92:80    TCP     1
14      2015-11-27 18:13:38     192.168.3.35:1036 => 195.2.253.92:80    TCP     1
15      2015-11-27 18:13:38     192.168.3.35:1037 => 195.2.253.92:80    TCP     1
16      2015-11-27 18:13:39     192.168.1.101:1037 => 65.32.5.111:53    UDP     3
17      2015-11-27 18:13:43     192.168.10.127:1196 => 192.168.10.101:445       TCP     3
18      2015-11-27 18:13:43     192.168.10.127:1196 => 192.168.10.101:445       TCP     3
19      2015-11-27 18:13:44     192.168.10.128:1495 => 192.168.10.101:445       TCP     3
20      2015-11-27 18:13:44     192.168.10.128:1495 => 192.168.10.101:445       TCP     3
21      2015-11-27 18:13:44     192.168.10.128:1505 => 64.127.109.133:80        TCP     1
22      2015-11-27 18:13:44     192.168.10.128:36012 => 72.20.34.145:6881       UDP     1
23      2015-11-27 18:13:44     192.168.10.128:1536 => 192.168.10.101:445       TCP     3
24      2015-11-27 18:13:44     192.168.10.128:1536 => 192.168.10.101:445       TCP     3
25      2015-11-27 18:13:44     192.168.10.128:1547 => 192.168.10.101:445       TCP     3
...
```

priorityが3より大きいalertを表示するには次のようにします.

```
$ python u2reader.py -g /etc/snort/gen-msg.map -s /etc/snort/sid-msg.map -c /etc/snort/classification.config -p 3 -v samples/snort.unified2
...
28      2015-11-27 18:13:45     192.168.10.126:1158 => 192.168.10.101:445       TCP     3
        GPL NETBIOS SMB-DS IPC$ unicode share access    None    []
        tcp-connection  A TCP connection was detected
39      2015-11-27 18:13:47     192.168.10.129:1104 => 192.168.10.101:445       TCP     3
        GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode asn1 overflow attempt  None    ['url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx', 'nessus,12065', 'nessus,12052', 'cve,200
3-0818', 'bugtraq,9635', 'bugtraq,9633']
        tcp-connection  A TCP connection was detected
40      2015-11-27 18:13:47     192.168.10.129:1104 => 192.168.10.101:445       TCP     3
        GPL NETBIOS SMB-DS IPC$ unicode share access    None    []
        tcp-connection  A TCP connection was detected
50      2015-11-27 18:13:49     192.168.10.120:63324 => 192.168.10.102:139      TCP     3
        GPL NETBIOS SMB IPC$ unicode share access       None    []
        tcp-connection  A TCP connection was detected
51      2015-11-27 18:13:49     192.168.10.120:63378 => 192.168.10.102:139      TCP     3
        GPL NETBIOS SMB IPC$ unicode share access       None    []
        tcp-connection  A TCP connection was detected
52      2015-11-27 18:13:49     192.168.10.125:1359 => 192.168.10.101:445       TCP     3
        GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode asn1 overflow attempt  None    ['url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx', 'nessus,12065', 'nessus,12052', 'cve,200
3-0818', 'bugtraq,9635', 'bugtraq,9633']
        tcp-connection  A TCP connection was detected
53      2015-11-27 18:13:49     192.168.10.125:1359 => 192.168.10.101:445       TCP     3
        GPL NETBIOS SMB-DS IPC$ unicode share access    None    []
        tcp-connection  A TCP connection was detected
54      2015-11-27 18:13:49     192.168.10.127:1209 => 192.168.10.101:445       TCP     3
        GPL NETBIOS SMB-DS Session Setup NTMLSSP unicode asn1 overflow attempt  None    ['url,www.microsoft.com/technet/security/bulletin/MS04-007.mspx', 'nessus,12065', 'nessus,12052', 'cve,200
3-0818', 'bugtraq,9635', 'bugtraq,9633']
        tcp-connection  A TCP connection was detected
...
```

---

## Todo

めっちゃある

