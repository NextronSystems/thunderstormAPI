# ThunderstormAPI

This module allows you to interact with THOR Thunderstorm API, which is also known as THOR Service. 

Running THOR in service mode (--service) starts a local RESTful API service. This API allows to submit samples and returns results in JSON format. The service runs multi-threaded and is designed for high performance samples processing.  

This repository contains a Python module named `thunderstormAPI` and an example Python command line API client implementation named `thunderstorm-cli`. 

# Installation

```
pip install thunderstormAPI
```

(Note: use `pip3 install thunderstormAPI` on Debian)

## Thunderstorm CLI 

The Thunderstorm command line interface (CLI) is a pre-written tool that implements the Python module. 

### Usage

```commandline
usage: thunderstorm-cli [-h] [-t host] [-p port] [--ssl] [--strict_ssl strict-ssl] [-o source] [--status] [--info] [--result] [-r sample-id] [-s] [-f sample]
                        [-d sample-dir] [-e EXCLUDE [EXCLUDE ...]] [-i INCLUDE [INCLUDE ...]] [-l lookback] [-n threads] [-m minimum-level] [--asyn]
                        [-ps proxy-url] [-pu proxy-user] [-pp proxy-pass] [--debug] [--trace]

THOR-Thunderstorm-CLI

optional arguments:
  -h, --help            show this help message and exit
  -t host, --thor_host host
                        THOR service host
  -p port, --thor_port port
                        THOR service port
  --ssl                 Use TLS/SSL (HTTPS)
  --strict_ssl strict-ssl
                        Use strict TLS/SSL (deny self-signed SSL certificates)
  -o source, --source source
                        Source identifier (used in Thunderstorm server log)
  --debug               Debug output
  --trace               Trace output

=======================================================================
Info:
  --status              Get status information from the service (processed samples, errors, runtime)
  --info                Get general information (versions, license info)
  --result              Get information on a certain sample id
  -r sample-id, --id sample-id
                        Sample ID returned in asynchronous result

=======================================================================
Scan:
  -s, --scan            Transmit sample file to get it scanned
  -f sample, --file sample
                        Sample file
  -d sample-dir, --dir sample-dir
                        Sample directory
  -e EXCLUDE [EXCLUDE ...], --exclude EXCLUDE [EXCLUDE ...]
                        Exclude pattern (can be used multiple times)
  -i INCLUDE [INCLUDE ...], --include INCLUDE [INCLUDE ...]
                        Include pattern (can be used multiple times)
  -l lookback, --lookback lookback
                        Only submit files created or modified within the last X seconds
  -n threads, --threads threads
                        Number of threads
  -m minimum-level, --min_level minimum-level
                        Minimum level to report (Debug=1, Info=2, Notice=3, Error=4, Warning=5, Alert=6)
  --asyn                Asynchronous transmission (server just returns a send receipt and not a result, which allows a much fast transmission)

=======================================================================
Proxy:
  -ps proxy-url, --proxy proxy-url
                        proxy URL (e.g. https://my.proxy.net:8080)
  -pu proxy-user, --proxy_user proxy-user
                        proxy user
  -pp proxy-pass, --proxy_pass proxy-pass
                        proxy password
```

### Examples

#### Server

On a server you would run THOR in service mode as follows
```bash
./thor-linux-64 --server --server-host 10.0.0.14 --threadcount 40
```

See our github [repository](https://github.com/NextronSystems/nextron-helper-scripts/tree/master/thunderstorm) for scripts that help you with the installation of THOR Thunderstorm. 

#### Client

Get information on a running THOR Thunderstorm service on `10.0.0.14`

```bash
./thunderstorm-cli --info -t 10.0.0.14
```

Result 
```
[INFO ] Using THOR Thunderstorm service on host 127.0.0.1 port 8081 without SSL/TLS
{
    "allowed_samples_per_hour": 0,
    "sigma_version": "0.17.0-383-gd73447c1",
    "signature_version": "2020/08/13-125157",
    "thor_timestamp": "2020-08-17 07:04:36",
    "thor_version": "10.6.0",
    "yara_version": "4.0.2"
}
```

Submit a single sample to THOR Thunderstorm service running on `10.0.0.4`

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -f ./samples/webshell.txt
```

Result
```
[INFO ] Using THOR Thunderstorm service on host 10.0.0.14 port 8080 without SSL/TLS
[INFO ] Thunderstorm service stats UPTIME: 00h:45m:57s SCANNED_SAMPLES: 60 AVG_SCAN_TIME: 33ms
[INFO ] Submitting file ./samples/webshell.txt for scanning ...
[WARNI] Match found in FILE: ./samples/webshell.txt MATCH: {'level': 'Alert', 'module': 'Filescan', 'message': 'Malware file found', 'score': 140, 'context': {'ext': '', 'file': './samples/webshell.txt', 'firstBytes': '3c3f70687020406576616c28245f4745545b636d / <?php @eval($_GET[cm', 'md5': '6f70c1a517db1818e0234ba63185e6e9', 'sha1': '2f13649ccd9de947fd28616d73cc1387674a2df0', 'sha256': '5906cb00cbe1c108ff4a0e17f1c76606c57364467352ce4f986271e40bd5c1cc', 'size': 58, 'type': 'PHP'}, 'matches': [{'matched': ['php @eval($_POST['], 'reason': 'China Chopper Webshells - PHP and ASPX', 'ref': 'https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf', 'ruledate': '2015-03-10', 'rulename': 'ChinaChopper_Generic', 'subscore': 75, 'tags': ['CHINA', 'GEN', 'T1100', 'WEBSHELL']}, {'matched': ['<?php', '$_GET[', 'eval('], 'reason': 'Detects suspiciously small PHP file that receives a parameter and runs a eval statement', 'ref': 'https://github.com/qiyeboy/kill_webshell_detect', 'ruledate': '2020-07-31', 'rulename': 'SUSP_WEBSHELL_PHP_Tiny_Indicators_Jul20', 'subscore': 65, 'tags': ['FILE', 'SUSP', 'T1100', 'T1136', 'WEBSHELL']}]}
```

Submit all samples within a directory (recursively) to THOR Thunderstorm service running on `10.0.0.14`

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/
```

Result
```
[INFO ] Using THOR Thunderstorm service on host 10.0.0.14 port 8080 without SSL/TLS
[INFO ] Thunderstorm service stats UPTIME: 00h:59m:15s SCANNED_SAMPLES: 64 AVG_SCAN_TIME: 34ms
[INFO ] Submitting samples from ./samples/ using 12 threads
[INFO ] Scanning path: ./samples/ with 3 elements
[WARNI] Match found in FILE: ./samples/test-mimi.txt MATCH: {'level': 'Warning', 'module': 'Filescan', 'message': 'Possibly Dangerous file found', 'score': 205, 'context': {'ext': '', 'file': './samples/test-mimi.txt', 'firstBytes': '6c6f676f6e70617373776f7264733a3a0a73656b / logonpasswords::\nsek', 'md5': 'bf9d9616e86267d5d5ba48ad1161e2aa', 'sha1': '00d0289f25119fe4695e82aa09e18aa53b5606e2', 'sha256': '7579e064c44fb1782cf59485e7b812e72e30f1160d687e20976739d3f40cb748', 'size': 83, 'type': 'UNKNOWN'}, 'matches': [{'matched': [' -ma lsass.exe'], 'reason': 'Detects commands often used in malicious scripts', 'ref': 'https://twitter.com/SBousseaden/status/1272863752677965824', 'ruledate': '2020-06-16', 'rulename': 'SUSP_LSASS_Memory_Dump_CmdLine_Jun20_2', 'subscore': 70, 'tags': ['HKTL', 'SUSP', 'T1003', 'T1136']}, {'matched': ['-ma lsass.exe'], 'reason': 'Procdump - Batch file invocation', 'ref': '-', 'ruledate': '2013-01-01', 'rulename': 'HKTL_Procdump_BAT', 'subscore': 70, 'tags': ['APT', 'HKTL', 'T1136']}, {'matched': [' -ma ', ' lsass.exe'], 'reason': 'Detects suspicious post exploitation strings and command lines often used by attackers', 'ref': 'https://blog.talosintelligence.com/2019/08/china-chopper-still-active-9-years-later.html', 'ruledate': '2019-08-28', 'rulename': 'SUSP_PostExploitation_Cmds_Aug19_1', 'subscore': 65, 'tags': ['SUSP', 'T1136']}]}
[WARNI] Match found in FILE: ./samples/webshell.txt MATCH: {'level': 'Alert', 'module': 'Filescan', 'message': 'Malware file found', 'score': 140, 'context': {'ext': '', 'file': './samples/webshell.txt', 'firstBytes': '3c3f70687020406576616c28245f4745545b636d / <?php @eval($_GET[cm', 'md5': '6f70c1a517db1818e0234ba63185e6e9', 'sha1': '2f13649ccd9de947fd28616d73cc1387674a2df0', 'sha256': '5906cb00cbe1c108ff4a0e17f1c76606c57364467352ce4f986271e40bd5c1cc', 'size': 58, 'type': 'PHP'}, 'matches': [{'matched': ['php @eval($_POST['], 'reason': 'China Chopper Webshells - PHP and ASPX', 'ref': 'https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf', 'ruledate': '2015-03-10', 'rulename': 'ChinaChopper_Generic', 'subscore': 75, 'tags': ['CHINA', 'GEN', 'T1100', 'WEBSHELL']}, {'matched': ['<?php', '$_GET[', 'eval('], 'reason': 'Detects suspiciously small PHP file that receives a parameter and runs a eval statement', 'ref': 'https://github.com/qiyeboy/kill_webshell_detect', 'ruledate': '2020-07-31', 'rulename': 'SUSP_WEBSHELL_PHP_Tiny_Indicators_Jul20', 'subscore': 65, 'tags': ['FILE', 'SUSP', 'T1100', 'T1136', 'WEBSHELL']}]}
[WARNI] Match found in FILE: ./samples/sekurlsa.log MATCH: {'level': 'Alert', 'module': 'Filescan', 'message': 'Malware file found', 'score': 325, 'context': {'ext': '', 'file': './samples/sekurlsa.log', 'firstBytes': "5573696e67202773656b75726c73612e6c6f6727 / Using 'sekurlsa.log'", 'md5': '619e7ad14b5a64481958ac5248dd832f', 'sha1': '886817e0fbc813c711616e2d1ace7c819cfd5b55', 'sha256': '0c66a723033b367e3700e83054f521a853bd6764b24924ce66c5df81d8ff32f3', 'size': 1362, 'type': 'Mimikatz Logfile'}, 'matches': [{'matched': ['* Username : ', '* Password : ', 'credman :'], 'reason': 'Detects credential dump strings from APT case', 'ref': 'White Amflora', 'ruledate': '2016-05-02', 'rulename': 'CustomerCase_C2_Credential_Dump', 'subscore': 100, 'tags': ['APT', 'CLIENT', 'HKTL', 'T1003', 'T1136']}, {'matched': ['SID               :', '* NTLM     :', 'Authentication Id :', 'wdigest :'], 'reason': 'Detects a log file generated by malicious hack tool mimikatz', 'ref': '-', 'ruledate': '2015-03-31', 'rulename': 'Mimikatz_Logfile', 'subscore': 80, 'tags': ['HKTL', 'T1003', 'T1075', 'T1097', 'T1136', 'T1178']}, {'matched': ['* Password : (null)', 'mimikatz # sekurlsa::logonpasswords', '* NTLM     : ', '* Username : ', 'Logon Server      : ', '] CredentialKeys'], 'reason': 'Detects keyword combo known from Mimikatz log files', 'ref': 'https://github.com/gentilkiwi/mimikatz/wiki/module-~-standard#log', 'ruledate': '2019-02-26', 'rulename': 'SUSP_Mimikatz_LogFile_Keywords', 'subscore': 75, 'tags': ['SUSP', 'T1003', 'T1075', 'T1097', 'T1136', 'T1178']}, {'matched': ['Authentication Id :', 'SID               :', 'tspkg :', 'kerberos :', '* Username :', 'credman :'], 'reason': 'Detects a log file of password dumper mimikatz', 'ref': '-', 'ruledate': '2014-12-22', 'rulename': 'Mimikatz_Log_Output', 'subscore': 70, 'tags': ['APT', 'T1003', 'T1075', 'T1097', 'T1136', 'T1178']}]}
```

Submit all samples within a directory and submit only `*.exe` and `*.dll` files.

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/ --include *.exe --include *.dll
```

Submit all samples within a directory and exclude files.

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/ --exclude *.evtx
```

Submit all samples within a directory and send only files that have been changed or modified within the last hour. 

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/ --lookback 3600
```

Submit all samples within a directory and send the files using HTTPS.

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/ --ssl
```

Submit all samples within a directory and send the files using asynchronous mode. (fast submission, no result response)

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/ --asyn
```

Submit all samples within a directory and set a custom source value. 

```bash
./thunderstorm-cli --scan -t 10.0.0.14 -d ./samples/ --source sample_collector_1
```

## Python Module

The 2 helper functions of the Python module are:

- `get_info()` gets general information (versions, license info)
- `get_status()` gets status information from the service (processed samples, errors, runtime)

The 2 main functions of the Python module are:

- `scan(sample)` submits a sample for remote scanning
- `scan_multi(sample_list)` submits a list of samples (multi-threaded)

### __init__()

The `__init__` method accepts the following parameters:

- `host`: host on which the THOR Thunderstorm service runs
- `port`: port on which the THOR Thunderstorm service listens
- `source`: custom source identifier (which is the hostname by default)
- `use_ssl`: use SSL for the transmission
- `verify_ssl`: verify the SSL/TLS server certificate

### scan()

The `scan` method accepts the following parameters:

- `filelist`: list of absolute file paths
- `asyn`: asynchronous mode, just submit, don't wait for scan result (server returns only a submission receipt)
- `trace`: be more verbose than debug and show request and response

### scan_multi()

The `scan_multi` method accepts the following parameters:

- `filelist`: list of absolute file paths
- `num_threads`: number of threads
- `asyn`: asynchronous mode, just submit, don't wait for scan result (server returns only a submission receipt)
- `trace`: be more verbose than debug and show each request and response

## Examples

### Get Info 

```python 
from thunderstormAPI.thunderstorm import ThunderstormAPI

thorapi = ThunderstormAPI(host='thunderstorm.local')
thorapi.get_info()
```

Returns
```json
{
    "allowed_samples_per_hour": 0,
    "license_expiration_date": "2021/01/30",
    "sigma_version": "0.18.1",
    "signature_version": "2020/08/31-164212",
    "thor_timestamp": "2020-09-03 07:39:30",
    "thor_version": "10.6.0",
    "threads": 40,
    "yara_version": "4.0.2"
}
```

### Get Status 

```python 
from thunderstormAPI.thunderstorm import ThunderstormAPI

thorapi = ThunderstormAPI(host='thunderstorm.local')
thorapi.get_status()
```

Returns
```json
{
    "avg_scan_time_ms": 494,
    "avg_total_time_ms": 495,
    "denied_request_proportion": 0,
    "denied_requests": 0,
    "queued_async_requests": 70854,
    "quota_wait_time_ms": 0,
    "quota_waits": 0,
    "scanned_samples": 109230,
    "uptime_s": 1419
}
```

### Submit Single File

```python 
from thunderstormAPI.thunderstorm import ThunderstormAPI

thorapi = ThunderstormAPI(host='thunderstorm.local')
thorapi.scan('./samples/webshell.txt')
```

Returns
```json
[
    {
        "level": "Alert",
        "module": "Filescan",
        "message": "Malware file found",
        "score": 140,
        "context": {
            "ext": "",
            "file": "./samples/webshell.txt",
            "firstBytes": "3c3f70687020406576616c28245f4745545b636d / <?php @eval($_GET[cm",
            "md5": "6f70c1a517db1818e0234ba63185e6e9",
            "sha1": "2f13649ccd9de947fd28616d73cc1387674a2df0",
            "sha256": "5906cb00cbe1c108ff4a0e17f1c76606c57364467352ce4f986271e40bd5c1cc",
            "size": 58,
            "type": "PHP"
        },
        "matches": [
            {
                "matched": [
                    "php @eval($_POST["
                ],
                "reason": "China Chopper Webshells - PHP and ASPX",
                "ref": "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf",
                "ruledate": "2015-03-10",
                "rulename": "ChinaChopper_Generic",
                "subscore": 75,
                "tags": [
                    "CHINA",
                    "GEN",
                    "T1100",
                    "WEBSHELL"
                ]
            },
            {
                "matched": [
                    "<?php",
                    "$_GET[",
                    "eval("
                ],
                "reason": "Detects suspiciously small PHP file that receives a parameter and runs a eval statement",
                "ref": "https://github.com/qiyeboy/kill_webshell_detect",
                "ruledate": "2020-07-31",
                "rulename": "SUSP_WEBSHELL_PHP_Tiny_Indicators_Jul20",
                "subscore": 65,
                "tags": [
                    "FILE",
                    "SUSP",
                    "T1100",
                    "T1136",
                    "WEBSHELL"
                ]
            }
        ]
    }
]
```

### Submit a List of Samples

```python 
from thunderstormAPI.thunderstorm import ThunderstormAPI

SAMPLES = './samples'
samples = [path.join(SAMPLE_DIR, f) for f in listdir(SAMPLE_DIR)]

thorapi = ThunderstormAPI(host='thunderstorm.local')

thorapi.scan_multi(samples)
```

Returns
```json
[
    [
        {
            "level": "Alert",
            "module": "Filescan",
            "message": "Malware file found",
            "score": 140,
            "context": {
                "ext": "",
                "file": "./samples/webshell.txt",
                "firstBytes": "3c3f70687020406576616c28245f4745545b636d / <?php @eval($_GET[cm",
                "md5": "6f70c1a517db1818e0234ba63185e6e9",
                "sha1": "2f13649ccd9de947fd28616d73cc1387674a2df0",
                "sha256": "5906cb00cbe1c108ff4a0e17f1c76606c57364467352ce4f986271e40bd5c1cc",
                "size": 58,
                "type": "PHP"
            },
            "matches": [
                {
                    "matched": [
                        "php @eval($_POST["
                    ],
                    "reason": "China Chopper Webshells - PHP and ASPX",
                    "ref": "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf",
                    "ruledate": "2015-03-10",
                    "rulename": "ChinaChopper_Generic",
                    "subscore": 75,
                    "tags": [
                        "CHINA",
                        "GEN",
                        "T1100",
                        "WEBSHELL"
                    ]
                },
                {
                    "matched": [
                        "<?php",
                        "$_GET[",
                        "eval("
                    ],
                    "reason": "Detects suspiciously small PHP file that receives a parameter and runs a eval statement",
                    "ref": "https://github.com/qiyeboy/kill_webshell_detect",
                    "ruledate": "2020-07-31",
                    "rulename": "SUSP_WEBSHELL_PHP_Tiny_Indicators_Jul20",
                    "subscore": 65,
                    "tags": [
                        "FILE",
                        "SUSP",
                        "T1100",
                        "T1136",
                        "WEBSHELL"
                    ]
                }
            ]
        }
    ],
    [
        {
            "level": "Alert",
            "module": "Filescan",
            "message": "Malware file found",
            "score": 325,
            "context": {
                "ext": "",
                "file": "./samples/sekurlsa.log",
                "firstBytes": "5573696e67202773656b75726c73612e6c6f6727 / Using 'sekurlsa.log'",
                "md5": "619e7ad14b5a64481958ac5248dd832f",
                "sha1": "886817e0fbc813c711616e2d1ace7c819cfd5b55",
                "sha256": "0c66a723033b367e3700e83054f521a853bd6764b24924ce66c5df81d8ff32f3",
                "size": 1362,
                "type": "Mimikatz Logfile"
            },
            "matches": [
                {
                    "matched": [
                        "* Username : ",
                        "* Password : ",
                        "credman :"
                    ],
                    "reason": "Detects credential dump strings from APT case",
                    "ref": "White Amflora",
                    "ruledate": "2016-05-02",
                    "rulename": "CustomerCase_C2_Credential_Dump",
                    "subscore": 100,
                    "tags": [
                        "APT",
                        "CLIENT",
                        "HKTL",
                        "T1003",
                        "T1136"
                    ]
                },
                {
                    "matched": [
                        "SID               :",
                        "* NTLM     :",
                        "Authentication Id :",
                        "wdigest :"
                    ],
                    "reason": "Detects a log file generated by malicious hack tool mimikatz",
                    "ref": "-",
                    "ruledate": "2015-03-31",
                    "rulename": "Mimikatz_Logfile",
                    "subscore": 80,
                    "tags": [
                        "HKTL",
                        "T1003",
                        "T1075",
                        "T1097",
                        "T1136",
                        "T1178"
                    ]
                },
                {
                    "matched": [
                        "* Password : (null)",
                        "mimikatz # sekurlsa::logonpasswords",
                        "* NTLM     : ",
                        "* Username : ",
                        "Logon Server      : ",
                        "] CredentialKeys"
                    ],
                    "reason": "Detects keyword combo known from Mimikatz log files",
                    "ref": "https://github.com/gentilkiwi/mimikatz/wiki/module-~-standard#log",
                    "ruledate": "2019-02-26",
                    "rulename": "SUSP_Mimikatz_LogFile_Keywords",
                    "subscore": 75,
                    "tags": [
                        "SUSP",
                        "T1003",
                        "T1075",
                        "T1097",
                        "T1136",
                        "T1178"
                    ]
                },
                {
                    "matched": [
                        "Authentication Id :",
                        "SID               :",
                        "tspkg :",
                        "kerberos :",
                        "* Username :",
                        "credman :"
                    ],
                    "reason": "Detects a log file of password dumper mimikatz",
                    "ref": "-",
                    "ruledate": "2014-12-22",
                    "rulename": "Mimikatz_Log_Output",
                    "subscore": 70,
                    "tags": [
                        "APT",
                        "T1003",
                        "T1075",
                        "T1097",
                        "T1136",
                        "T1178"
                    ]
                }
            ]
        }
    ],
    [
        {
            "level": "Warning",
            "module": "Filescan",
            "message": "Possibly Dangerous file found",
            "score": 205,
            "context": {
                "ext": "",
                "file": "./samples/test-mimi.txt",
                "firstBytes": "6c6f676f6e70617373776f7264733a3a0a73656b / logonpasswords::\nsek",
                "md5": "bf9d9616e86267d5d5ba48ad1161e2aa",
                "sha1": "00d0289f25119fe4695e82aa09e18aa53b5606e2",
                "sha256": "7579e064c44fb1782cf59485e7b812e72e30f1160d687e20976739d3f40cb748",
                "size": 83,
                "type": "UNKNOWN"
            },
            "matches": [
                {
                    "matched": [
                        " -ma lsass.exe"
                    ],
                    "reason": "Detects commands often used in malicious scripts",
                    "ref": "https://twitter.com/SBousseaden/status/1272863752677965824",
                    "ruledate": "2020-06-16",
                    "rulename": "SUSP_LSASS_Memory_Dump_CmdLine_Jun20_2",
                    "subscore": 70,
                    "tags": [
                        "HKTL",
                        "SUSP",
                        "T1003",
                        "T1136"
                    ]
                },
                {
                    "matched": [
                        "-ma lsass.exe"
                    ],
                    "reason": "Procdump - Batch file invocation",
                    "ref": "-",
                    "ruledate": "2013-01-01",
                    "rulename": "HKTL_Procdump_BAT",
                    "subscore": 70,
                    "tags": [
                        "APT",
                        "HKTL",
                        "T1136"
                    ]
                },
                {
                    "matched": [
                        " -ma ",
                        " lsass.exe"
                    ],
                    "reason": "Detects suspicious post exploitation strings and command lines often used by attackers",
                    "ref": "https://blog.talosintelligence.com/2019/08/china-chopper-still-active-9-years-later.html",
                    "ruledate": "2019-08-28",
                    "rulename": "SUSP_PostExploitation_Cmds_Aug19_1",
                    "subscore": 65,
                    "tags": [
                        "SUSP",
                        "T1136"
                    ]
                }
            ]
        }
    ]
]
```

### Submit a List of Samples (Asynchronous)

Submit samples in asnychronous mode, which has the advantage of faster samples submission and avoiding service overload but doesn't return a scan result to the submitting client. 

```python 
from thunderstormAPI.thunderstorm import ThunderstormAPI

SAMPLES = '/software/set1'
samples = [path.join(SAMPLE_DIR, f) for f in listdir(SAMPLE_DIR)]

thorapi = ThunderstormAPI(host='thunderstorm.local')

thorapi.scan_multi(samples, asyn=True)
```

```json
[
    {
        "file": "/software/set1/DVD Maker/sonicsptransform.ax",
        "id": 360715
    },
    {
        "file": "/software/set1/DVD Maker/directshowtap.ax",
        "id": 360711
    },
    {
        "file": "/software/set1/DVD Maker/bod_r.TTF",
        "id": 360716
    },
    {
        "file": "/software/set1/DVD Maker/rtstreamsink.ax",
        "id": 360717
    },
    {
        "file": "/software/set1/DVD Maker/rtstreamsource.ax",
        "id": 360709
    },
    {
        "file": "/software/set1/DVD Maker/PipeTran.dll",
        "id": 360708
    },
    {
        "file": "/software/set1/DVD Maker/soniccolorconverter.ax",
        "id": 360707
    },
    {
        "file": "/software/set1/DVD Maker/WMM2CLIP.dll",
        "id": 360714
    },
    {
        "file": "/software/set1/DVD Maker/DVDMaker.exe",
        "id": 360718
    },
    {
        "file": "/software/set1/DVD Maker/audiodepthconverter.ax",
        "id": 360706
    },
    {
        "file": "/software/set1/DVD Maker/Pipeline.dll",
        "id": 360713
    },
    {
        "file": "/software/set1/DVD Maker/offset.ax",
        "id": 360710
    },
    {
        "file": "/software/set1/DVD Maker/SecretST.TTF",
        "id": 360712
    },
    {
        "file": "/software/set1/DVD Maker/fieldswitch.ax",
        "id": 360705
    },
    {
        "file": "/software/set1/DVD Maker/Eurosti.TTF",
        "id": 360704
    }
]
```