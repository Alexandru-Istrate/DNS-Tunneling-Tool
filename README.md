<h1 align='center'> DNS Tunneling Tool </h1>
<br>

`DNS Tunneling Tool` enables file transfer via the DNS protocol to exfiltrate data from restrictive networks.
<p> The tool uses TXT DNS requests to craft response packets containing chunks of data. </p>
<img src='images/demo.gif'>

# Usage
```sh
python dns_tunnel.py -h
```
This will display the help manual:

```yaml
usage: dns_tunnel.py [-h] [-s] [-c IP_ADDRESS] [-p PORT]

DNS Tunneling Tool

options:
  -h, --help            show this help message and exit
  -s, --server          Start server for DNS Tunneling
  -c CLIENT, --client CLIENT
                        Run as client and connect to the specified IP address
  -p PORT, --port PORT  Specify the port number
```
### Start the server

```sh
python dns_tunnel.py --server --port [PORT_NUMBER]
```
This starts the server on localhost that will transfer files from the <b>current directory</b>. 

### Use the client to download files

```sh
python dns_tunnel.py --client [IP_ADDRESS] --port [PORT_NUMBER]
```
Connect to a server that is using this tool.

Once the client is running, it will greet us with a terminal prompt, and by typing `help` it will display the available commands.

```yaml
----->  DNS Tunnel Client by Alexandru Istrate  <-----
Type 'help' to see the command list
dns-tunnel > help
Use the following commands:
ls  -> List the files that are available on the server
get [filename]  -> Download file from the server
exit  -> Exit the client
```
Use `ls` to list the available files and `get [filename]` to download the file and store it in the<b> current directory </b>
