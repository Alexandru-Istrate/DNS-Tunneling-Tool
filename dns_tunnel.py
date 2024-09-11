import socket
from scapy.all import *
import sys
import subprocess
import argparse
import io
import random
from tqdm import tqdm

def dns_server(port):
    simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    simple_udp.bind(('0.0.0.0', port))
    

    print('DNS Tunnel server is running...')
    while True:
        simple_udp.settimeout(None)
        request, source_address = simple_udp.recvfrom(65535)
        packet = DNS(request) 
        dns = packet.getlayer(DNS)
        if dns is not None and dns.opcode == 0:  # DNS QUERY
            print("got: ")
            print(packet.summary())
            qname = packet.qd.qname
            if qname[-17:] == b'.dns.tunnel.live.' and packet.qd.qtype==16:
                simple_udp.settimeout(5)
                if qname == b'op.ls.dns.tunnel.live.':
                    print('Received request to list files')
                    ls = subprocess.Popen('ls', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    ls.wait()
                    ls_output, err = ls.communicate()
                    output_buffer = io.BytesIO(ls_output)
                    chunk = output_buffer.read(200)
                    seq_number = random.randint(0, 2147483648)
                    nr_tries = 0
                    while chunk:
                        nr_tries += 1
                        seq_bytes = seq_number.to_bytes(4, byteorder='big')
                        dns_answer = DNSRR(
                                rrname=dns.qd.qname,
                                ttl = 32,
                                type = "TXT",
                                rclass = "IN",
                                rdata = seq_bytes + chunk
                                 )
                        dns_response = DNS(
                                id = packet[DNS].id,
                                qr = 1,
                                aa = 0,
                                rcode = 0,
                                qd = packet.qd,
                                an = dns_answer
                                )
                        simple_udp.sendto(bytes(dns_response), source_address)
                        try:
                            ack_packet, _ = simple_udp.recvfrom(65535)
                            ack_dns = DNS(ack_packet).getlayer('DNS')
                            if ack_dns.qd.qname[4:] == f'ack.op.ls.dns.tunnel.live.'.encode() and ack_dns.qd.qname[:4] == seq_bytes:
                                chunk = output_buffer.read(200)
                                seq_number += 1
                                nr_tries = 0
                        except:
                            if nr_tries == 5:
                                print("Listing cancelled. No ack response")
                                break
                    if not chunk: 
                            seq_bytes = seq_number.to_bytes(4, byteorder='big')                  
                            dns_answer = DNSRR(
                            rrname=dns.qd.qname,
                            ttl = 32,
                            type = "TXT",
                            rclass = "IN",
                            rdata = seq_bytes + b'End of file'
                            )
                            dns_response = DNS(
                                id = packet[DNS].id,
                                qr = 1,
                                aa = 0,
                                rcode = 0,
                                qd = packet.qd,
                                an = dns_answer
                            )
                            nr_tries = 0
                            while True:
                                nr_tries += 1
                                simple_udp.sendto(bytes(dns_response), source_address)
                                try:
                                    ack_packet, _ = simple_udp.recvfrom(65535)
                                    ack_dns = DNS(ack_packet).getlayer('DNS')
                                    if ack_dns.qd.qname[4:] == f'ack.op.ls.dns.tunnel.live.'.encode() and ack_dns.qd.qname[:4] == seq_bytes:
                                        break
                                except:
                                    if nr_tries == 5:
                                        print("Listing cancelled. No ack response")
                                        break

                else:
                    file_name = qname[:-17].decode().replace('/','_').replace('\\','_')
                    print(f'Received request for file: {file_name}')
                    seq_number = random.randint(0, 2147483648)
                    try:
                        file_to_send = open(file_name, 'rb')
                        total_size = os.path.getsize(file_name)
                        total_size_bytes = total_size.to_bytes(4, byteorder='big')

                        nr_tries = 0
                        while True:
                            nr_tries += 1
                            seq_bytes = seq_number.to_bytes(4, byteorder='big')               
                            dns_answer = DNSRR(
                            rrname=dns.qd.qname,
                            ttl = 32,
                            type = "TXT",
                            rclass = "IN",
                            rdata = seq_bytes + total_size_bytes
                            )
                            dns_response = DNS(
                                id = packet[DNS].id,
                                qr = 1,
                                aa = 0,
                                rcode = 0,
                                qd = packet.qd,
                                an = dns_answer
                            )
                            simple_udp.sendto(bytes(dns_response), source_address)
                            try:
                                ack_packet, _ = simple_udp.recvfrom(65535)
                                ack_dns = DNS(ack_packet).getlayer('DNS')
                                if ack_dns.qd.qname[4:] == f'ack.{file_name}.dns.tunnel.live.'.encode() and ack_dns.qd.qname[:4] == seq_bytes:
                                    seq_number += 1
                                    break
                            except:
                                if nr_tries == 5:
                                    break
                                
                        if nr_tries == 5:
                            print("No ack response from the client")
                            break                    
                            
                        progress_bar = tqdm(total=total_size, unit='B', unit_scale=True, desc=file_name, dynamic_ncols=True)
                        file_chunk = file_to_send.read(200)
                        while(file_chunk):
                            nr_tries = 0
                            seq_bytes = seq_number.to_bytes(4, byteorder='big')  
                            dns_answer = DNSRR(
                                rrname=dns.qd.qname,
                                ttl = 32,
                                type = "TXT",
                                rclass = "IN",
                                rdata = seq_bytes + file_chunk
                            )
                            dns_response = DNS(
                                id = packet[DNS].id,
                                qr = 1,
                                aa = 0,
                                rcode = 0,
                                qd = packet.qd,
                                an = dns_answer
                            )
                            simple_udp.sendto(bytes(dns_response), source_address)
                            try:
                                ack_packet, _ = simple_udp.recvfrom(65535)
                                ack_dns = DNS(ack_packet).getlayer('DNS')
                                if ack_dns.qd.qname[4:] == f'ack.{file_name}.dns.tunnel.live.'.encode() and ack_dns.qd.qname[:4] == seq_bytes:
                                    progress_bar.update(len(file_chunk))
                                    file_chunk = file_to_send.read(200)
                                    seq_number += 1
                            except:
                                if nr_tries <= 5:
                                    nr_tries += 1 
                                    continue
                                else:
                                    break
                        if not file_chunk:
                            seq_bytes = seq_number.to_bytes(4, byteorder='big')                  
                            dns_answer = DNSRR(
                            rrname=dns.qd.qname,
                            ttl = 32,
                            type = "TXT",
                            rclass = "IN",
                            rdata = seq_bytes + b'End of file'
                            )
                            dns_response = DNS(
                                id = packet[DNS].id,
                                qr = 1,
                                aa = 0,
                                rcode = 0,
                                qd = packet.qd,
                                an = dns_answer
                            )
                            nr_tries = 0
                            while True:
                                nr_tries += 1
                                simple_udp.sendto(bytes(dns_response), source_address)
                                try:
                                    ack_packet, _ = simple_udp.recvfrom(65535)
                                    ack_dns = DNS(ack_packet).getlayer('DNS')
                                    if ack_dns.qd.qname[4:] == f'ack.{file_name}.dns.tunnel.live.'.encode() and ack_dns.qd.qname[:4] == seq_bytes:
                                        break
                                except:
                                    nr_tries += 1
                                    if nr_tries == 5:
                                        print("Transfer cancelled. No ack response")
                                        break
                        progress_bar.close()                        
                    except(FileNotFoundError):
                        seq_bytes = seq_number.to_bytes(4, byteorder='big') 
                        dns_answer = DNSRR(
                                rrname=dns.qd.qname,
                                ttl = 32,
                                type = "TXT",
                                rclass = "IN",
                                rdata = seq_bytes + b'File not found'
                            )
                        dns_response = DNS(
                            id = packet[DNS].id,
                            qr = 1,
                            aa = 0,
                            rcode = 0,
                            qd = packet.qd,
                            an = dns_answer
                        )
                        simple_udp.sendto(bytes(dns_response), source_address)
            else:
                dns_response = DNS(
                    id=packet[DNS].id,
                    qr=1,  # 1 for response, 0 for query
                    aa=0,  # Authoritative Answer
                    rcode=3,  # Name Error
                    qd=packet.qd  # original query
                )
                simple_udp.sendto(bytes(dns_response), source_address)


def get_file(file_name, ip_address, port):
    file_name = file_name.replace('/','_')
    ip = IP(dst=ip_address)
    transport = UDP(dport=port)
    dns = DNS(rd=1)
    get_file_qname = f'{file_name}.dns.tunnel.live.'.encode()
    ack_file_qname = b'ack.' + get_file_qname
    dns_query = DNSQR(qname=get_file_qname, qtype=16, qclass=1)
    dns.qd = dns_query

    expected_seq = -1
    nr_tries = 0

    try:
        writeFile = open(file_name,'xb')
    except FileExistsError:
        print('A file with the same name already exists!')
        return
    while True:
        nr_tries += 1
        answer = sr1(ip / transport / dns, timeout=10, verbose=False)
        if answer and answer.haslayer(DNS) and answer[DNS].an and answer[DNS].an.rrname == get_file_qname:
            seq_number_bytes = answer[DNS].an.rdata[0][:4]
            seq_number = int.from_bytes(seq_number_bytes, byteorder='big')
            if expected_seq == -1 or expected_seq == seq_number:
                if answer[DNS].an.rdata[0][4:] == b'End of file':
                    dns_ack = DNSQR(qname=seq_number_bytes + ack_file_qname, qtype=16, qclass=1)
                    dns.qd = dns_ack
                    send(ip / transport / dns, verbose=False)
                    break
                elif answer[DNS].an.rdata[0][4:] == b'File not found':
                    print(f'No such file on the server.')
                    os.remove(file_name)
                    break
                else:
                    if expected_seq == -1:
                            file_size = int.from_bytes(answer[DNS].an.rdata[0][4:8], byteorder='big')
                            progress_bar = tqdm(total=file_size, unit='B', unit_scale=True, desc=file_name, dynamic_ncols=True)
                    else:
                        writeFile.write(answer[DNS].an.rdata[0][4:])
                        progress_bar.update(len(answer[DNS].an.rdata[0][4:]))
                    dns_ack = DNSQR(qname=seq_number_bytes + ack_file_qname, qtype=16, qclass=1)
                    dns.qd = dns_ack
                    nr_tries = 0
                    expected_seq = seq_number + 1     
        else:
            if nr_tries == 5:
                print("No response received from the server.")
                os.remove(file_name)
                break

def list_files(ip_address, port):
    ip = IP(dst=ip_address)
    transport = UDP(dport=port)
    dns = DNS(rd=1)
    dns_query = DNSQR(qname = b'op.ls.dns.tunnel.live.', qtype=16, qclass=1)
    dns.qd = dns_query
    output_buffer = io.BytesIO()
    nr_tries = 0
    expected_seq = -1
    while True:
        nr_tries += 1
        answer = sr1(ip / transport / dns, timeout = 2, verbose=False)
        if answer and answer.haslayer(DNS) and answer[DNS].an and answer[DNS].an.rrname == b'op.ls.dns.tunnel.live.':
            seq_number_bytes = answer[DNS].an.rdata[0][:4]
            seq_number = int.from_bytes(seq_number_bytes, byteorder='big')
            if expected_seq == -1 or expected_seq == seq_number:
                if answer[DNS].an.rdata[0][4:] == b'End of file':
                    print('\n' + output_buffer.getvalue().decode())
                    dns_ack = DNSQR(qname = seq_number_bytes + b'ack.op.ls.dns.tunnel.live.')
                    dns.qd = dns_ack
                    send(ip / transport / dns, verbose=False)
                    break
                else:  
                    output_buffer.write(answer[DNS].an.rdata[0][4:])
                    dns_ack = DNSQR(qname = seq_number_bytes + b'ack.op.ls.dns.tunnel.live.')
                    dns.qd = dns_ack
                    nr_tries = 0
                    expected_seq = seq_number + 1
                    
        else:
            if nr_tries == 5:
                print("No response received from the server.")
                break

def dns_client(ip_address , port):
    print("----->  DNS Tunnel Client by Alexandru Istrate  <-----")
    print("Type 'help' to see the command list")
    while True:
        print('dns-tunnel > ',end='')
        cmd = input().strip()

        if cmd == 'help': 
            print('Use the following commands:')
            print('ls  -> List the files that are available on the server')
            print('get [filename]  -> Download file from the server')   
            print('exit  -> Exit the client')
        elif cmd[:3] == 'get':
            file_name = cmd[3:].strip()
            get_file(file_name, ip_address, port)
        elif cmd == 'ls':
            list_files(ip_address, port)
        elif cmd == 'exit':
            break
        else:
            print('Unrecognized command')


def main(argv):
    
    parser = argparse.ArgumentParser(description='DNS Tunneling Tool', usage='%(prog)s [-h] [-s] [-c IP_ADDRESS] [-p PORT]')
    
    parser.add_argument('-s', '--server', action='store_true', help='Start server for DNS Tunneling')
    parser.add_argument('-c', '--client', type=str, help='Run as client and connect to the specified IP address')
    parser.add_argument('-p', '--port', type=int, help='Specify the port number')
    
    args = parser.parse_args()


    if not args.server and not args.client:
        parser.error("You must specify either --server or --client")

    if args.server and args.client:
        parser.error("You cannot specify both --server and --client")

    if args.client and not args.client.strip():
        parser.error("You must specify an IP address to connect to. --client [ip-address]")

    if args.server or args.client:
        if not args.port:
            parser.error("You must specify a port number with --port")

    if args.server:
        print(f"Starting server on port {args.port}")
        dns_server(args.port)

    if args.client:
        print(f"Running client and connecting to {args.client} on port {args.port}")
        dns_client(args.client, args.port)


if __name__ == '__main__':
    main(sys.argv)
