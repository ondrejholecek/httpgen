#!/usr/bin/env python2.7 

# BSD 3-Clause License
# 
# Copyright (c) 2018, Ondrej Holecek <ondrej at holecek dot eu>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
# 
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
# 
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import time
import select
import threading
import errno
import random
import json
import argparse
import sys
import os
import signal

class HTTPgen:
	def __init__(self, proxy, timeouts, cache_dns, debug=False):
		if proxy != None:
			self.proxy_ip   = proxy[0]
			self.proxy_port = proxy[1]
		else:
			self.proxy_ip   = None
			self.proxy_port = None

		self.connect_timeout  = timeouts[0]
		self.read_timeout     = timeouts[1]
		self.response_timeout = timeouts[2]

		self.cache_dns = cache_dns
		self.debug     = debug

		#
		self.counters_lock = threading.Lock()
		self.clear_counters()
		self.load_reuse_stats()

		#
		self.sockets = {}
		self.sockets_lock = threading.Lock()
		self.epoll   = select.epoll()
		self.should_run = True
		self.src_last_used = {}
		self.dns_cache = {}
		
		self.handle  = threading.Thread(target=self.start_thread, args=("handler", self.handle_thread))
		self.handle.start()
		self.busy    = None
	
	def save_reuse_stats(self):
		f = open("/tmp/reuse_stats.json", "w")
		json.dump(self.src_last_used, f)
		f.close()
	
	def load_reuse_stats(self):
		try:
			f = open("/tmp/reuse_stats.json", "r")
			self.src_last_used = json.load(f)
			f.close()
		except:
			pass
		
	def clear_counters(self, interval=1):
		zero = {
			'ok'       : 0,
			'invalid'  : 0,
			'timeouts' : {},
			'error'    : 0,
		}

		self.counters_lock.acquire()
		try:
			old = self.counters
		except AttributeError:
			old = zero

		self.counters = zero
		self.counters_lock.release()

		# divide by interval before returning
		for c in old.keys():
			if type(old[c]) == int:
				old[c] = int(round(float(old[c]) / interval))

			elif  type(old[c]) == dict:
				for cc in old[c].keys():
					old[c][cc] = old[c][cc] / interval
			
		return old
	
	def destroy(self):
		self.should_run = False
		self.handle.join()
		if self.busy != None: self.busy.join()
		self.save_reuse_stats()

	def get_host_ip(self, host):
		if host in self.dns_cache: return self.dns_cache[host]

		try:
			ip = socket.gethostbyname(host)
		except socket.gaierror, e:
			print >>sys.stderr, "Unable to translate host %s to IP: %s" % (host, str(e),)
			if self.debug: raise
			return None
			
		if self.cache_dns: self.dns_cache[host] = ip
		return ip
		
	def try_connect(self, socket_info):
		sock = socket_info['object']

		# connect (with non-blocking)
		try:
			if self.proxy_ip != None:
				sock.connect( (self.proxy_ip, self.proxy_port) )
			else:
				sock.connect( (self.get_host_ip(socket_info['real_host']), 80) )
		except socket.error, e:
			if e.args[0] in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
				pass
			elif e.args[0] in (errno.ECONNREFUSED, errno.ECONNRESET):
				socket_info['state'] = 'connection_refused'
			elif e.args[0] == errno.EISCONN:
				pass # TODO: ???
			else:
				raise 
		else:
			socket_info['connected_time'] = time.time()
			socket_info['state'] = 'sent'
			socket_info['object'].send(socket_info['request'])

	def cleanup(self, sockfd):
		# if the socket fd was used, make sure we clean it up
		self.sockets_lock.acquire()

		if sockfd in self.sockets:
			try:
				self.epoll.unregister(sockfd)
			except: pass

			try:
				self.sockets[sockfd]['object'].shutdown(socket.SHUT_RDWR)
				self.sockets[sockfd]['object'].close()
				self.sockets[sockfd]['object'] = None
			except: pass

			del self.sockets[sockfd]

		self.sockets_lock.release()

	def request(self, src_ip, proto, host, path):
		while True:	
			# port reuse check - seems that FortiPoC is reusing ports too soon
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
			sock.bind( (src_ip, 0) )
	
			info = "%s:%i" % sock.getsockname()
			if info in self.src_last_used and (time.time() - self.src_last_used[info]) < 121:
#				print "socket %s reused too soon" % (info,)
				continue
			else:	
				self.src_last_used[info] = time.time()
				break

		#
		sock.setblocking(0)

		socket_info = {
			'init_time'       : time.time(),
			'connected_time'  : None,
			'last_read_time'  : None,
			'object'          : sock,
			'event'           : threading.Event(),
			'state'           : 'connecting',
			'data'            : '',
			'real_host'       : host,
		}

		if self.proxy_ip != None:
			socket_info['request'] = 'GET %s://%s%s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % (
				proto,
				host,
				path,
				host,
			)
		else:
			socket_info['request'] = 'GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' % (
				path,
				host,
			)

		sockfd = sock.fileno()
		self.cleanup(sockfd)

		self.sockets_lock.acquire()
		self.sockets[sockfd] = socket_info
		self.sockets_lock.release()

		# register our new socket
		self.epoll.register(sockfd, select.EPOLLIN | select.EPOLLERR | select.EPOLLHUP)
		self.try_connect(self.sockets[sockfd])

	def handle_thread(self):
		while self.should_run:
			# first process sockets with event
			sockfds = self.epoll.poll(timeout=0.1)
			self.sockets_lock.acquire()
			for (sockfd, event) in sockfds:
				# incoming data
				if event == select.EPOLLIN:
					# do not start reading if we haven't noticed the socket is connected
					if self.sockets[sockfd]['connected_time'] == None: continue

					#
					part = self.sockets[sockfd]['object'].recv(1024)
					self.sockets[sockfd]['data'] += part

					if len(part) == 0:
						self.epoll.unregister(sockfd)
						self.sockets[sockfd]['state'] = 'closed'
						self.sockets[sockfd]['event'].set()
					else:
						self.sockets[sockfd]['state'] = 'reading'
						self.sockets[sockfd]['last_read_time'] = time.time()

				elif event == select.EPOLLERR:
					self.epoll.unregister(sockfd)
					self.sockets[sockfd]['state'] = 'error'
					self.sockets[sockfd]['event'].set()

				elif event == select.EPOLLHUP:
					# ignore as this can come before EPOLLIN
					pass

			# then process all of them for timeouts, etc.
			for sockfd in self.sockets.keys():
				socket_info = self.sockets[sockfd]

				# if it is still not connected, try again
				if socket_info['state'] == 'connecting':
					if (time.time()-socket_info['init_time']) > self.connect_timeout:
						try: self.epoll.unregister(sockfd)
						except: pass
						socket_info['state'] = 'connect_timeout'
						socket_info['event'].set()
					else:
						self.try_connect(socket_info)

				elif socket_info['state'] == 'sent':
					if (time.time()-socket_info['connected_time']) > self.read_timeout:
						try: self.epoll.unregister(sockfd)
						except: pass
						socket_info['state'] = 'initial_response_timeout'
						socket_info['event'].set()
					
				elif socket_info['state'] == 'reading':
					if (time.time()-socket_info['last_read_time']) > self.read_timeout:
						try: self.epoll.unregister(sockfd)
						except: pass
						socket_info['state'] = 'data_timeout'
						socket_info['event'].set()

				elif socket_info['state'] == 'connection_refused':
						try: self.epoll.unregister(sockfd)
						except: pass
						socket_info['event'].set()
					
				# enforce the full response time (only for connected sockets)
				if socket_info['connected_time'] != None:
					if (time.time()-socket_info['connected_time']) > self.response_timeout:
							try: self.epoll.unregister(sockfd)
							except: pass
							socket_info['state'] = 'response_timeout'
							socket_info['event'].set()
					
			self.sockets_lock.release()

	def parse_url(self, url):
		r = {}
		r['proto'] = url.split('://')[0]
		r['host']  = url.split('://', 1)[1].split('/', 1)[0]
		try:
			r['path'] = '/' + url.split('://', 1)[1].split('/', 1)[1]
		except:
			r['path'] = '/'

		if r['proto'] != 'http':
			print >>sys.stderr, "Invalid url '%s': only 'http' protocol is supported at the moment" % (url,)
			self.should_run = False

		return r

	def keep_busy(self, request_count, source_ips, urls, reserved):
		self.busy_data = {
			'request_count' : request_count,
			'source_ips'    : source_ips,
			'urls'          : [],
			'reserved'      : {},
		}

		for url in urls:
			self.busy_data['urls'].append(self.parse_url(url))

		for ip in reserved.keys():
			self.busy_data['reserved'][ip] = self.parse_url(reserved[ip])
			self.busy_data['reserved'][ip]['lastused'] = 0

		self.busy    = threading.Thread(target=self.start_thread, args=("starter", self.keep_busy_thread))
		self.busy.start()
		self.collect = threading.Thread(target=self.start_thread, args=("collector", self.collect_responses_thread))
		self.collect.start()

	def start_thread(self, name, function):
		try:
			function()
		except Exception, e:
			print >>sys.stderr, "Thread '%s' raised exception: %s" % (name, str(e),)
			if self.debug: raise

		signal.alarm(5)
		self.should_run = False

	def update_source_ips(self, source_ips):
		self.busy_data['source_ips'] = source_ips

	def keep_busy_thread(self):
		while self.should_run:
			start = time.time()

			for i in range(self.busy_data['request_count']):
				while True:
					ip = random.sample(self.busy_data['source_ips'], 1)[0]
					if ip in self.busy_data['reserved']:
						url = self.busy_data['reserved'][ip]

						if (self.busy_data['reserved'][ip]['lastused'] + 40) > start: 
							continue
						else:
							self.busy_data['reserved'][ip]['lastused'] = start
							break
					else:
						url = random.sample(self.busy_data['urls'], 1)[0]
						break

				self.request( ip, url['proto'], url['host'], url['path'] )
				time.sleep(float(1)/(float(self.busy_data['request_count'])*1.1))

			end = time.time()
			sleep = (float(1)-(end-start))
			if sleep > 0: time.sleep(sleep)
		
	def collect_responses_thread(self):
		while self.should_run:
			to_clean = []
			started = time.time()

			sockfds = self.sockets.keys()
			for sockfd in sockfds:
				if not self.sockets[sockfd]['event'].is_set(): continue

				state = self.sockets[sockfd]['state']
				data  = self.sockets[sockfd]['data']
		
				self.counters_lock.acquire()

				if state == 'closed':
					if data.startswith('HTTP/1.1 200 OK'):
						self.counters['ok'] += 1
					else:
						self.counters['invalid'] += 1
		
				elif state in ('connect_timeout', 'initial_response_timeout', 'data_timeout', 'response_timeout'):
#					print "timeout: " + str(self.sockets[sockfd]['object'].getsockname())
					if state not in self.counters['timeouts']: self.counters['timeouts'][state] = 0
					self.counters['timeouts'][state] += 1
		
				else:
					self.counters['error'] += 1

				self.counters_lock.release()

				to_clean.append(sockfd)

			for sockfd in to_clean:
				self.cleanup(sockfd)

			ended = time.time()
			if (ended-started < 1):
				time.sleep( ended-started )
			


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='HTTP traffic generator')
	parser.add_argument('--urls', help='File with the URLs (default /etc/httpgen/urls)', default="/etc/httpgen/urls")
	parser.add_argument('--ips', help='File with the source IP addresses (default /etc/httpgen/ips)', default="/etc/httpgen/ips")
	parser.add_argument('--proxy', help='Proxy server in IP:port format')
	parser.add_argument('--ctimeout', type=int, default=3, help='Connect timeout')
	parser.add_argument('--rtimeout', type=int, default=3, help='Timeout for each read')
	parser.add_argument('--stimeout', type=int, default=5, help='Session timeout')
	parser.add_argument('--reqs', type=int, help='Requests per second', required=True)
	parser.add_argument('--stats', help='Statistics output in format filename:interval', default="/dev/stdout:1")
	parser.add_argument('--reduce', help='Reduce the number of source IPs, format seconds:count', default="0:0")
	parser.add_argument('--reserve', help='Reserve the IP address for specific URL, format IP:URL', action='append', default=[])
	parser.add_argument('--cachedns', action='store_true', help='Remember IP for hostnames (no TTL check)', default=False)
	parser.add_argument('--debug', action='store_true', help='Enable debugging (do not use for production)', default=False)
	args = parser.parse_args()

	if args.proxy != None:
		try:
			proxy_ip   = args.proxy.split(':', 1)[0]
			proxy_port = int(args.proxy.split(':', 1)[1])
			proxy = (proxy_ip, proxy_port)
		except:
			print >>sys.stderr, "Proxy address is not in the right format (IP:port)."
			sys.exit(1)
	else:
		proxy = None
	
	try:
		stats_file = args.stats.split(':', 1)[0]
		stats_int  = int(args.stats.split(':', 1)[1])
	except:
		print >>sys.stderr, "Statistics output is not in the right format (filename:interval)."
		sys.exit(1)

	try:
		reduce_time  = int(args.reduce.split(':', 1)[0])
		reduce_count = int(args.reduce.split(':', 1)[1])
	except:
		print >>sys.stderr, "IP reduce is in not in the right format (seconds:count)."
		sys.exit(1)

	reserved = {}
	try:
		for tmp in args.reserve:
			reserved[tmp.split(':', 1)[0]] = tmp.split(':', 1)[1]
	except:
		print >>sys.stderr, "IP/URL reservation is not in the right format (IP:URL)"
		sys.exit(1)
	
	ips = []
	try:
		f = open(args.ips, "r")
		while True:
			line = f.readline()
			if len(line) == 0: break
			ips.append(line.strip())
	except Exception, e:
		print >>sys.stderr, "Cannot read source IPs from %s: %s" % (args.ips, str(e),)
		sys.exit(1)

	urls = []
	try:
		f = open(args.urls, "r")
		while True:
			line = f.readline()
			if len(line) == 0: break
			urls.append(line.strip())
	except Exception, e:
		print >>sys.stderr, "Cannot read URLs from %s: %s" % (args.urls, str(e),)
		sys.exit(1)

	try:
		stats = file(stats_file, "a")
	except Exception, e:
		print >>sys.stderr, "Cannot output statistics file \"%s\": %s" % (stats_file, str(e),)
		sys.exit(1)

	hg = HTTPgen( proxy, (args.ctimeout, args.rtimeout, args.stimeout), args.cachedns, args.debug )
	hg.keep_busy(args.reqs, ips, urls, reserved)
	started = time.time()

	try:
		while hg.should_run:
			counters = hg.clear_counters(interval=stats_int)
			timeouts = 0
			for t in counters['timeouts'].keys(): timeouts += counters['timeouts'][t]
			print >>stats, "%i %i %i %i %i %i" % (int(time.time()), args.reqs, counters['ok'], timeouts, counters['invalid'], counters['error'],)
			stats.flush()
			time.sleep(stats_int)

			# 
			if reduce_time > 0 and time.time() > started+reduce_time:
				reduce_time = 0
				hg.update_source_ips(random.sample(ips, reduce_count))

	except KeyboardInterrupt:
		pass

	stats.close()
	hg.destroy()


