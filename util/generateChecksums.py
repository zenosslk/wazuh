#!/usr/bin/python
import fnmatch
import os
import sqlite3
import signal
import sys
import os.path


def signal_handler(signal, frame):
	print "Interrupted!"
	if (conn):
		conn.commit()
		conn.close()
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
conn = sqlite3.connect('/var/ossec/etc/md5db.db')
for file in os.listdir('/var/lib/dpkg/info'):
	if fnmatch.fnmatch(file, '*.md5sums'):
		c = conn.cursor()
		f = open('/var/lib/dpkg/info/' + file, 'r') 
		l = f.readline()
		while l:
			array = l.split()
			try:
				c.execute('INSERT INTO files VALUES("' + array[0] + '","' + array[1] + '",date("now"))')
			except sqlite3.Error, e:
				 print "%s: %s" % (array[0], e.args[0])
			l = f.readline()
		conn.commit()
		f.close()
conn.close()
