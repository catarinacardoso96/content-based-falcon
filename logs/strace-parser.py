from __future__ import print_function

import re
import sys
import json
import difflib
import progressbar
from collections import deque
from rabin import Rabin, set_min_block_size, set_average_block_size, set_max_block_size

####################################################################################################

flag = sys.argv[1]
if flag == 'table':
	print_flag = 0
elif flag == 'ftable':
	print_flag = 1
elif flag == 'json':
	print_flag = 2
elif flag == 'mean':
	print_flag = 3
elif flag == 'match':
	print_flag = 4
else:
	print_flag = -1

files = sys.argv[2:]

####################################################################################################

if print_flag == 0 or print_flag == 1:
	print("%-12s %-6s %-8s %-40s %-35s %-6s %-7s %-6s" %
		 ("TIMESTAMP", "PID", "SYSCALL", "FD", "BUF", "SIZE", "RETURN", "OBS"))

if print_flag == 4:
    print("%-5s %-5s %-5s %-6s %-7s %-7s" %
		 ("MIN", "AVG", "MAX", "COUNT", "SMEAN", "MATCH"))

def print_table(timestamp, pid, syscall, fd, buf, size, r_value, obs):
	print("%-12d %-6d %-8s %-40.40s %-35.35s %-6s %-7s %-6s" %
		 (timestamp, pid, syscall, fd, buf, size, r_value, obs))

def print_table_obs(timestamp, pid, syscall, fd, buf, size, r_value, obs):
	if print_flag == 0:
		print_table(timestamp, pid, syscall, fd, buf, size, r_value, obs)

def eprint(*args, **kwargs):
	print(*args, file=sys.stderr, **kwargs)

####################################################################################################

def convert_timestamp(timestamp):
	a = timestamp.split(":")
	b = a[2].split(".")

	hrs = int(a[0])
	mins = int(a[1])
	secs = int(b[0])
	usecs = int(b[1])

	return ((hrs*60 + mins)*60 + secs)*1000000 + usecs

def generate_socket_id(addr1, addr2, port1, port2):

	if addr1 < addr2:
		socket_id = "%s:%d-%s:%d" % (addr1, port1, addr2, port2)
	elif addr2 < addr1:
		socket_id = "%s:%d-%s:%d" % (addr2, port2, addr1, port1)
	else:
		if port1 < port2:
			socket_id = "%s:%d-%s:%d" % (addr1, port1, addr2, port2)
		else:
			socket_id = "%s:%d-%s:%d" % (addr2, port2, addr1, port1)

	return socket_id

####################################################################################################

def parse_file_descriptor(file_descriptor):
	a = re.split("<", file_descriptor, 1)
	fd = int(a[0])

	b = re.split(":\[", a[1], 1)
	socket_type = b[0]

	c = re.split(":", b[1], 1)
	src = c[0]

	d = re.split("->", c[1], 1)
	src_port = int(d[0])

	e = re.split(":", d[1], 1)
	dst = e[0]

	e = re.split("\]>", e[1],1)
	dst_port = int(e[0])

	socket = generate_socket_id(src, dst, src_port, dst_port)

	return fd, socket_type, src, src_port, dst, dst_port, socket

def parse_pid_timestamp(line):
	a = re.split("\s+", line, 1)
	pid = int(a[0])

	b = re.split("\s+", a[1], 1)
	timestamp = convert_timestamp(b[0])
	remnant = b[1]

	return pid, timestamp, remnant

def parse_syscall_fd(line):
	a = re.split("\(", line, 1)
	syscall = a[0]

	b = re.split(",\s+", a[1], 1)
	fd = b[0]
	remnant = b[1]

	return syscall, fd, remnant

def parse_buffer_size(line):
	#print(line)
	a = re.split("\"\.*,\s+(?=[0-9]+\)?\s)", line[1:], 1) # remove tick "
	buffer = a[0]
	#print(buffer)
	b = re.split("\)?\s+(?=\=\s+[0-9]+)", a[1], 1)

	if re.search("\<unfinished", b[0]):
		b = re.split("\<unfinished", b[0])

	size = int(b[0])
	remnant = b[1]

	return buffer, size, remnant

def parse_return_value(line):
	a = re.split("\=\s+", line, 1)
	r_value = int(a[1])

	return r_value

def parse_resumed(line):
	a = re.split("\sresumed\>\s+", line, 1)  # <... ... resumed>
	syscall = a[0][5:] # remove "<... "
	remnant = a[1]

	return syscall, remnant

####################################################################################################

def create_entry(timestamp, thread, syscall, file_descriptor, message, size, syscall_exit):

	if not re.search("^\d+\<TCP:", file_descriptor):
		return

	fd, socket_type, src, src_port, dst, dst_port, socket = parse_file_descriptor(file_descriptor)

	thread = "%d@%s" % (thread, src)

	if syscall == "read":
		type = "RCV"
		src, dst = dst, src
		src_port, dst_port = dst_port, src_port

	elif syscall == "write":
		type = "SND"

	else:
		return

	entry = {
		"id": None,
		"thread": thread,
		"timestamp": timestamp,
		"type": type,
		"src": src,
		"src_port": src_port,
		"dst_port": dst_port,
		"dst": dst,
		"socket_type": socket_type,
		"socket": socket,
		"size": syscall_exit,
		"data": {
			"similarity": {},
			"syscall_exit": syscall_exit,
			#"syscall": syscall,
			#"fd": fd,
			"message": message.translate(None, "\\x").decode('hex'),
			"message_hex": message.translate(None, "\\x"),
			#"exit_timestamp": exit_timestamp,
			#"enter_timestamp": enter_timestamp
		}
	}

	global trace
	trace.append(entry)

####################################################################################################
#'''
size_table = [[4,  8, 8,  16, 16, 32, 32,  64, 64,  128, 128, 256, 256,  512, 512,  1024],
			  [8,  8, 16, 16, 32, 32, 64,  64, 128, 128, 256, 256, 512,  512, 1024, 1024],
			  [16, 8, 32, 16, 64, 32, 128, 64, 256, 128, 512, 256, 1024, 512, 2048, 1024]]
'''
size_table = [[256,  512, 512,  1024, 1024, 2048, 2048, 4096, 4096,  8192, 8192],
			  [512,  512, 1024, 1024, 2048, 2048, 4096, 4096, 8192,  8192, 16384],
			  [1024, 512, 2048, 1024, 4096, 2048, 8192, 4096, 16384, 8192, 32768]]
'''
def init_rabin(min, avg, max):
	rfp = Rabin()

	set_min_block_size(min)
	set_max_block_size(max)
	set_average_block_size(avg)
	#set_window_size(12)
	#set_prime(5)

	return rfp

def convert_rabin(buf):
	global rfp
	rfp.clear()
	rfp.update(buf)

	fprints = [i[1:] for i in rfp.fingerprints()] # remove offset

	return fprints

def compute_similarity(min, avg, max):
	global rfp
	rfp = init_rabin(min, avg, max)

	queue = deque([])
	queue_max_size = 200

	similarity_counter = 0
	similarity_sum = 0

	with progressbar.ProgressBar(max_value=counter) as similarity_bar:

		for entry in ordered_trace:

			id = entry['id']
			message = entry['data']['message']
			size = len(message)
			fprints = convert_rabin(message)

			for (q_entry, q_id, q_size, q_fprints) in queue:
				b_size = size if size >= q_size else q_size
				match = 0

				seq_match = difflib.SequenceMatcher(None, fprints, q_fprints)
				info_list = seq_match.get_matching_blocks()

				for info in info_list:
					matching_blocks = fprints[info.a:info.a + info.size]
					for block in matching_blocks:
						match += block[0]/float(b_size) * 100 # get lenght

				if match != 0:
					r_match = round(match, 2)

					entry['data']['similarity'][q_id] = r_match
					q_entry['data']['similarity'][id] = r_match

					similarity_counter += 1
					similarity_sum += r_match

			queue.append((entry, id, size, fprints))
			if len(queue) > queue_max_size:
				queue.popleft()

			similarity_bar.update(id)

########################################################

	if print_flag == 4:
		match_counter = 0

		for entry in ordered_trace:
			if entry['data']['similarity']:
				match_counter += 1
			entry['data']['similarity'] = {} # clear entries from other iterations

		match_mean = match_counter/float(counter) * 100 if counter > 0 else 0
		similarity_mean = similarity_sum/similarity_counter if similarity_counter > 0 else 0

		print("%-5s %-5s %-5s %-6s %-7s %-7s" %
			 (size_table[0][i], size_table[1][i], size_table[2][i], similarity_counter, round(similarity_mean, 2), round(match_mean, 2)))

####################################################################################################

stack = {} # stack with unfinished syscall
trace = [] # list of dict

####################################################################################################

eprint("parsing")

for file_name in files:
	file = open(file_name, "r")
	line_num = 0
	num_lines = sum(1 for line in open(file_name, "r")) # remove for efficiency improvement

	with progressbar.ProgressBar(max_value=num_lines) as parsing_bar:

		for line in file:
			pid, timestamp, line = parse_pid_timestamp(line)

			if re.search("-1 EAGAIN \(Resource temporarily unavailable\)$", line)\
			 or line[:3] == '---' or line[:3] == '+++':
				# if -1 EAGAIN (Resource temporarily unavailable)
				# or --- SIG... ---
				# or +++ exited with .. +++
				continue

			elif line[0] != '<': # if not "<... resumed"
				syscall, fd, line = parse_syscall_fd(line)

				if not re.search("\<unfinished", line):
					buffer, size, line = parse_buffer_size(line)
					r_value = parse_return_value(line)

					create_entry(timestamp, pid, syscall, fd, buffer, size, r_value)
					print_table_obs(timestamp, pid, syscall, fd, buffer, size, r_value, "")

				else:
					if syscall == "read": # read "<unfinished ...>"
						stack.setdefault(pid,[]).append({'syscall': syscall, 'fd': fd})
						print_table_obs(timestamp, pid, syscall, fd, "-", "-", "-", "unfinished")

					elif syscall == "write":  # write "<unfinished ...>"
						buffer, size, line = parse_buffer_size(line)
						stack.setdefault(pid,[]).append({'syscall': syscall, 'fd': fd, 'buffer': buffer, 'size': size})
						print_table_obs(timestamp, pid, syscall, fd, buffer, size, "-", "unfinished")

			else: # if "<... resumed"
				if pid in stack:
					item = stack[pid].pop()
					syscall, line = parse_resumed(line)

					if syscall == "read": # <... read resumed>
						buffer, size, line = parse_buffer_size(line)
						r_value = parse_return_value(line)

						create_entry(timestamp, pid, syscall, fd, buffer, size, r_value)
						print_table_obs(timestamp, pid, item['syscall'], item['fd'], buffer, size, r_value, "resumed")

					elif syscall == "write":  # <... write resumed>
						r_value = parse_return_value(line)

						create_entry(timestamp, pid, syscall, fd, buffer, size, r_value)
						print_table_obs(timestamp, pid, item['syscall'], item['fd'], item['buffer'], item['size'], r_value, "resumed")

			line_num += 1
			parsing_bar.update(line_num)

####################################################################################################

ordered_trace = sorted(trace, key=lambda k: k['timestamp'])
counter = 0

for entry in ordered_trace: # assign id to message
	entry['id'] = counter
	counter += 1

####################################################################################################

if print_flag == 1:
	for entry in ordered_trace:
		print_table(entry['timestamp'], entry['thread'], entry['data']['syscall'], entry['socket'],
					entry['message'], entry['size'], entry['data']['syscall_exit'], '')

####################################################################################################

elif print_flag == 2:
	eprint("computing similarity")
	compute_similarity(64, 128, 256)
	#compute_similarity(512, 1024, 2028)

	eprint("printing")
	special_trace = []

	for entry in ordered_trace:

		#if entry['id'] > 480 and entry['id'] < 666:
		#if "4861646f6f702069732074686520456c657068616e74204b696e67210a" in entry['data']['message_hex']:
		#if entry['id'] == 484 or entry['id'] == 485 or entry['id'] == 486 or entry['id'] == 487:
			#del entry['data']['message_hex']
		del entry['data']['message']
		special_trace.append(entry)

	#print(json.dumps(ordered_trace, indent=4))
	print(json.dumps(special_trace, indent=4))

####################################################################################################

elif print_flag == 3:

	sum = 0 # sum size
	sum_len = 0 # sum length buffer
	sum_exit = 0 # sum syscall return value

	for entry in ordered_trace:
		sum += entry['size']
		sum_len += len(entry['data']['message'])
		sum_exit += entry['data']['syscall_exit']

	print("mean size = " + str(sum/counter)) # based on lenght given by strace
	print("mean msg = " + str(sum_len/counter)) # based on lenght calculated by len(message)
	print("mean syscall exit = " + str(sum_exit/counter)) # based on lenght given by syscall return value

	print("sum size = " + str(sum))
	print("sum len = " + str(sum_len))
	print("sum syscall exit = " + str(sum_exit))

####################################################################################################

elif print_flag == 4:
	eprint("computing similarity")
	for i in range(0, len(size_table[0])):
		compute_similarity(size_table[0][i], size_table[1][i], size_table[2][i])

####################################################################################################
