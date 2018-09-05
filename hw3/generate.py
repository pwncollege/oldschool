import subprocess
import random
import string
import struct
import shutil
import time
import tqdm
import os

challenge_header = """
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>

void asdf(int i)
{
}

int main(int argc, char **argv, char **envp)
{
	int i,j,k,n,m,x,y;
	unsigned short *input_shorts;

	puts("====================");
	puts(argv[0]);
	puts("... license verifier");
	puts("====================");
	puts("This software will allow you to read the flag.");
	puts("However, before you can do so, you must verify that you are licensed to read flag files!");
	puts("This program consumes a license key over some communication channel that you must figure out.");
	puts("You must also figure out (by reverse engineering this program) what that license key is.");
	puts("Providing the correct license key will net you the flag!");
	puts("");
	puts("Good luck!");
"""
challenge_footer = """
	puts("");
	if (success)
	{
		puts("Correct! Here is your flag:");
		system("/get_flag");
		exit(0);
	}
	else
	{
		puts("Wrong! No flag for you!");
		exit(1);
	}

	return 0;
}
"""

def escape_string(s):
	h = s.encode('hex').lower()
	return '\\x'+'\\x'.join(h[i:i+2] for i in range(0, len(h), 2))

class Challenge(object):
	def __init__(self, wait_type, input_solution, input_type, input_src, input_offset, manglers, data_location, result_check, random_seed=0, read_fd=None):
		self._input_length = len(input_solution)

		assert input_type in VALID_INPUT_TYPES
		self._input_type = input_type

		assert (
			(type(input_src) is int) if input_type in [ "fd", "arg" ] else
			(type(input_src) is str and set(input_src).issubset(set(string.lowercase))) if input_type in [ "mmap", "fifo", "file", "env" ] else
			False
		)
		self._input_src = input_src

		assert type(input_offset) is int
		self._input_offset = input_offset

		assert all(m in VALID_MANGLERS for m in manglers)
		self._manglers = manglers

		assert wait_type in VALID_WAIT_TYPES
		self._wait_type = wait_type
		assert self._wait_type != "mmap" or self._input_type == "mmap"

		assert data_location in VALID_DATA_LOCATIONS
		self._data_location = data_location

		assert read_fd is None or (input_type == 'file' and type(read_fd) is int)
		self._read_fd = read_fd

		#assert use_getenv is False or input_type == 'env'
		#self._use_getenv = use_getenv

		assert "shuffle" not in manglers or random_seed != 0
		self._random_seed = random_seed
		self._random = random.Random(self._random_seed)
		self._shuffles = [
			(self._random.randrange(0, self._input_length), self._random.randrange(0, self._input_length))
			for _ in range(self._input_length * self._manglers.count('shuffle'))
		]

		self._input_solution = input_solution
		assert not { '\0', '\n', '\r', '\1', '\xff', '\xfe', '\xfd' } & set(self._input_solution)

		assert result_check in VALID_RESULT_CHECKS
		self._result_check = result_check

		self._expected_result = self._compute_mangled()

	def __repr__(self):
		return """Challenge(
	wait_type=%r,
	input_solution=%r,
	input_type=%r, input_src=%r, input_offset=%d,
	manglers=%s,
	data_location=%r,
	result_check=%r,
	random_seed=%d, read_fd=%r
)""" % (self._wait_type, self._input_solution, self._input_type, self._input_src, self._input_offset, self._manglers, self._data_location, self._result_check, self._random_seed, self._read_fd)

	def _compute_mangled(self):
		result = self._input_solution

		shuffle_iter = iter(self._shuffles)
		for m in self._manglers:
			if m == "reverse":
				result = result[::-1]
			if m == "shuffle":
				for _ in range(self._input_length):
					sl = list(result)
					s,d = next(shuffle_iter)
					sl[s], sl[d] = sl[d], sl[s]
					result = ''.join(sl)
			if m == 'sort':
				result = ''.join(sorted(result))
			if m == 'xor_ff':
				result = ''.join(chr(ord(c)^0xff) for c in result)
			if m == 'xor_42':
				result = ''.join(chr(ord(c)^0x42) for c in result)
			if m == 'xor_1337':
				rtrunc = result[:-1] if len(result)%2 else result
				fmt = "<%dH"%(len(rtrunc)/2)
				rtrunc = struct.pack(fmt, *[ x^0x1337 for x in struct.unpack(fmt, rtrunc) ])
				result = rtrunc + result[-1] if len(result)%2 else rtrunc

		return result

	def test(self, right=None):
		if right is None:
			self.test(right=True)
			self.test(right=False)
			return

		print "Testing %r right=%s" % (self, right)

		shutil.rmtree("/tmp/test")
		os.makedirs('/tmp/test')
		self.compile('/tmp/test/crackme')

		# write the expected solution to the file anyways
		solution = "0"*self._input_offset + (self._input_solution if right else "nope")
		with open('/tmp/test/solution', 'w') as o:
			o.write(solution)

		s = open('/tmp/test/solution')
		cmd = [ '/tmp/test/crackme' ]

		#
		# prepare input source
		#

		if self._input_type == 'arg':
			cmd += [ 'a' ] * (self._input_src - 1)
			cmd += [ solution ]

		if self._input_type in [ "file", "mmap" ]:
			os.link('/tmp/test/solution', '/tmp/test/'+self._input_src)

		target_fd = None
		if self._read_fd is not None or self._input_type == 'fd':
			target_fd = self._read_fd or self._input_src
			if target_fd != 0:
				os.dup2(s.fileno(), target_fd)

		env = os.environ.copy()
		if self._input_type == 'env':
			env[self._input_src] = solution

		print "Launching process!"
		p = subprocess.Popen(cmd, cwd='/tmp/test', stdin=s, stdout=subprocess.PIPE, stderr=2, env=env)

		if self._wait_type == 'sleep':
			time.sleep(0.5)
			print "Sending signal!"
			os.kill(p.pid, 10)

		if self._input_type == 'fifo':
			while not os.path.exists('/tmp/test/'+self._input_src):
				pass
			print "Writing to fifo!"
			with open('/tmp/test/'+self._input_src, 'w') as o:
				o.write(solution)

		print "Communicating!"
		stdout, _ = p.communicate()
		print stdout

		#
		# clean up
		#
		s.close()
		if target_fd:
			os.close(self._read_fd or self._input_src)

		assert ("Correct" in stdout) if right else ("Wrong" in stdout)

	def compile(self, filename):
		with open(filename+'.c', 'w') as o:
			o.write(self.emit())
		assert os.system('gcc -O1 -Wno-unused-result %s.c -o %s' % (filename, filename)) == 0

	def emit(self):
		code = challenge_header

		# wait
		if self._wait_type == "sleep":
			code += """
	puts("Taking a brief nap...");
	signal(SIGUSR1, asdf);
	sleep(31337);
	puts("");
	puts("Ready to receive your license key!");
"""

		# allocate the input
		if self._data_location == "stack":
			code += """
	unsigned char input[%d];
""" % (self._input_length + 16)
		elif self._data_location == "heap":
			code += """
	unsigned char *input = malloc(%d);
""" % (self._input_length + 16)

		#
		# open the input file
		if self._input_type == "fifo":
			code += """
	assert(mkfifo("%s", 0666) == 0);
""" % self._input_src

		if self._input_type in ["fifo", "file", "mmap"]:
			code += """
	int input_fd = open("%s", 0);
	assert(input_fd > 0);
""" % self._input_src

		if self._input_type == "mmap":
			code += """
	unsigned char *input_map = mmap(0, 0x1000, 4, MAP_SHARED, input_fd, 0);
	assert(input_map != (void *)-1);
"""

		if self._input_type == "fd":
			code += """
	int input_fd = %d;
""" % self._input_src

		# sneaky override
		if self._read_fd is not None:
			code += """
	input_fd = %d;
""" % self._read_fd

		# not needed for: arg, env

		#
		# get the input
		#
		if self._input_type in [ "file" ]:
			code += """
	lseek(input_fd, %d, SEEK_SET);
	read(input_fd, input, %d);
""" % (self._input_offset, self._input_length)

		if self._input_type in [ "fd", "fifo" ]:
			code += """
	char *garbage = malloc(%d);
	read(input_fd, garbage, %d);
	read(input_fd, input, %d);
""" % (self._input_offset, self._input_offset, self._input_length)

		if self._input_type == "arg":
			code += """
	assert(argc > %d);
	memcpy(input, argv[%d]+%d, %d);
""" % (self._input_src, self._input_src, self._input_offset, self._input_length)

		if self._input_type == "mmap":
			code += """
	memcpy(input, input_map + %d, %d);
""" % (self._input_offset, self._input_length)

		if self._input_type == "env":
			code += """
	i = 0;
	while (envp[i])
	{
		if (strncmp(envp[i], "%s", %d) == 0) memcpy(input, envp[i] + %d + %d + 1, %d);
		i++;
	}
""" % (self._input_src, len(self._input_src), len(self._input_src), self._input_offset, self._input_length)

		code += """
	input[%d] = 0;
	input[%d] = 0;
	puts("");
	puts("Checking the received license key!");
""" % (self._input_length, self._input_length+1)

		#
		# mangle the input
		#
		#assert all(m in [ "reverse", "shuffle", "sort", "bitflip", "xor_1337", "xor_42" ] for m in manglers)

		shuffle_iter = iter(self._shuffles)
		for m in self._manglers:
			if m == "reverse":
				code += """
	for (i = 0; i < %d/2; i++)
	{
		j = input[i];
		k = input[%d-i-1];
		input[i] = k;
		input[%d-i-1] = j;
	}
""" % (self._input_length, self._input_length, self._input_length)

			if m == "sort":
				code += """
	for (i = 0; i < %d-1; i++)      
		// Last i elements are already in place   
		for (j = 0; j < %d-i-1; j++) 
			if (input[j] > input[j+1])
			{
				x = input[j];
				y = input[j+1];
				input[j] = y;
				input[j+1] = x;
			}
""" % (self._input_length, self._input_length)

			if m == "xor_42":
				code += """
	for (i = 0; i < %d; i++)      
		input[i] ^= 0x42;
""" % (self._input_length)

			if m == "xor_ff":
				code += """
	for (i = 0; i < %d; i++)      
		input[i] ^= 0xff;
""" % (self._input_length)

			if m == "xor_1337":
				code += """
	input_shorts = (unsigned short *)&input[0];
	for (i = 0; i < %d/2; i++)
		input_shorts[i] ^= 0x1337;
""" % (self._input_length)

			if m == "shuffle":
				for _ in range(self._input_length):
					s,d = next(shuffle_iter)
					code += """
	i = input[%d];
	j = input[%d];
	input[%d] = j;
	input[%d] = i;
""" % (s, d, s, d)

		#
		# and the check
		#
		if self._result_check == "strcmp":
			code += """
	int success = strcmp(input, "%s") == 0;
""" % escape_string(self._expected_result)
		elif self._result_check == "memcmp":
			code += """
	int success = memcmp(input, "%s", %d) == 0;
""" % (escape_string(self._expected_result), len(self._expected_result))

		code += challenge_footer
		return code

VALID_INPUT_TYPES = [ "fd", "arg", "env", "mmap", "fifo", "file" ]
VALID_MANGLERS = [ "reverse", "shuffle", "sort", "xor_ff", "xor_1337", "xor_42" ]
VALID_DATA_LOCATIONS = ["stack", "heap"]
#VALID_WAIT_TYPES = [ "none", "sleep", "signal", "mmap" ]
VALID_WAIT_TYPES = [ "none", "sleep" ]
VALID_RESULT_CHECKS = [ "memcmp", "strcmp" ]

def generate_args(seed=0, difficulty=0, **kw):
	r = random.Random(seed)

	kw.setdefault('wait_type', r.choice(VALID_WAIT_TYPES))
	kw.setdefault('input_type', r.choice(VALID_INPUT_TYPES))

	if kw['input_type'] in [ 'mmap', 'fifo', 'file', 'env' ]:
		kw.setdefault('input_src', ''.join(r.choice(string.lowercase) for _ in range(5)))
	elif kw['input_type'] == 'fd':
		if difficulty < 2:
			kw.setdefault('input_src', 0)
		elif difficulty < 10:
			kw.setdefault('input_src', r.randrange(20, 800))
		else:
			kw.setdefault('input_src', r.randrange(1, 3))
	elif kw['input_type'] == 'arg':
		kw.setdefault('input_src', r.randrange(1, 1337))
	else:
		assert False

	if kw['input_type'] == 'file' and difficulty > 5 and r.randrange(0, 3) == 0:
		kw.setdefault('read_fd', r.randrange(20, 800))

	if difficulty > 3:
		kw.setdefault('input_offset', r.randrange(0, 128))
	else:
		kw.setdefault('input_offset', 0)

	kw.setdefault('input_solution', ''.join(r.choice(string.lowercase) for _ in range(r.randrange(2*(difficulty+1), 4*(difficulty+1)))))

	kw.setdefault('manglers', [ r.choice(VALID_MANGLERS) for _ in range(difficulty) ])
	kw.setdefault('data_location', r.choice(VALID_DATA_LOCATIONS))
	kw.setdefault('result_check', r.choice(VALID_RESULT_CHECKS))
	kw.setdefault('random_seed', seed)

	return kw

def test():
	for _input_type in VALID_INPUT_TYPES:
		for _d in range(10):
			seed_start = VALID_INPUT_TYPES.index(_input_type)*1000 + _d*100
			seed_end = seed_start + 8
			for _s in range(seed_start, seed_end):
				print "Settings:", _d, _s
				c = Challenge(**generate_args(wait_type='none', seed=_s, difficulty=_d, input_type=_input_type))
				c.test()

	# test sleep a bit
	for _input_type in VALID_INPUT_TYPES:
		for _d in range(5):
			for _s in range(2):
				print "Settings:", _d, _s
				c = Challenge(**generate_args(wait_type='sleep', seed=_s, difficulty=_d, input_type=_input_type))
				c.test()

	print "ALL DONE!"

COMPANIES = [ 'adobe', 'amazon', 'apple', 'facebook', 'google', 'hp', 'lg', 'microsoft', 'mozilla', 'nokia', 'yahoo' ]
WORDS = [ w.strip().lower() for w in open(os.path.join(os.path.dirname(__file__), 'words')).readlines() if set(w.strip().lower()).issubset(string.lowercase) and len(w.strip()) > 6 ]
def create(dirname):
	# 6 total input types
	# 11 difficulty levels
	# 2 per type per level
	for _u in tqdm.tqdm(range(200)):
		for _d in range(11):
			for _i in VALID_INPUT_TYPES:
				_s_start = 10000*_u + 1000*_d + 100*VALID_INPUT_TYPES.index(_i)
				_s_end = _s_start + 2
				for _s in range(_s_start, _s_end):
					try: os.makedirs(os.path.join(dirname, str(_u)))
					except OSError: pass
					c = Challenge(**generate_args(seed=_s, difficulty=_d, input_type=_i))
					c.compile(os.path.join(dirname, str(_u), "%s_%s" % (COMPANIES[_d], WORDS[_s%len(WORDS)])))

if __name__ == '__main__':
	import sys
	if sys.argv[1] == 'test':
		test()
	else:
		create('challenges')
