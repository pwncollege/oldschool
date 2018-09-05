import subprocess
import random
import string
import struct
import time
import os

challenge_header = """
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdin.h>

int main(int argc, char **argv, char **envp)
{
	int i,j,k,n,m,x,y;
"""
challenge_footer = """
		if (correct)
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

class Challenge(object):
	def __init__(self, wait_type, input_solution, input_type, input_src, input_offset, manglers, data_location, result_check, random_seed=0, read_fd=None):
		self._input_length = len(input_solution)

		assert input_type in [ "fd", "arg", "env", "mmap", "fifo", "file" ]
		self._input_type = input_type

		assert (
			(type(input_src) is int) if input_src in [ "fd", "arg" ] else
			(type(input_src) is str and set(input_src).issubset(set(string.lowercase))) if input_src in [ "mmap", "fifo", "file", "env" ] else
			False
		)
		self._input_src = input_src

		assert type(input_offset) is int
		self._input_offset = input_offset

		assert all(m in [ "reverse", "shuffle", "sort", "xor_ff", "xor_1337", "xor_42" ] for m in manglers)
		self._manglers = manglers

		assert wait_type in [ "none", "sleep", "signal", "mmap" ]
		self._wait_type = wait_type
		assert self._wait_type != "mmap" or self._input_type == "mmap"

		assert data_location in ["stack", "heap"]
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
		assert not { '\0', '\n', '\r', '\1', '\xff', '\xfe', '\xfd' } & self._input_solution

		assert result_check in [ "memcmp", "strcmp" ]
		self._result_check = result_check

		self._expected_result = self._compute_mangled()

	def _compute_mangled(self):
		result = self._input_solution

		shuffle_iter = iter(self._shuffles)
		for m in self._manglers:
			if m == "reverse":
				result = result[::-1]
			if m == "shuffle":
				for _ in range(len(self._input_length)):
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
				rtrunc = result[:-(len(result)%2)]
				fmt = "<%dH"%(len(rtrunc)/2)
				rtrunc = struct.pack(x^0x1337 for x in struct.unpack(fmt, result))
				if len(rtrunc) < len(result):
					rtrunc += result[-1]
				result = rtrunc

		return result

	def test(self, right=None):
		if right is None:
			assert self.test(right=True)
			assert self.test(right=False)
			return

		print "Testing %r right=%s" % (self, right)

		try: os.makedirs('/tmp/test')
		except OSError: pass
		self.compile('/tmp/test/bin')

		# write the expected solution to the file anyways
		solution = "0"*self._input_offset + (self._input_solution if right else "nope")
		with open('/tmp/test/solution', 'w') as o:
			o.write(solution)

		s = open('/tmp/test/solution')
		cmd = [ '/tmp/test/bin' ]

		#
		# prepare input source
		#

		if self._input_type == 'arg':
			cmd += [ 'a' ] * (self._input_src - 1)
			cmd += [ solution ]

		if self._input_type in [ "file", "mmap" ]:
			os.link('/tmp/test/solution', '/tmp/test/'+self._input_src)

		if self._read_fd is not None or self._input_type == 'fd':
			os.dup2(s.fileno(), self._read_fd or self._input_src)

		env = os.environ()
		if self._input_type == 'env':
			env[self._input_src] = solution

		p = subprocess.Popen(cmd, cwd='/tmp/test', stdin=s, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		time.sleep(1)

		if self._input_src == 'fifo':
			with open('/tmp/test/'+self._input_src, 'w') as o:
				o.write(solution)

		stdout, _ = p.communicate()

		#
		# clean up
		#
		s.close()
		if self._read_fd is not None or self._input_type == 'fd':
			os.close(self._read_fd or self._input_src)

		assert ("Correct" in stdout) if right else ("Wrong" in stdout)

	def compile(self, filename):
		with open(filename+'.c', 'w') as o:
			o.write(self.emit())
		assert os.system('gcc %s.c -o %s' % (filename, filename)) == 0

	def emit(self):
		code = challenge_header

		# allocate the input
		if self._data_location == "stack":
			code += """
	unsigned char input[%d];
""" % self._input_length
		elif self._data_location == "heap":
			code += """
	unsigned char *input = malloc(%d);
""" % self._input_length

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
	assert(input_map != -1);
""" % self._input_src

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
		if self._input_type in [ "fd", "fifo", "file" ]:
			code += """
	lseek(input_fd, %d, SEEK_SET);
	read(input_fd, input, %d);
""" % (self._input_offset, self._input_length)

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
	int i = 0;
	while (envp[i])
	{
		if (strncmp(envp[i], "%s", %d) == 0) memcpy(input, envp[i] + %d + %d + 1);
	}
""" % (self._input_src, len(self._input_src), len(self._input_src), self._input_offset)

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
		k = input[%d-i];
		input[i] = k;
		input[%d-i] = j;
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
		input[j] ^= 0x42;
""" % (self._input_length, self._input_length)

			if m == "xor_ff":
				code += """
	for (i = 0; i < %d; i++)      
		input[j] ^= 0xff;
""" % (self._input_length, self._input_length)

			if m == "xor_1337":
				code += """
	unsigned short *input_shorts;
	for (i = 0; i < %d/2; i++)      
		input_short[j] ^= 0x1337;
""" % (self._input_length, self._input_length)

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
			success = strcmp(input, %r) == 0;
	""" % self._expected_result
		elif self._result_check == "memcmp":
			code += """
			success = memcmp(input, %r, %d) == 0;
	""" % (self._expected_result, len(self._expected_result))

		code += challenge_footer
		return code

if __name__ == '__main__':
	c = Challenge(
		wait_type='none',
		input_solution="hello!",
		input_type="fd", input_src=0, input_offset=0,
		manglers = [ ],
		data_location = 'stack',
		result_check = 'memcmp',
		random_seed=0, read_fd=None
	)
	c.test()
