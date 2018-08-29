#include <sys/sendfile.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

int main()
{
	int fd = open("/flag", 0);
	if (fd < 0)
	{
		perror("Error opening /flag");
		exit(1);
	}

	sendfile(0, fd, 0, 1024);
}
