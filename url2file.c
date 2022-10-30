#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <limits.h>
#include <libgen.h>
#define ARCH 8
#define PATH_MAXIMUM 400

char *file_path = "/tmp/index.html";
char *dir_path = "/tmp/";
char *dlfile_name = "";
char *current_dir;
char command[PATH_MAXIMUM];
char fp[PATH_MAXIMUM];
char dp[PATH_MAXIMUM];
char lfp[PATH_MAXIMUM];
char dl_fp[PATH_MAXIMUM];

int is_file_exists(char *file_path)
{
	FILE *fptr = fopen(file_path, "r");
	if (fptr == NULL)
		return 0;

	fclose(fptr);
	return 1;
}

void cleanup()
{
	sprintf(command, "%s%s%s%s", "rm -rf ", current_dir, dir_path, "* 2>/dev/null");
	system(command);
	sprintf(command, "%s%s%s%s", "rm -rf ", current_dir, dir_path, ".* 2>/dev/null");
	system(command);
}

void prepare_file_location()
{
	sprintf(command, "%s%s%s%s", "mkdir ", current_dir, dir_path," 2>/dev/null");
	system(command);
}
void change_permission(char *fp)
{
	char *chg_per_cmd;
	chg_per_cmd = (char*) malloc(255* sizeof(char));
	sprintf(chg_per_cmd, "%s%s", "/bin/chmod 777 ", fp);
	system(chg_per_cmd);
}
void prepare_command(char *url, int type)
{
	if (type == 1)
	{
		char *cmd = "wget -q -O ";
		sprintf(command, "%s%s%s%s%s", cmd, current_dir, file_path, " ", url);
	}
	else if (type == 2)
	{
		char *cmd = "cp ";
		sprintf(command, "%s%s%s%s%s", cmd, url, " ", current_dir, dir_path);
	}
	else if (type == 3)
	{
		char *cmd = "wget -q -O ";
		sprintf(command, "%s%s%s%s%s%s", cmd, current_dir, dir_path, dlfile_name, " ", url);
	}
}

int checkurl(const char *url)
{
	if ((strncmp(url, "http://", strlen("http://")) == 0) || (strncmp(url, "https://", strlen("https://")) == 0))
		return 1;
	return 0;
}

int checkfilename_included(const char *str, const char *token)
{
	char *p = strstr(str, token);
	if (p)
		return 1;
	return 0;
}

int isExistfile(const char *str)
{
	char *check_file = realpath(str, NULL);
	if (check_file)
		return 1;
	return 0;
}

void getdata_from_tracee_addrspace(pid_t pid, long addr, char *buffer)
{
	long _addr;
	int i;
	_addr = addr;

	do {
		long value;
		char *p;
		value = ptrace(PTRACE_PEEKTEXT, pid, _addr, NULL);
		_addr += sizeof(long);

		p = (char*) &value;
		for (i = 0; i < sizeof(long); ++i, ++buffer)
		{*buffer = *p++;
			if (*buffer == '\0')
				break;
		}
	} while (i == sizeof(long));
}

void putdata_to_tracee_addrspace(pid_t pid, long addr, char *buffer)
{
	union u
	{
		long value;
		char str[sizeof(long)];
	}
	data;
	int length = strlen(buffer);
	int j = 0;
	int i = 0;
	char *laddr;
	laddr = buffer;
	for (; i < (length / sizeof(long)) + 1; ++i)
	{
		memcpy(data.str, laddr, sizeof(long));
		ptrace(PTRACE_POKEDATA, pid, addr + i *ARCH, data.value);
		laddr += sizeof(long);
	}

	j = length % sizeof(long);

	if (j != 0)
	{
		memcpy(data.str, laddr, j);
		ptrace(PTRACE_POKEDATA, pid, addr + i *ARCH, data.value);
	}
}

int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		fprintf(stderr, "Not enough arguments\n");
		exit(0);
	}
	int status;
	long syscall;
	int in_syscall = 0;
	char *str;
	int file_on_disc = 0;

	current_dir = (char*) malloc(100* sizeof(char));
	getcwd(current_dir, PATH_MAX);

	sprintf(fp, "%s%s", current_dir, file_path);
	sprintf(dp, "%s%s", current_dir, dir_path);

	cleanup();
	prepare_file_location();

	pid_t pid = fork();
	if (pid == 0)
	{
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		kill(getpid(), SIGSTOP);
		execvp(argv[1], argv + 1);
	}
	else
	{
		ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD);
		ptrace(PTRACE_SYSCALL, pid, NULL, NULL);

		while (1)
		{
			pid = waitpid(-1, &status, __WALL);

			if (WIFEXITED(status))
			{
				break;
			}

			if (WSTOPSIG(status) == SIGTRAP)
			{
				struct user_regs_struct regs2;
				ptrace(PTRACE_GETREGS, pid, 0, &regs2);

				if (regs2.orig_rax == SYS_execve)
				{
					str = (char*) malloc(255* sizeof(char));
					//getdata_from_tracee_addrspace(pid, (long) regs2.rdi, str);
					//printf("%s\n",str);
					//getdata_from_tracee_addrspace(pid, ((long) regs2.rdi + 8), str);	
					//printf("%s\n",str);

					getdata_from_tracee_addrspace(pid, ((long) regs2.rdi + 11), str);
					
					if (checkurl(str))
					{
						printf("Remote File Address to Download: %s\n", str);
						dlfile_name = basename(str);
						if (dlfile_name)
						{
							sprintf(dl_fp, "%s%s", dp, dlfile_name);
							printf("Downloaded File Path: %s\n", dl_fp);
							prepare_command(str, 3);
							//if (is_file_exists(lfp) == 0)
							{
								system(command);
								putdata_to_tracee_addrspace(pid, ((long) regs2.rdi + 11), dl_fp);
								file_on_disc = 1;
							}
							//if (file_on_disc == 1)
							{
								change_permission(dl_fp);
							}
						}
						else
							printf("please enter a valid file in your URL\n");
					}
				}
			}

			struct user_regs_struct regs;
			ptrace(PTRACE_GETREGS, pid, 0, &regs);
			syscall = regs.orig_rax;
			file_on_disc = 0;
			if (syscall == SYS_open)
			{
				if (in_syscall == 0)
				{
					in_syscall = 1;
					str = (char*) malloc(255* sizeof(char));
					getdata_from_tracee_addrspace(pid, (long) regs.rdi, str);

					if (checkurl(str))
					{
						prepare_command(str, 1);
						if (is_file_exists(fp) == 0)
						{
							system(command);
							putdata_to_tracee_addrspace(pid, (long) regs.rdi, fp);
							file_on_disc = 1;
						}
					}
				}
				else
				{
					in_syscall = 0;
				}
			}

			if (syscall == SYS_openat)
			{
				if (in_syscall == 0)
				{
					in_syscall = 1;
					str = (char*) malloc(255* sizeof(char));
					getdata_from_tracee_addrspace(pid, (long) regs.rsi, str);
					if (checkurl(str))
					{
						prepare_command(str, 1);
						if (is_file_exists(fp) == 0)
						{
							system(command);
							putdata_to_tracee_addrspace(pid, (long) regs.rsi, fp);
							file_on_disc = 1;
						}
					}
					if (file_on_disc == 0)
					{
						if (isExistfile(str))
						{
							if (checkfilename_included(str, basename(argv[2])))
							{
								prepare_command(str, 2);
								sprintf(lfp, "%s%s%s", current_dir, dir_path, basename(str));
								if (is_file_exists(lfp) == 0)
								{
									system(command);
									putdata_to_tracee_addrspace(pid, (long) regs.rsi, lfp);
									file_on_disc = 1;
								}
							}
						}
					}
				}
				else
				{
					in_syscall = 0;
				}
			}

			if (syscall == SYS_stat || syscall == SYS_lstat || syscall == SYS_access)
			{
				if (in_syscall == 0)
				{
					in_syscall = 1;
					str = (char*) malloc(255* sizeof(char));
					getdata_from_tracee_addrspace(pid, (long) regs.rdi, str);

					if (checkurl(str))
					{
						prepare_command(str, 1);
						system(command);
						putdata_to_tracee_addrspace(pid, (long) regs.rdi, fp);
						file_on_disc = 1;
					}
					if (file_on_disc == 0)
						if (isExistfile(str))
						{
							if (checkfilename_included(str, basename(argv[2])))
							{
								prepare_command(str, 2);
								sprintf(lfp, "%s%s%s", current_dir, dir_path, basename(str));
								if (is_file_exists(lfp) == 0)
								{
									system(command);
									putdata_to_tracee_addrspace(pid, (long) regs.rdi, lfp);
									file_on_disc = 1;
								}
							}
						}
				}
				else
				{
					in_syscall = 0;
				}
			}

			if (syscall == SYS_execve)
			{
				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				pid = waitpid(-1, &status, __WALL);

				ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
				pid = waitpid(-1, &status, __WALL);

			}
			ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
		}
	}
	if (file_on_disc == 1)
	{
		cleanup();
	}
	return 0;
}