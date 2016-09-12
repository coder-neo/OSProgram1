#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <sys/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <asm/unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fnmatch.h>
#include <fcntl.h>
#include "parse.h"

//Global config struct contains all globs and permission
struct Config config;

struct sandbox {
  pid_t child;
  const char *progname;
};

struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox*, struct user_regs_struct *regs);
};


char* getPermission( char* glob)
{
	char *permissions = NULL;
	int i;
    struct fileConfig* temp;
    temp = config.paths;
 
    for( i = 0; i < config.size; i++){
       if(fnmatch(temp->filePath,glob,FNM_PATHNAME) == 0)
       {
          permissions = temp->permission;
       }
       temp++;
    }
	return permissions;

}

char *extract_fileName(pid_t child, unsigned long addr) {
    char *filePath = malloc(PATH_MAX);
    int bytesRead = 0;
    unsigned long data;
    while (1) {
        data = ptrace(PTRACE_PEEKDATA, child, addr + bytesRead);
        if(errno != 0) {
            filePath[bytesRead] = 0;
            break;
        }
        memcpy(filePath + bytesRead, &data, sizeof data);
        if (memchr(&data, 0, sizeof data) != NULL)
            {
              break;
            }
        bytesRead += sizeof data;
    }
    return filePath;
}

void openAtSystemCall(struct sandbox* sandb, struct user_regs_struct *regs)
{
  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  bool readFlag,writeFlag;
  int size;
  long rdi;
  unsigned long int flags,mode;
  filepath = extract_fileName(sandb->child,regs->rsi);
  flags = regs->rdx;
  mode = regs->r10;
  realpath(filepath, absolutePath);
  readFlag = true;
  writeFlag =true;
  printf("OpenAt( %s, %lu, %lu ) = %d\n", absolutePath,flags,mode,errno);
  permission = getPermission(absolutePath);
  if(permission != NULL)
    {
        if(permission[0] == '0')
           readFlag = false;
        if(permission[1] == '0')
           writeFlag = false;

        if((flags & O_ACCMODE) == O_WRONLY && !writeFlag)
           printf("WRITE LOCHA\n");
        if((flags & O_ACCMODE) == O_RDWR && !readFlag && !writeFlag)
           printf("READ WRITE LOCHA\n");
        if((flags & O_ACCMODE) == O_RDONLY && !readFlag)
           printf("READ LOCHA\n");
             
    }
}

void openSystemCall(struct sandbox* sandb, struct user_regs_struct *regs)
{
  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  bool readFlag,writeFlag;
  long rdi;
  unsigned long int flags,mode;
  filepath = extract_fileName(sandb->child,regs->rdi);
  flags = regs->rsi;
  mode = regs->rdx;
  realpath(filepath, absolutePath);
  readFlag = true;
  writeFlag =true;
  printf("Open( %s, %lu, %lu ) = %d\n", absolutePath,flags,mode,errno);
  permission = getPermission(absolutePath);
  if(permission != NULL)
    {
        if(permission[0] == '0')
           readFlag = false;
        if(permission[1] == '0')
           writeFlag = false;

        if((flags & O_ACCMODE) == O_WRONLY && !writeFlag)
           printf("WRITE LOCHA\n");
        if((flags & O_ACCMODE) == O_RDWR && !readFlag && !writeFlag)
           printf("READ WRITE LOCHA\n");
        if((flags & O_ACCMODE) == O_RDONLY && !readFlag)
           printf("READ LOCHA\n");
             
    }

}

// http://stackoverflow.com/questions/33431994/extracting-system-call-name-and-arguments-using-ptrace
void writeSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{
  char *fdpath = malloc(PATH_MAX);
  char *filepath = malloc(PATH_MAX);
  char *absolutePath = malloc(PATH_MAX); 
  int size;
  sprintf(fdpath,"/proc/%u/fd/%llu",sb->child,regs->rdi);
  size = readlink(fdpath, filepath, PATH_MAX);  
  filepath[size] = '\0';
  realpath(filepath, absolutePath);
  printf("Write( %s )\n", absolutePath);
}

// http://stackoverflow.com/questions/33431994/extracting-system-call-name-and-arguments-using-ptrace
void readSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{
  char *fdpath = malloc(PATH_MAX);
  char *filepath = malloc(PATH_MAX);
  char *absolutePath = malloc(PATH_MAX); 
  int size;
  sprintf(fdpath,"/proc/%u/fd/%llu",sb->child,regs->rdi);
  size = readlink(fdpath, filepath, PATH_MAX);  
  filepath[size] = '\0';
  realpath(filepath, absolutePath);
  printf("Read( %s )\n", absolutePath);
}

void execSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{

printf("EXEC\n");
  /*
  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  realpath(filepath, absolutePath);
  printf("execve( %s ) = %d\n", absolutePath,errno);
  permission = getPermission(absolutePath);
  if(permission != NULL)
    {
        if(permission[2] == '0')
           printf("EXEC LOCHA\n");
             
    }
  */

}
struct sandb_syscall sandb_syscalls[] = {
  {__NR_read,            readSystemCall},
  {__NR_write,           writeSystemCall},
  {__NR_exit,            NULL},
  {__NR_execve,          execSystemCall},
  {__NR_brk,             NULL},
  {__NR_mmap,            NULL},
  {__NR_access,          NULL},
  {__NR_openat,          openAtSystemCall},
  {__NR_open,            openSystemCall},
  {__NR_fstat,           NULL},
  {__NR_close,           NULL},
  {__NR_mprotect,        NULL},
  {__NR_munmap,          NULL},
  {__NR_arch_prctl,      NULL},
  {__NR_exit_group,      NULL},
  {__NR_getdents,        NULL},
};

void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void sandb_handle_syscall(struct sandbox *sandb) {
  int i;
  struct user_regs_struct regs;

  if(ptrace(PTRACE_GETREGS, sandb->child, NULL, &regs) < 0)
    err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_GETREGS:");
  //printf("SysCall --------------->%lu\n",regs.orig_rax);
  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
    if(regs.orig_rax == sandb_syscalls[i].syscall) {
      if(sandb_syscalls[i].callback != NULL)
        sandb_syscalls[i].callback(sandb, &regs);
      return;
    }
  }

  if(regs.orig_rax == -1) {
    printf("[SANDBOX] Segfault ?! KILLING !!!\n");
  } 
}

void sandb_init(struct sandbox *sandb, int argc, char **argv) {
  pid_t pid;

  pid = fork();

  if(pid == -1)
    err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

  if(pid == 0) {

    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");

    if(execvp(argv[0], argv) < 0)
      err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");

  } else {
    sandb->child = pid;
    sandb->progname = argv[0];
    wait(NULL);
  }
}

void sandb_run(struct sandbox *sandb) {
  int status;

  if(ptrace(PTRACE_SYSCALL, sandb->child, NULL, NULL) < 0) {
    if(errno == ESRCH) {
      waitpid(sandb->child, &status, __WALL | WNOHANG);
      sandb_kill(sandb);
    } else {
      err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_SYSCALL:");
    }
  }

  wait(&status);

  if(WIFEXITED(status))
    exit(EXIT_SUCCESS);

  if(WIFSTOPPED(status)) {
    sandb_handle_syscall(sandb);
  }
}

int main(int argc, char **argv) {
  struct sandbox sandb;
  int i;
  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : -c ConfigFile command args", argv[0]);
  }
  struct fileConfig* temp;
  int skipArgs = 1;
  char *configPath;
  
  for (i = 1; i < argc; i++)
   {
   	if(strcmp(*(argv+i),"-c") == 0)
           {
                configPath = *(argv + i + 1);
                skipArgs += 2;
                break;
           }
   }
  if(skipArgs == 1)
   {
      configPath = ".fendrc";
   }
  printf("Config path is %s\n",configPath);

  config =  parse(configPath);
  
  temp = config.paths;
 
  for( i = 0; i < config.size; i++){
     printf("Path -> %s,  Permission -> %s\n",temp->filePath, temp->permission);
     temp++;
  }

  sandb_init(&sandb, argc-skipArgs, argv+skipArgs);

  for(;;) {
    sandb_run(&sandb);
  }

  return EXIT_SUCCESS;
}
