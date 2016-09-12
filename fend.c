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
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>

#include "parse.h"

struct sandbox {
  pid_t child;
  const char *progname;
};

struct sandb_syscall {
  int syscall;
  void (*callback)(struct sandbox*, struct user_regs_struct *regs);
};

char *extract_fileName(pid_t child, unsigned long addr) {
    char *filePath = malloc(256);
    int allocated = 256;
    int read = 0;
    unsigned long tmp;
    while (1) {
        if (read + sizeof tmp > allocated) {
            allocated *= 2;
            filePath = realloc(filePath, allocated);
        }

        tmp = ptrace(PTRACE_PEEKDATA, child, addr + read);
       // printf("Read %d, addr %ld, errno %d\n",read,addr,errno);
        if(errno != 0) {
            filePath[read] = 0;
           // printf("Break 1\n");
            break;
        }
        memcpy(filePath + read, &tmp, sizeof tmp);
        if (memchr(&tmp, 0, sizeof tmp) != NULL)
            {
        //      printf("Break 2");
              break;
            }
        read += sizeof tmp;
    }
   // printf("String read %s\n",filePath);
    return filePath;
}

void openSystemCall(struct sandbox* sandb, struct user_regs_struct *regs)
{
  char *filepath,*fdpath;
  int size;
  long rdi;
  int flags,mode;
  printf("Open system call\n");
  rdi = ptrace(PTRACE_PEEKUSER,sandb->child,regs->rdi);
  filepath = extract_fileName(sandb->child,regs->rdi);
  flags = regs->rsi;
  mode = regs->rdx;
  //memcpy(mode, &regs->rdx, sizeof(int));
  printf("Flags -> %d, Mode -> %d\n",flags,mode);
  //sprintf(fdpath,"/proc/%u/fd/%llu",sandb->child,regs->rdi);
  //printf("FdPath %s\n",fdpath);
  // size = readlink(fdpath, filepath, 256);  //this gives the filepath for a particular fd
  // printf("size %d",size);
  // filepath[size] = '\0';
  printf("File->%s\n", filepath);
  // printf("\nread2");
}
void writeSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{
  char *fdpath,*filepath;
  int size;
  sprintf(fdpath,"/proc/%u/fd/%llu",sb->child,regs->rdi);
  size = readlink(fdpath, filepath, 256);  //this gives the filepath for a particular fd
  filepath[size] = '\0';
  printf("Write File->%s\n", filepath);
  printf("Write system call\n");
}
void readSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{
  char *fdpath,*filepath;
  int size;
  sprintf(fdpath,"/proc/%u/fd/%llu",sb->child,regs->rdi);
  size = readlink(fdpath, filepath, 256);  //this gives the filepath for a particular fd
  filepath[size] = '\0';
  printf("Read File->%s\n", filepath);
  printf("Read system call\n");
}
struct sandb_syscall sandb_syscalls[] = {
  {__NR_read,            readSystemCall},
  {__NR_write,           writeSystemCall},
  {__NR_exit,            NULL},
  {__NR_brk,             NULL},
  {__NR_mmap,            NULL},
  {__NR_access,          NULL},
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

  for(i = 0; i < sizeof(sandb_syscalls)/sizeof(*sandb_syscalls); i++) {
    if(regs.orig_rax == sandb_syscalls[i].syscall) {
      if(sandb_syscalls[i].callback != NULL)
        sandb_syscalls[i].callback(sandb, &regs);
      return;
    }
  }

  if(regs.orig_rax == -1) {
    printf("[SANDBOX] Segfault ?! KILLING !!!\n");
  } else {
    printf("[SANDBOX] Trying to use devil syscall (%llu) ?!? KILLING !!!\n", regs.orig_rax);
  }
  // sandb_kill(sandb);
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
 // ptrace(PTRACE_SYSCALL, sandb->child, 0, 0);
}

int main(int argc, char **argv) {
  struct sandbox sandb;
  int i;
  if(argc < 2) {
    errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  }

  struct Config config;
  struct fileConfig* temp;
  config =  parse(".fendrc");
  temp = config.paths;
  
  for( i = 0; i < config.size; i++){
     printf("Path -> %s,  Permission -> %s\n",temp->filePath, temp->permission);
     temp++;
  }

  sandb_init(&sandb, argc-1, argv+1);

  for(;;) {
    sandb_run(&sandb);
  }

  return EXIT_SUCCESS;
}