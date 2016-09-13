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

int getDelimCount(char *filename)
{
	int count = 0;
	int i = 0;

	for (i = 0; i < strlen(filename); i++)
	{
		if(filename[i] == '/')
			{
			    count++;
			}
	

	}

	return count;

}

char *extract_parent(char *filename, int level)
{
    char *parent_path = malloc(PATH_MAX);
	int lastDelIndex = -1;
	int i = 0;
    int count = 0; 

	for (i = 0; i < strlen(filename); i++)
	{
		if(filename[i] == '/')
			{
			    lastDelIndex = i;
                count++;
			}
        if(count == level)
           break;
	}

	memcpy(parent_path,filename,lastDelIndex);
    //printf("path %s,",parent_path);
	return parent_path;

}

void checkOnParent(char *filePath)
{
	int count = getDelimCount(filePath);
    char *permissions;
    char* extractedPath = malloc(PATH_MAX);
    int i;
    for( i = 1; i <= count; i++)
      {
         extractedPath = extract_parent(filePath,i);
         permissions = getPermission(extractedPath);
         //printf("%d,%s,%s\n",count,extractedPath,permissions);
         if(permissions != NULL && permissions[2] == '0')
          {
			printf("ACCESS DENIED : EXECUTE/SEARCH denied on %s\n",extractedPath);
            break;
          }
          
      }

}

void renameSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{

  char *oldname,*newname;
  char *oldAbsolutePath = malloc(PATH_MAX);
  char *oldAbsoluteParentPath = malloc(PATH_MAX);
  char *newAbsolutePath = malloc(PATH_MAX);
  char *newAbsoluteParentPath = malloc(PATH_MAX);
  char *permission1,*permission2;
  
  oldname = extract_fileName(sb->child,regs->rdi);
  realpath(oldname, oldAbsolutePath);
  int count = getDelimCount(oldAbsolutePath);
  oldAbsoluteParentPath = extract_parent(oldAbsolutePath,count);
  permission1 = getPermission(oldAbsoluteParentPath);

  newname = extract_fileName(sb->child,regs->rsi);
  realpath(newname, newAbsolutePath);
  count = getDelimCount(oldAbsolutePath);
  newAbsoluteParentPath = extract_parent(newAbsolutePath,count);
  printf("rename( %s, %s ) = %d\n", oldAbsolutePath,newAbsolutePath,errno);
  permission2 = getPermission(newAbsoluteParentPath);
  if(permission2 != NULL)
    {
        if(permission2[1] == '0')
           printf("ACCESS DENIED : Destination parent Directory no write Access\n");
             
    }
 if(permission1 != NULL)
    {
        if(permission1[1] == '0')
            printf("ACCESS DENIED : Source parent Directory no write Access\n");
             
    }

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

//printf("EXEC\n");

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
  

}


void rmdirSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  realpath(filepath, absolutePath);
  printf("rmdir( %s, %lu ) = %d\n", absolutePath,regs->rsi,errno);

  checkOnParent(absolutePath);

  int count = getDelimCount(absolutePath);
  absolutePath = extract_parent(absolutePath,count);
  permission = getPermission(absolutePath);
  //printf("Parent Path - %s\n",absolutePath);
  if(permission != NULL)
    {
        if(permission[2] == '0')
           printf("mkdir LOCHA\n");
             
    }

}

void chdirSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  realpath(filepath, absolutePath);
  printf("chdir( %s, %lu ) = %d\n", absolutePath,regs->rsi,errno);
  permission = getPermission(absolutePath);
  if(permission != NULL)
    {
        if(permission[2] == '0')
           printf("chdirSystemCall LOCHA\n");
             
    }
  

}

void mkdirSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  realpath(filepath, absolutePath);
  printf("mkdir( %s, %lu ) = %d\n", absolutePath,regs->rsi,errno);
 
  checkOnParent(absolutePath);
 
 int count = getDelimCount(absolutePath);
   absolutePath = extract_parent(absolutePath,count);
  permission = getPermission(absolutePath);
  //printf("Parent Path - %s\n",absolutePath);
  if(permission != NULL)
    {
        if(permission[2] == '0')
           printf("mkdir LOCHA\n");
             
    }
  

}

void accessSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  int mode;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  mode = regs->rsi;
  realpath(filepath, absolutePath);
  printf("access( %s, %d ) = %d\n", absolutePath,regs->rsi,errno);


  checkOnParent(absolutePath);

  
  
  permission = getPermission(absolutePath);
  //printf("Parent Path - %s\n",absolutePath);
  if(permission != NULL)
    {
        if((mode & R_OK) == R_OK && permission[0] == '0')
           {
              printf("ACCESS DENIED: No Read permission on : %s \n",absolutePath);
           }
        if((mode & W_OK) == W_OK && permission[1] == '0')
           {
			  printf("ACCESS DENIED: No Write permission on : %s \n",absolutePath);
           }
        if((mode & X_OK) == X_OK && permission[2] == '0')
           {
              printf("ACCESS DENIED: No Execute permission on : %s \n",absolutePath);
           }
             
    }
  

}

void statSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  realpath(filepath, absolutePath);
  printf("stat( %s ) = %d\n", absolutePath,errno);

  checkOnParent(absolutePath); 

}

void newfstatatSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rsi);
  realpath(filepath, absolutePath);
  printf("stat( %s ) = %d\n", absolutePath,errno);

  checkOnParent(absolutePath); 

}

void lStatSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  
  filepath = extract_fileName(sb->child,regs->rdi);
  realpath(filepath, absolutePath);
  printf("lstat( %s ) = %d\n", absolutePath,errno);

  checkOnParent(absolutePath); 

}

void faccessAtSystemCall(struct sandbox* sb, struct user_regs_struct *regs)
{


  char *filepath;
  char *absolutePath = malloc(PATH_MAX);
  char *permission;
  int mode;
  
  filepath = extract_fileName(sb->child,regs->rsi);
  mode = regs->rdx;
  realpath(filepath, absolutePath);
  printf("access( %s, %d ) = %d\n", absolutePath,regs->rsi,errno);

  checkOnParent(absolutePath);

  permission = getPermission(absolutePath);
  //printf("Parent Path - %s\n",absolutePath);
  if(permission != NULL)
    {
        if((mode & R_OK) == R_OK && permission[0] == '0')
           {
              printf("ACCESS DENIED: No Read permission on : %s \n",absolutePath);
           }
        if((mode & W_OK) == W_OK && permission[1] == '0')
           {
			  printf("ACCESS DENIED: No Write permission on : %s \n",absolutePath);
           }
        if((mode & X_OK) == X_OK && permission[2] == '0')
           {
              printf("ACCESS DENIED: No Execute permission on : %s \n",absolutePath);
           }
             
    }
  

}

struct sandb_syscall sandb_syscalls[] = {
  {__NR_execve,          execSystemCall},
  {__NR_access,          accessSystemCall},
  {__NR_openat,          openAtSystemCall},
  {__NR_open,            openSystemCall},
  {__NR_brk,             NULL},
  {__NR_newfstatat,      newfstatatSystemCall},
  {__NR_stat,            statSystemCall},
  {__NR_lstat,           lStatSystemCall},
  {__NR_mkdir,           mkdirSystemCall},
  {__NR_rmdir,           rmdirSystemCall},
  {__NR_chdir,           chdirSystemCall},
  {__NR_faccessat,       faccessAtSystemCall},
  {__NR_rename,          renameSystemCall},
};

void sandb_kill(struct sandbox *sandb) {
  kill(sandb->child, SIGKILL);
  wait(NULL);
  exit(EXIT_FAILURE);
}

void sandb_handle_syscall(struct sandbox *sandb) {
  int i;
  struct user_regs_struct regs;
  // ptrace(PTRACE_SETOPTIONS, sandb->child, 0, PTRACE_O_TRACEEXEC);
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
    printf("SANDB INIT Exec args: %s, %s\n",argv[0],argv[1]);
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

  //if( status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))
  //{
    //printf("EXEC Called\n");
  //}

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
