#include <stdlib.h> 
#include <stdio.h> 
#include <linux/limits.h>
int main() 
{ 
        char resolved_path[PATH_MAX]; 
	char *args[2];        
	realpath("faltu.txt", resolved_path);
	printf("\n%s\n",resolved_path);
        
        args[0] = "./hello";
        args[1] = "";
        execve(args[0], args, NULL);
         
        return 0; 
} 
