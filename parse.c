#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef enum { false, true } bool;
struct fileConfig{
char permission[4];
bool last;
char filePath[256];
};

struct fileConfig* parse(char* fileName)
{
   
    FILE* file = fopen(fileName, "r"); /* should check the result */
    char path[256],permissions[4];
    int nret,i;
    int lines = 0;
    struct fileConfig *paths,*temp;
    while(!feof(file)){
         nret = fscanf(file,"%s %s",&permissions,&path);	
	if(nret == 2)
	{
         lines++;
	
	}
    }
    fclose(file);
    
    paths = (struct fileConfig*)malloc(lines * sizeof(struct fileConfig));
    file = fopen(fileName, "r");
    temp = paths;
    for(i = 0; i < lines ; i++){
           nret = fscanf(file,"%s %s",&permissions,&path);
	
	memcpy(temp[i].permission,permissions,4 * sizeof(char));
	memcpy(temp[i].filePath,path,256 * sizeof(char));
        temp[i].last = false;	
	if(i == lines -1)
	{
	  temp[i].last = true;	
	}
	


    }
    /* may check feof here to make a difference between eof and io failure -- network
       timeout for instance */

    fclose(file);

    return paths;
}


int main(int argc, char* argv[])
{
    char* fileName = argv[1]; /* should check that argc > 1 */
    struct fileConfig *paths;
    paths =  parse(fileName);
    do
	{
	   printf("Path -> %s,  Permission -> %s\n",paths->filePath, paths->permission);
	   paths++;
	}while(!paths->last);
    printf("Path -> %s,  Permission -> %s\n",paths->filePath, paths->permission);
    return 0;
}
