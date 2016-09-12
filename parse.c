#include <stdlib.h>
#include <string.h>
#include "parse.h"

struct Config parse(char* fileName)
{
   
    FILE* file = fopen(fileName, "r"); /* should check the result */
    char path[256],permissions[4];
    int nret,i;
    int lines = 0;
    struct fileConfig *paths,*temp;
    struct Config config;
    //Count no lines
    while(!feof(file)){
        nret = fscanf(file,"%s %s",&permissions,&path);
        if(nret == 2)
	    {
             lines++;
        }
    }
    
    fclose(file);
    
    paths = (struct fileConfig*)malloc(lines * sizeof(struct fileConfig));
    config.paths = paths;
    config.size = lines;
    file = fopen(fileName, "r");
    temp = paths;

    for(i = 0; i < lines ; i++){
        nret = fscanf(file,"%s %s",&permissions,&path);
	
	    memcpy(temp[i].permission,permissions,4 * sizeof(char));
	    memcpy(temp[i].filePath,path,256 * sizeof(char));
        temp[i].last = false;	
	
        if(i == lines -1){
	       temp[i].last = true;	
	    }
    }

    fclose(file);

    return config;
}

/*
int main(int argc, char* argv[])
{
    char* fileName = argv[1]; 
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
*/