#include<stdio.h>

typedef enum { false, true } bool;

struct fileConfig{
    char permission[4];
    bool last;
    char filePath[256];
};

struct Config
{
	struct fileConig* paths;
	int size;
};

struct Config parse(char*);