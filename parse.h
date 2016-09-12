#include<stdio.h>
#include <errno.h>
#include <linux/limits.h>
typedef enum { false, true } bool;

struct fileConfig{
    char permission[4];
    char filePath[PATH_MAX];
};

struct Config
{
	struct fileConfig* paths;
	int size;
};

struct Config parse(char*);
