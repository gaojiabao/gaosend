#ifndef __LIST_SINGLE_H__
#define __LIST_SINGLE_H__

// parameter storage structure
typedef struct Node{
	char* title;
	char* cValue;
	int   iValue;
	int   flag; //0:unchange,1:no input,2:fix,3:random,4:increase,5:decrease
	struct Node* next;
}st_node;

typedef st_node* pNode;

enum Node_flag{
    FG_UNCHANGE,
    FG_NOINPUT,
    FG_FIXDATA,
    FG_RANDOM,
    FG_INCR,
    FG_DECR,
};

void CreateStorage(void);
pNode RemoveNode(char*);
pNode InsertNode(char* , char*, int, int);
char* GetcValue(char* );
int GetiValue(char* );
int GetFlag(char* );
void DestoryStorage();
void ShowParameter();
void RefreshParameter();
void StorageInput(char* , char* ,char );

#define MD5LEN 16

// md5 storage structure
typedef struct StreamInfo{
    unsigned char value[MD5LEN];
    struct StreamInfo* next;
}stream_info, *pStreamInfo;

//typedef stream_info* pMD5Node;

void StoreStreamInfo(unsigned char*);
void CreateStreamStorage(void);
void DisplayAllStreamMD5();
pStreamInfo InsertStreamInfo(unsigned char*);

#endif
