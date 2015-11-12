#ifndef __LIST_SINGLE_H__
#define __LIST_SINGLE_H__

typedef struct Node{
	char* title;
	char* cValue;
	int   iValue;
	int   flag; //0:fix,1:random,2:increase
	struct Node* next;
}node;

typedef node* pNode;
// 创建初始化链表
void create(void);
// 删除链表中的某一个元素
pNode Remove(char*);
// 向链表中插入数据
pNode insertion(char* , char*, int, int);
// 根据原有的数据查找更新数据
void update(char* , char*, int, int);
// 根据元素查找节点
pNode find(char* );
// 统计当前链表中有多少个元素
int size();
void UpdatecValue(char* ,char*);
void UpdateiValue(char* ,int);
char* GetcValue(char* );
int GetiValue(char* );
int GetFlag(char* );
// 销毁链表
void destory();
// 遍历链表中的所有数据
void display();
void ParameterUpadte();
void Storage(char* , char* ,char );

#endif
