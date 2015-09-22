#include "list_single.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

static pNode head;

// 创建初始化链表
void create(void)
{
	head = calloc(1, sizeof(node));
	assert(head != NULL);
	head->title = NULL;
	head->value = NULL;
	head->flag = 0;
	head->next = NULL;
}

// 删除链表中的某一个元素
pNode Remove(char* title)
{
	assert(head!=NULL);
	pNode pPre = head;
	pNode cur = head->next;
	pNode pNext;
	while(cur!=NULL){
		if(strcmp(cur->title, title) == 0){
			break;
		}else{
			pPre = cur;
			cur = cur->next;
		}
	}
	assert(cur!=NULL);
	pNext = pPre->next->next;
	if(pNext!=NULL){
		pPre->next = pNext;
		free(cur);
	}else{
		pPre->next = NULL;
		free(cur);
	}
	return cur;
}

// 向链表中插入数据
pNode insertion(char* title, char* value, int flag)
{
	assert(head!=NULL);
	pNode pCur = head;
	pNode pPre;
	pNode pNew = (pNode)malloc(sizeof(node));
	pNew->title = title;
	pNew->value = value;
	pNew->flag = flag;
	pNew->next = NULL;
	assert(pNew!=NULL);
	while(pCur!=NULL){
		pPre = pCur;
		pCur = pCur->next;
	}
	pPre->next = pNew;
	return pNew;
}

// 根据元素查找节点
pNode find(char* title)
{
	pNode pCur = head->next;

	while(pCur != NULL){
		if(strcmp(pCur->title, title) == 0){
			break;
		}else{
			pCur = pCur->next;
		}
	}
	return pCur;
}

// 根据原有的数据查找更新数据
void update(char* title, char* value, int flag)
{
	printf("*******in update()*********\n");
	pNode obj = find(title);
	printf("************1\n");
	//assert(obj != NULL);
	if(obj == NULL) {
		obj = insertion(title, value, flag);
	}
	printf("************2\n");
	//memcpy(obj->value, value, strlen(value));
	obj->value = value;
	obj->flag = flag;
	printf("************3\n");
}

char* GetValue(char* title)
{
	pNode obj = find(title);
	return obj->value;
}

int GetFlag(char* title)
{
	pNode obj = find(title);
	return obj->flag;
}

// 统计当前链表中有多少个元素
int size()
{
	int count = 0;
	pNode obj = head->next;
	while(obj!=NULL){
		count++;
		obj = obj->next;
	}
	return count;
}

// 销毁链表
void destory()
{
	pNode cur = head;
	pNode pNext = head->next;
/*
	head -> next ->next
 */
	while(pNext!=NULL){
		//free(cur);
		cur = pNext;
		pNext = pNext->next;
		free(cur);
	}
	free(head);
}

// 遍历链表中的所有数据
void display()
{
	int i,s;
	s = size();
	pNode list =  head->next;
	for(i=0;i<s;i++){
		printf("%s:%s[%d]\n", list->title, list->value, list->flag);	
		list = list->next;
	}
}

