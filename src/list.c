#include "list.h"
#include "function.h"
#include <stdio.h>
#include "default.h"
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>

static pNode head;

// 创建初始化链表
void create(void)
{
	head = calloc(1, sizeof(node));
	assert(head != NULL);
	head->title = NULL;
	head->cValue = NULL;
	head->iValue = -1;
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
pNode insertion(char* title, char* cValue, int iValue, int flag)
{
	assert(head!=NULL);
	pNode pCur = head;
	pNode pPre;
	pNode pNew = (pNode)malloc(sizeof(node));
	pNew->title = title;
	pNew->cValue = cValue;
	pNew->iValue = iValue;
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
	pNode pRes = NULL;
	pNode pCur = head->next;

	while(pCur != NULL){
		if(strcmp(pCur->title, title) == 0){
			pRes = pCur;
			break;
		}else{
			pCur = pCur->next;
		}
	}

	return pRes;
}

// 根据原有的数据查找更新数据
void update(char* title, char* cValue, int iValue, int flag)
{
	pNode obj = find(title);
	if(obj == NULL) {
		obj = insertion(title, cValue, iValue, flag);
	}
	obj->cValue = cValue;
	obj->iValue = iValue;
	obj->flag = flag;
}

void UpdatecValue(char* title, char* cValue)
{
	pNode obj = find(title);
	if(NULL != obj) {
		update(title, cValue, obj->iValue, obj->flag);
	} else {
		printf("UpdatecValue error[%s:%s]\n", title, cValue);
		exit(0);
	}
}

void UpdateiValue(char* title, int iValue)
{
	pNode obj = find(title);
	if(obj != NULL) {
		update(title, obj->cValue, iValue, obj->flag);
	} else {
		printf("UpdateiValue error\n");
		exit(0);
	}
}

char* GetcValue(char* title)
{
	pNode obj = find(title);
	if(obj == NULL) return NULL;
	else return obj->cValue;
}

int GetiValue(char* title)
{
	pNode obj = find(title);
	return obj->iValue;
}

int GetFlag(char* title)
{
	pNode obj = find(title);
	if(!obj) return -1;
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
		printf("%s:%s,%d[%d]\n", list->title, 
					list->cValue, list->iValue, list->flag);	
		list = list->next;
	}
}

// 遍历链表中的所有数据
void ParameterUpadte()
{
	char* name = NULL;
	int flag;
	int i,s;
	s = size();
	pNode list =  head->next;

	for(i=0;i<s;i++){
		name = list->title;
		flag = list->flag;
		if(flag%3 == 1) { // random 
			if(strcmp(name, "smac") == 0) {
				UpdatecValue(name, GetRandomMacAddress(0));
			} else if(strcmp(name, "dmac") == 0) {
				UpdatecValue(name, GetRandomMacAddress(1));
			} else if(strcmp(name, "sip") == 0) {
				UpdatecValue(name, GetRandomIpAddress(0));
			} else if(strcmp(name, "dip") == 0) {
				UpdatecValue(name, GetRandomIpAddress(1));
			} else if(strcmp(name, "sport") == 0) {
				UpdateiValue(name, GetRandomPort(0));
			} else if(strcmp(name, "dport") == 0) {
				UpdateiValue(name, GetRandomPort(1));
			} else if(strcmp(name, "vlan1") == 0) {
				UpdateiValue(name, GetRandomVlan());
			} else if(strcmp(name, "vlan2") == 0) {
				UpdateiValue(name, GetRandomVlan());
			} else if(strcmp(name, "pktlen") == 0) {
				UpdateiValue(name, GetRandomPacketLength());
			}
		} else if(flag%3 == 2) { // increase
			if(strcmp(name, "smac") == 0) {
				UpdatecValue(name, GetIncreaseMacAddress(0));
			} else if(strcmp(name, "dmac") == 0) {
				UpdatecValue(name, GetIncreaseMacAddress(1));
			} else if(strcmp(name, "sip") == 0) {
				UpdatecValue(name, GetIncreaseIpAddress(0));
			} else if(strcmp(name, "dip") == 0) {
				UpdatecValue(name, GetIncreaseIpAddress(1));
			} else if(strcmp(name, "sport") == 0) {
				UpdateiValue(name, GetIncreasePort(0));
			} else if(strcmp(name, "dport") == 0) {
				UpdateiValue(name, GetIncreasePort(1));
			} else if(strcmp(name, "vlan1") == 0) {
				UpdateiValue(name, GetIncreaseVlan(0));
			} else if(strcmp(name, "vlan2") == 0) {
				UpdateiValue(name, GetIncreaseVlan(1));
			} else if(strcmp(name, "pktlen") == 0) {
				UpdateiValue(name, GetIncreasePacketLength());
			}
		}

		list = list->next;
	}
}

void Storage(char* title, char* value, char mode)
{
	int flag;

	if(strcmp(title, "protocol") == 0) {
		unsigned int i = 0;
		char pro[8];

		memset(pro, 0, sizeof(pro));

		for(; i<strlen(value); i++) {
			pro[i] = toupper(value[i]);
		}

		if(strcmp(pro, "ARP") == 0) {
			update("l3pro", "ARP", -1, 0);
			update("l4pro", NULL, -1, 0);
		} else if(strcmp(pro, "ICMP") == 0) {
			update("l3pro", "IPv4", -1, 0);
			update("l4pro", "ICMPv4", -1, 0);
		} else if(strcmp(pro, "UDP") == 0) {
			update("l3pro", "IPv4", -1, 0);
			update("l4pro", "UDP", -1, 0);
		} else if(strcmp(pro, "TCP") == 0) {
			update("l3pro", "IPv4", -1, 0);
			update("l4pro", "TCP", -1, 0);
		} else if(strcmp(pro, "HTTP-GET") == 0) {
			if(GetiValue("pktlen") < 360) {
				update("pktlen", NULL, 360, 0);
			}
			update("dport", NULL, 80, 0);
			update("l3pro", "IPv4", -1, 0);
			update("l4pro", "TCP", -1, 0);
			update("l7pro", "HTTP-GET", -1, 0);
		} else if(strcmp(pro, "HTTP-POST") == 0) {
			if(GetiValue("pktlen") < 360) {
				update("pktlen", NULL, 360, 0);
			}
			update("dport", NULL, 80, 0);
			update("l3pro", "IPv4", -1, 0);
			update("l4pro", "TCP", -1, 0);
			update("l7pro", "HTTP-POST", -1, 0);
		} else if(strcmp(pro, "DNS") == 0) {
			if (GetcValue("url") == NULL) {
				int pktlen = MACHDRLEN+IP4HDRLEN+UDPHDRLEN+DNSHDRLEN+13+6;
				update("pktlen", NULL, pktlen, 0);
			} else {
				char* url = GetcValue("url");
				char* host = strtok(url, "/");
				update("host", host, -1, 0);
				int pktlen = MACHDRLEN+IP4HDRLEN+UDPHDRLEN \
							 +DNSHDRLEN+strlen(url)+6;
				update("pktlen", NULL, pktlen, 0);
			}
			update("dport", NULL, 53, 0);
			update("l3pro", "IPv4", -1, 0);
			update("l4pro", "UDP", -1, 0);
			update("l7pro", "DNS", -1, 0);
		}
	}

	if(strcmp(value, "random") == 0) {
		flag = 1;
	} else if(strcmp(value, "increase") == 0) {
		flag = 2;
	} else {
		flag = 0;
	}

	if(mode == 'c') {
		if(flag == 0) {
			update(title, value, -1, flag+3);
		} else {
			update(title, NULL, -1, flag+3);
		}
	} else if(mode == 'i') {
		if(flag == 0) {
			update(title, NULL, atoi(value), flag+3);
		} else {
			update(title, NULL, -1, flag+3);
		}
	}
}

