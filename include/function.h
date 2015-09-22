/*
 *  author   : Mr. Gao
 *
 *  function : To statement functions.
 */ 

#ifndef __FUNCTION_H__
#define __FUNCTION_H__

#include	<stdio.h>
#include	"packet.h"

uint16_t	GetCheckSum(uint16_t *, int);
char	ChangeHexToString(int);
char*	GetUrlString();
int		GetRandomNumber();
char*	GetRandomCharactor(int);
char*	GetIncreaseMacAddress(int);
char*	GetRandomMacAddress(int);
int		mac_type_change (char *, char *);
char*	GetRandomIpAddress(int);
char*	GetIncreaseIpAddress(int);
int		GetIncreasePort(int);
int		GetRandomPort();
int		GetRandomPacketLength();
int		GetIncreasePacketLength();
int		GetIncreaseVlan(int);
int		GetRandomVlan();
uint8_t	GetRandomLayer4Pro();
char*	ChangeLayer4HexToString(uint16_t);
uint16_t	GetHex(char*);
void	ProgramProcessingSchedule(int, int);
char*	subs(char*, int, int);
void	DisplayPacketData(char*, int);
char*	m_option(int ,char** );
int		ProtocolConversion(char* );

#endif

