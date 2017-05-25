#ifndef __MODIFY_H__
#define __MODIFY_H__

#define M_SRC  0 
#define M_DST  1
#define M_VLAN 0
#define M_QinQ 1

#define M_HEAD 0 
#define M_REAR 1 

typedef struct cList{
    char* mac[2];
    U32   ip4[2];
    S16   port[2];
    S32   vlan[2];
}stChgList;

typedef struct condition{
    U32 ip1[2]; // 0:before modify 1:after modify
    U32 ip2[2];
}stCndList;

stPktStrc GetPktStrc();

#endif
