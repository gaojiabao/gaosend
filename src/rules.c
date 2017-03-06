#include    <unistd.h>
#include    <string.h>
#include    <sys/time.h>
#include    "func.h"
#include    "runlog.h"
#include    "common.h"
#include    "storage.h"
#include    "statistic.h"


static int RuleModeInitialization(char* pRuleName)
{
    int iSaveFd = -1;

    if (strcmp(pRuleName, "aclnmask") == 0) {
        iSaveFd = OpenSaveFile(ACLNMASKFILE);
    } else if (strcmp(pRuleName, "aclex") == 0) {
        iSaveFd = OpenSaveFile(ACLEXFILE);
    } else if (strcmp(pRuleName, "mac_table") == 0) {
        iSaveFd = OpenSaveFile(MACTABLEFILE);
    }

    return iSaveFd;
}

static void CloseRuleMode(int iRuleFd)
{
    close(iRuleFd);
    LOGRECORD(DEBUG, "Write rules finished");
}

void RulesGenerationEntrance(stPktStrc stPkt, int iRuleNum)
{
    static int iSaveFd = -1;
    const int iCount = GetiValue("count");
    char* pRuleName = GetcValue("rule");

    if (iSaveFd < 0) {
        iSaveFd = RuleModeInitialization(pRuleName);
    }

    // to print reletive ACL rules into file
    if (strcmp(pRuleName, "aclnmask") == 0) {
        if (dprintf(iSaveFd, "add ruleset test aclnmask %d action=drop," 
                    "sip=%s,dip=%s,sport=%d,dport=%d,protocol=%s\n", 
                    iRuleNum, GetcValue("sip"), GetcValue("dip"), 
                    GetiValue("sport"), GetiValue("dport"),
                    GetcValue("l4pro")) < 0) {
            LOGRECORD(ERROR, "write aclmask rules error");
        }
    } else if (strcmp(pRuleName, "aclex") == 0) {
        int offset = GetiValue("offset");
        if (dprintf(iSaveFd, "add ruleset test aclex %d "
                    "action=drop, offset=%d, strkey=%s\n", 
                    iRuleNum, offset, stPkt.pData+offset) < 0) {
            LOGRECORD(ERROR, "write aclex rules error");
        }
    } else if (strcmp(pRuleName, "mac_table") == 0) {
        if (dprintf(iSaveFd, "add mac_table %s " "action=forward, outgroup=1\n", 
                    GetcValue("smac")) < 0) {
            LOGRECORD(ERROR, "write mac table rules error");
        }
    }

    if (iCount == (iRuleNum+1)) {
        CloseRuleMode(iSaveFd);
    }
}

