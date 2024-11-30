#pragma once
#include "stdint.h"
#include <string>
#include "structs.h"


/* constexpr unsigned long long QNS_NAME_LENGTH = 256; */

/* using QNSOwner = const char*; */
/* using IPFSHash = const char*; */

/* struct QNSName { */
/*   unsigned char name[QNS_NAME_LENGTH]; */
/* }; */

/* // Structure of each entry behind the lookup. */
/* struct QNSEntry { */
/*   // Name of the entry. Potentially needed to check for hash collisions */
/*   QNSName name; */
/*   // Id to look up */
/*   char id[55]; */
/*   // Owner */
/*   QNSOwner owner; */
/*   // ipfs hash */
/*   IPFSHash ipfs; */
/*   // Expiration date */
/*   int expiration; */
/* }; */

QNSEntry qnsLookup(const char* nodeIp, int nodePort, const char* seed, const char* query);
void qnsRegisterName(const char* nodeIp, int nodePort, const char* seed, const QNSEntry entry);
void qnsUpdate(const char* nodeIp, int nodePort, const char* seed, const QNSEntry newEntry);
void qnsTransferOwnership(const char* nodeIp, int nodePort, const char* seed, const QNSEntry entry);

void qnsRegisterName(const char* nodeIp, int nodePort, const char* seed, const char* filename);
void qnsUpdate(const char* nodeIp, int nodePort, const char* seed, const char* filename);
void qnsTransferOwnership(const char* nodeIp, int nodePort, const char* seed, const char* filename);


std::string formatQNSEntry(const QNSEntry entry);
QNSEntry qnsReadFile(const char *filename);
