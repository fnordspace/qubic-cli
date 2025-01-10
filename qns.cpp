#include "qns.h"
#include "keyUtils.h"
#include "structs.h"
#include "logger.h"
#include "nodeUtils.h"
#include "K12AndKeyUtil.h"
#include "connection.h"
#include "walletUtils.h"
#include <vector>
#include <string>
#include <sstream>
#include <fstream>
#include <cstring>
#include <algorithm>

constexpr int QNS_CONTRACT_ID = 10;

enum qnsFunctionId{
    lookup = 1,
};

enum qnsProcedureId{
    registerName = 1,
    update = 2,
    transferOwnership = 3
};


// Definition of structs

//registerName
struct registerName_input {
    QNSEntry entry;
};

struct registerName_output {
    int returnCode;
};


// Update
struct update_input {
    QNSEntry entry;
};

struct update_output {
    int returnCode;
};


// lookup (function)
struct lookup_input {
    QNSName query;
};

struct lookup_output {
    QNSEntry value;
    int returnCode;
};


// transferOwnership
struct transferOwnership_input {
    QNSEntry entry;
};

struct transferOwnership_output {
    int returnCode;
};



// Implementation of procedures and functions

QNSEntry qnsLookup(const char* nodeIp, int nodePort, const char* seed, const char* query)
{
    auto qc = make_qc(nodeIp, nodePort);
    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } packet;
    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(RequestContractFunction::type());
    packet.rcf.inputSize = 0; packet.rcf.inputType = qnsFunctionId::lookup;
    packet.rcf.contractIndex = QNS_CONTRACT_ID;
    qc->sendData((uint8_t *) &packet, packet.header.size());
    auto res = qc->receivePacketWithHeaderAs<QNSlookup_output>();
    LOG("Entry found: {}", formatQNSEntry(res.value).c_str());
    return res.value;
}

void qnsRegisterName(const char* nodeIp, int nodePort, const char* seed, const uint32_t scheduledTickOffset, const QNSEntry entry)
{
    auto qc = make_qc(nodeIp, nodePort);

    uint8_t privateKey[32] = {0};
    uint8_t sourcePublicKey[32] = {0};
    uint8_t destPublicKey[32] = {0};
    uint8_t subseed[32] = {0};
    uint8_t digest[32] = {0};
    uint8_t signature[64] = {0};
    char publicIdentity[128] = {0};
    char txHash[128] = {0};
    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    const bool isLowerCase = false;
    getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    ((uint64_t*)destPublicKey)[0] = QNS_CONTRACT_ID;
    ((uint64_t*)destPublicKey)[1] = 0;
    ((uint64_t*)destPublicKey)[2] = 0;
    ((uint64_t*)destPublicKey)[3] = 0;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        registerName_input input;
        unsigned char signature[64];
    } packet;
    packet.input.entry = entry;
    // memset(&packet.reg, 0, sizeof(SendToManyV1_input));
    packet.transaction.amount = 0;
    // for (int i = 0; i < std::min(25, int(addresses.size())); i++){
    //     getPublicKeyFromIdentity(addresses[i].data(), packet.stm.addresses[i]);
    //     packet.stm.amounts[i] = amounts[i];
    //     packet.transaction.amount += amounts[i];
    // }
    // long long fee = getSendToManyV1Fee(qc);
    // LOG("Send to many V1 fee: %lld\n", fee);
    // packet.transaction.amount += fee; // fee
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QNS_REGISTER_NAME;
    packet.transaction.inputSize = sizeof(registerName_input);
    KangarooTwelve((unsigned char*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(registerName_input),
                   digest,
                   32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.signature, signature, 64);
    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t *) &packet, packet.header.size());
    KangarooTwelve((unsigned char*)&packet.transaction,
                   sizeof(packet.transaction) + sizeof(registerName_input) + SIGNATURE_SIZE,
                   digest,
                   32); // recompute digest for txhash
    getTxHashFromDigest(digest, txHash);
    LOG("registerName tx has been sent!\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}


void qnsUpdate(const char* nodeIp, int nodePort, const char* seed, const QNSEntry newEntry)
{
    // auto qc = make_qc(nodeIp, nodePort);

    // uint8_t privateKey[32] = {0};
    // uint8_t sourcePublicKey[32] = {0};
    // uint8_t destPublicKey[32] = {0};
    // uint8_t subseed[32] = {0};
    // uint8_t digest[32] = {0};
    // uint8_t signature[64] = {0};
    // char publicIdentity[128] = {0};
    // char txHash[128] = {0};
    // getSubseedFromSeed((uint8_t*)seed, subseed);
    // getPrivateKeyFromSubSeed(subseed, privateKey);
    // getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);
    // const bool isLowerCase = false;
    // getIdentityFromPublicKey(sourcePublicKey, publicIdentity, isLowerCase);
    // ((uint64_t*)destPublicKey)[0] = QUTIL_CONTRACT_ID;
    // ((uint64_t*)destPublicKey)[1] = 0;
    // ((uint64_t*)destPublicKey)[2] = 0;
    // ((uint64_t*)destPublicKey)[3] = 0;

    // struct {
    //     RequestResponseHeader header;
    //     Transaction transaction;
    //     BurnQubic_input bqi;
    //     unsigned char signature[64];
    // } packet;
    // packet.bqi.amount = amount;
    // packet.transaction.amount = amount;
    // memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    // memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    // uint32_t currentTick = getTickNumberFromNode(qc);
    // packet.transaction.tick = currentTick + scheduledTickOffset;
    // packet.transaction.inputType = qutilProcedureId::BurnQubic;
    // packet.transaction.inputSize = sizeof(BurnQubic_input);
    // KangarooTwelve((unsigned char*)&packet.transaction,
    //                sizeof(packet.transaction) + sizeof(BurnQubic_input),
    //                digest,
    //                32);
    // sign(subseed, sourcePublicKey, digest, signature);
    // memcpy(packet.signature, signature, 64);
    // packet.header.setSize(sizeof(packet));
    // packet.header.zeroDejavu();
    // packet.header.setType(BROADCAST_TRANSACTION);
    // qc->sendData((uint8_t *) &packet, packet.header.size());
    // KangarooTwelve((unsigned char*)&packet.transaction,
    //                sizeof(packet.transaction) + sizeof(BurnQubic_input) + SIGNATURE_SIZE,
    //                digest,
    //                32); // recompute digest for txhash
    // getTxHashFromDigest(digest, txHash);
    // LOG("BurnQubic tx has been sent!\n");
    // printReceipt(packet.transaction, txHash, nullptr);
    // LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    // LOG("to check your tx confirmation status\n");
}

void qnsTransferOwnership(const char* nodeIp, const int nodePort, const char* seed, const QNSEntry newEntry) {
    // addresses.resize(0);
    // amounts.resize(0);
    // std::ifstream infile(payoutListFile);
    // std::string line;
    // while (std::getline(infile, line))
    // {
    //     std::istringstream iss(line);
    //     std::string a;
    //     int64_t b;
    //     if (!(iss >> a >> b)) { break; } // error
    //     addresses.push_back(a);
    //     amounts.push_back(b);
    // }
}

std::string formatQNSEntry(const QNSEntry entry) {
    std::string result;
    result.append("Name: ")
        .append(reinterpret_cast<const char *>(entry.name.name))
        .append("\n");
    result.append("ID: ").append(entry.id).append("\n");
    result.append("Owner: ").append(entry.owner).append("\n");
    result.append("IPFS Hash: ").append(entry.ipfs).append("\n");
    result.append("Expiration: ").append(std::to_string(entry.expiration));
    return result;
}

QNSEntry qnsReadFile(const char *filename) {
    QNSEntry res;
    std::ifstream file(filename);
    std::string line;

    while (std::getline(file, line)) {
        // Split line on ": "
        auto pos = line.find(": ");
        if (pos == std::string::npos)
          continue;

        std::string field = line.substr(0, pos);
        std::string value = line.substr(pos + 2);

        // Remove any trailing whitespace/newlines
        value.erase(std::remove_if(value.begin(), value.end(), ::isspace),
                    value.end());

        if (field == "name") {
          std::memcpy(res.name.name, value.c_str(),
                      std::min(value.length(), (size_t)QNS_NAME_LENGTH));
        } else if (field == "id") {
            strncpy(res.id, value.c_str(), 54);
            res.id[54] = '\0';
        } else if (field == "owner") {
          res.owner = strdup(value.c_str());
        } else if (field == "ipfs") {
          res.ipfs = strdup(value.c_str());
        } else if (field == "expiration") {
          res.expiration = std::stoi(value);
        }
    }

    return res;
}

void qnsRegisterName(const char* nodeIp, int nodePort, const char* seed, const uint32_t scheduledTick, const char* filename)
{
    QNSEntry entry = qnsReadFile(filename);
    qnsRegisterName(nodeIp, nodePort, seed, scheduledTick, entry);
};


void qnsUpdate(const char* nodeIp, int nodePort, const char* seed, const char* filename){

    QNSEntry entry = qnsReadFile(filename);
    qnsUpdate(nodeIp, nodePort, seed, entry);
};


void qnsTransferOwnership(const char* nodeIp, int nodePort, const char* seed, const char* filename){
    QNSEntry entry = qnsReadFile(filename);
    qnsTransferOwnership(nodeIp, nodePort, seed, entry);
};
