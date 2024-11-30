#include "stdint.h"
#include "keyUtils.h"
#include "utils.h"
#include "defines.h"

#include "K12AndKeyUtil.h"
//#include "structs.h"
//#include "connection.h"
//#include "fourq-qubic.h"

#include <cstdint>
#include <cstdio>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>

struct RequestResponseHeader {
private:
    uint8_t _size[3];
    uint8_t _type;
    unsigned int _dejavu;

public:
    inline unsigned int size() {
        if (((*((unsigned int*)_size)) & 0xFFFFFF)==0) return INT32_MAX; // size is never zero, zero means broken packets
        return (*((unsigned int*)_size)) & 0xFFFFFF;
    }

    inline void setSize(unsigned int size) {
        _size[0] = (uint8_t)size;
        _size[1] = (uint8_t)(size >> 8);
        _size[2] = (uint8_t)(size >> 16);
    }

    inline bool isDejavuZero()
    {
        return !_dejavu;
    }

    inline void zeroDejavu()
    {
        _dejavu = 0;
    }

    inline void randomizeDejavu()
    {
        rand32(&_dejavu);
        if (!_dejavu)
        {
            _dejavu = 1;
        }
    }

    inline uint8_t type()
    {
        return _type;
    }

    inline void setType(const uint8_t type)
    {
        _type = type;
    }
};
typedef struct
{
    unsigned char publicKey[32];
} RequestedEntity;

struct Tick
{
    unsigned short computorIndex;
    unsigned short epoch;
    unsigned int tick;

    unsigned short millisecond;
    unsigned char second;
    unsigned char minute;
    unsigned char hour;
    unsigned char day;
    unsigned char month;
    unsigned char year;

    unsigned long long prevResourceTestingDigest;
    unsigned long long saltedResourceTestingDigest;

    uint8_t prevSpectrumDigest[32];
    uint8_t prevUniverseDigest[32];
    uint8_t prevComputerDigest[32];
    uint8_t saltedSpectrumDigest[32];
    uint8_t saltedUniverseDigest[32];
    uint8_t saltedComputerDigest[32];

    uint8_t transactionDigest[32];
    uint8_t expectedNextTickTransactionDigest[32];

    unsigned char signature[SIGNATURE_SIZE];
    static constexpr unsigned char type()
    {
        return 3;
    }
};

#define NUMBER_OF_COMPUTOR 676

//#pragma pack(push, 1)
typedef struct
{
    // TODO: Padding
    unsigned short epoch;
    uint8_t publicKeys[NUMBER_OF_COMPUTOR][32];
    unsigned char signature[64];
} Computors;
//#pragma pack(pop)

 
#define ARB_SEEDS "oetvbpntxzlcgdhafoyjglrfcbegivrbzjlzchfhjudrhcnvsftdqyt"
#define ARB_IDEN "MEFKYFCDXDUILCAJKOIKWQAPENJDUHSSYPBRWFOTLALILAYWQFDSITJELLHG"
#define N_KEY NUMBER_OF_COMPUTOR
int nodePort = 0;

static bool qubicSendData(char* ip, char *buffer, unsigned int size) {

    printf("Start Sending \n");
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 500000;
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);
    if (serverSocket < 0) {
        printf("Failed to create a socket!\n");
        return false;
    }
    sockaddr_in addr;

    explicit_bzero((char *)&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(nodePort);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        printf("Error translating command line ip address to usable one.");
        return false;
    }

    if (connect(serverSocket, (const sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("Failed to connect, done here.\n");
        return false;
    }

    printf("Start Sending for readl\n");
    while (size) {
        int numberOfBytes = size;
        if ((numberOfBytes = send(serverSocket, buffer, numberOfBytes, 0)) <= 0) {
            strerror(errno);
            return false;
        }
        buffer += numberOfBytes;
        size -= numberOfBytes;
        printf("sent %d bytes\n", numberOfBytes);
    }


    printf("closing  \n");
    close(serverSocket);
    printf("closed  \n");
    return true;
}


int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("./broadcastComputorTestnet [nodeip] [epoch] [node port] [Complist "
               "file]\n");
        return 0;
    }

    nodePort = std::atoi(argv[3]);
    printf("Broadcasting computor list to %s:%d epoch %s\n", argv[1], nodePort,
           argv[2]);

    std::vector<std::string> IDs;

    // Also try reading complists format
    std::ifstream complist(argv[4]);
    std::string line;
    while (std::getline(complist, line)) {
        // Skip empty lines
        if (line.empty())
            continue;

        // Check if line starts with "Epoch:" or contains "VERIFIED"
        if (line.find("Epoch:") != std::string::npos ||
            line.find("Computor list") != std::string::npos) {
            break;
        }

        // Extract ID by removing leading number and whitespace
        size_t idStart = line.find_first_not_of("0123456789 ");
        if (idStart != std::string::npos) {
            std::string id = line.substr(idStart);
            if (!id.empty()) {
            IDs.push_back(id);
            }
        }
    }

    if (IDs.size() != N_KEY) {
        printf("Error: ID file must contain exactly %d id\n", N_KEY);
        return -1;
    }

    // unsigned char src_privatek[N_KEY + 1][32] __attribute((aligned(32)));
    uint8_t src_pubkey[N_KEY][32] __attribute((aligned(32)));
    // unsigned char src_subseed[N_KEY + 1][32] __attribute((aligned(32)));

    unsigned char arb_privatek[32] __attribute((aligned(32)));
    unsigned char arb_pubkey[32] __attribute((aligned(32)));
    unsigned char arb_subseed[32] __attribute((aligned(32)));

    struct {
        RequestResponseHeader header;
        Computors c;
    } packet;

    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(2); // BROADCAST_COMPUTORS
    packet.c.epoch = std::atoi(argv[2]);

    for (int i = 0; i < N_KEY; i++) {
        getPublicKeyFromIdentity(IDs[i].c_str(), src_pubkey[i]);
        memcpy(packet.c.publicKeys[i], src_pubkey[i], 32);
        printf("Added ID Nr. %u %s\n", i+1, IDs[i].c_str());
        printf("Generated pubkey: ");
        bool nonZero = false;
        for (int j = 0; j < 32; j++) {
            printf("%02x", src_pubkey[i][j]);
            if (src_pubkey[i][j] != 0) {
              nonZero = true;
            }
        }
        if (!nonZero) {
            printf(" WARNING: All bytes are zero!");
        }
        printf("\n\n");
    }
    if (!getSubseedFromSeed((uint8_t *)ARB_SEEDS, arb_subseed)) {
        printf("Error subseeds\n");
        exit(-1);
    }
    getPrivateKeyFromSubSeed(arb_subseed, arb_privatek);
    getPublicKeyFromPrivateKey(arb_privatek, arb_pubkey);

    uint8_t digest[32];
    uint8_t sig[64];

    KangarooTwelve((unsigned char *)&packet.c, sizeof(Computors) - 64, digest,
                   32);

    sign(arb_subseed, arb_pubkey, digest, packet.c.signature);

    // uint8_t arb_pubkey[32];
    getPublicKeyFromIdentity(ARB_IDEN, arb_pubkey);
    if (verify(arb_pubkey, digest, sig)) {
        printf("Sig ok\n");
    }

    qubicSendData(argv[1], reinterpret_cast<char *>(&packet),
                  packet.header.size());
    return 0;
}
