#include "stdint.h"
#include "keyUtils.h"
#include "utils.h"
#include "defines.h"

#include "testnetKey.h"
#include "K12AndKeyUtil.h"
//#include "structs.h"
//#include "connection.h"
//#include "fourq-qubic.h"

#include <cstdio>
#include <stdexcept>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

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
    if (argc < 4){
        printf("./broadcastComputorTestnet [nodeip] [epoch] [node port]\n");
        return 0;
    }
    nodePort = std::atoi(argv[3]);
    printf("Broadcasting computor list to %s:%d epoch %s\n", argv[1], nodePort, argv[2]);
    unsigned char src_privatek[N_KEY+1][32] __attribute((aligned(32)));
    unsigned char src_pubkey[N_KEY+1][32] __attribute((aligned(32)));
    unsigned char src_subseed[N_KEY+1][32] __attribute((aligned(32)));

    struct {
        RequestResponseHeader header;
        Computors c;
    } packet;

    packet.header.setSize(sizeof(packet));
    packet.header.randomizeDejavu();
    packet.header.setType(2); // BROADCAST_COMPUTORS
    packet.c.epoch = std::atoi(argv[2]);
    for (int i = 0; i < N_KEY; i++) {
        if (!getSubseedFromSeed((unsigned char *) computorSeeds[i], src_subseed[i])) {
            printf("Error subseeds\n");
            exit(-1);
        }
        getPrivateKeyFromSubSeed(src_subseed[i], src_privatek[i]);
        getPublicKeyFromPrivateKey(src_privatek[i], src_pubkey[i]);
        memcpy(packet.c.publicKeys[i], src_pubkey[i], 32);
    }
    if (!getSubseedFromSeed((uint8_t*)ARB_SEEDS, src_subseed[N_KEY])) {
        printf("Error subseeds\n");
        exit(-1);
    }
    getPrivateKeyFromSubSeed(src_subseed[N_KEY], src_privatek[N_KEY]);
    getPublicKeyFromPrivateKey(src_privatek[N_KEY], src_pubkey[N_KEY]);
    uint8_t digest[32];
    uint8_t sig[64];
    // printf("header size %d\n", sizeof(RequestResponseHeader));
    // printf("computors size %d\n", sizeof(Computors));
    // printf("packet size %d\n", sizeof(packet));
    KangarooTwelve((unsigned char*)&packet.c,
                   sizeof(Computors) - 64,
                   digest,
                   32);

    sign(src_subseed[N_KEY], src_pubkey[N_KEY], digest, packet.c.signature);

    uint8_t arb_pubkey[32];
    getPublicKeyFromIdentity(ARB_IDEN, arb_pubkey);
    if (verify(arb_pubkey, digest, sig)){
        printf("Sig ok\n");
    }
//    printf("trying to send computors...\n");
    qubicSendData(argv[1], reinterpret_cast<char *>(&packet), packet.header.size());
    return 0;
}
