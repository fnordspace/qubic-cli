#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include "K12AndKeyUtil.h"
#include "keyUtils.h"

#define NUMBER_OF_COMPUTORS 676
#define MAX_NUMBER_OF_SOLUTIONS 65536

struct SystemFile
{
    int16_t  version;           // 2
    uint16_t epoch;             // 2
    uint32_t tick;              // 4
    uint32_t initialTick;       // 4
    uint32_t latestCreatedTick; // 4
    uint32_t latestLedTick;     // 4  -> 20 bytes

    uint16_t initialMillisecond; // 2
    uint8_t  initialSecond;      // 1
    uint8_t  initialMinute;      // 1
    uint8_t  initialHour;        // 1
    uint8_t  initialDay;         // 1
    uint8_t  initialMonth;       // 1
    uint8_t  initialYear;        // 1  -> 8 bytes

    uint64_t latestOperatorNonce; // 8 bytes

    uint32_t numberOfSolutions;  // 4
    uint32_t _padding;           // 4 (compiler alignment for m256i)
    struct {
        uint8_t computorPublicKey[32];
        uint8_t miningSeed[32];
        uint8_t nonce[32];
    } solutions[MAX_NUMBER_OF_SOLUTIONS];

    uint8_t futureComputors[NUMBER_OF_COMPUTORS][32];
};

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <system.eoe>\n", argv[0]);
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f)
    {
        fprintf(stderr, "Error: cannot open '%s'\n", argv[1]);
        return 1;
    }

    SystemFile sys;
    size_t n = fread(&sys, 1, sizeof(sys), f);
    fclose(f);

    if (n != sizeof(sys))
    {
        fprintf(stderr, "Error: expected %zu bytes, got %zu\n", sizeof(sys), n);
        return 1;
    }

    fprintf(stderr, "epoch=%u  tick=%u  initialTick=%u  solutions=%u\n",
            sys.epoch, sys.tick, sys.initialTick, sys.numberOfSolutions);

    char identity[61];
    for (int i = 0; i < NUMBER_OF_COMPUTORS; i++)
    {
        memset(identity, 0, sizeof(identity));
        getIdentityFromPublicKey(sys.futureComputors[i], identity, false);
        printf("%3d %s\n", i, identity);
    }

    return 0;
}
