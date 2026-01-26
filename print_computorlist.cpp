#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include "K12AndKeyUtil.h"
#include "keyUtils.h"

#define NUMBER_OF_COMPUTORS 676
#define MAX_NUMBER_OF_SOLUTIONS 65536

#pragma pack(push, 1)
struct SystemFile
{
    int16_t  version;
    uint16_t epoch;
    uint32_t tick;
    uint32_t initialTick;
    uint32_t latestCreatedTick;
    uint32_t latestLedTick;

    uint16_t initialMillisecond;
    uint8_t  initialSecond;
    uint8_t  initialMinute;
    uint8_t  initialHour;
    uint8_t  initialDay;
    uint8_t  initialMonth;
    uint8_t  initialYear;

    uint64_t latestOperatorNonce;

    uint32_t numberOfSolutions;
    struct {
        uint8_t computorPublicKey[32];
        uint8_t miningSeed[32];
        uint8_t nonce[32];
    } solutions[MAX_NUMBER_OF_SOLUTIONS];

    uint8_t futureComputors[NUMBER_OF_COMPUTORS][32];
};
#pragma pack(pop)

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
