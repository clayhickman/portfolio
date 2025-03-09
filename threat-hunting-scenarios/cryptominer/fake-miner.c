/*
 * fake-miner.c
 * -------------------
 * This sample file is DEFANGED. It does NOT perform cryptomining or malicious activity.
 * It ONLY includes strings that might be detected or flagged by antivirus or EDR solutions.
 */

#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

int main(void)
{
    // Suspicious strings and comments to trigger detection heuristics:
    const char *poolAddress = "pool.xmr-example.com";   // Fake mining pool address
    const char *walletID    = "FakeWallet1234567890";   // Fake wallet address
    const char *minerUser   = "FakeMinerUser";          // Fake username

    // Mentioning known cryptominer references:
    // XMRig, Claymore, ccminer, cryptonight, etc.

    printf("Starting XMRig Miner...\n");
    printf("Connecting to pool: %s\n", poolAddress);
    printf("Using wallet: %s\n", walletID);
    printf("Mining as user: %s\n", minerUser);
    printf("This is a DEFANGED, benign test executable. No real mining occurs.\n");

    // Simulate some "activity"
    for(int i = 0; i < 5; i++){
        printf("[FakeMiner] Mining iteration %d...\n", i+1);
        // In real malware, here you might have cryptographic hashing or network code.
        // We do nothing but sleep for a second.
        #ifdef _WIN32
            Sleep(1000);
        #else
            sleep(1);
        #endif
    }

    printf("FakeMiner has completed its run.\n");
    return 0;
}
