/*
 * fake-miner.c (DEFANGED)
 * -----------------------
 * This is a safe, non-malicious test program that mimics cryptomining behavior.
 * It simulates network activity and creates registry persistence to trigger logs
 * in Microsoft Defender for Endpoint. This program does NOT perform real cryptographic
 * computations or mining.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <shlwapi.h>  // Needed for registry persistence
#pragma comment(lib, "ws2_32.lib")  // Link against Windows Sockets API
#pragma comment(lib, "Shlwapi.lib") // Link against Windows Shell API
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#define MINING_POOL "pool.xmr-example.com"
#define MINING_POOL_IP "192.168.1.100"  // Fake mining pool IP
#define MINING_POOL_PORT 3333
#define TEST_URL "http://example.com/fake_mining_activity"
#define REG_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define REG_VALUE_NAME "FakeMiner"

void simulate_network_activity() {
#ifdef _WIN32
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    char *message = "FAKE_MINER_HASH_REQUEST";

    printf("[*] Initializing Winsock...\n");
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("[-] Winsock init failed. Error Code : %d\n", WSAGetLastError());
        return;
    }

    // Create a socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("[-] Could not create socket. Error Code : %d\n", WSAGetLastError());
        WSACleanup();
        return;
    }

    server.sin_addr.s_addr = inet_addr(MINING_POOL_IP);
    server.sin_family = AF_INET;
    server.sin_port = htons(MINING_POOL_PORT);

    // Attempt to connect (will likely fail unless a listener is running)
    printf("[*] Connecting to mining pool %s (%s:%d)...\n", MINING_POOL, MINING_POOL_IP, MINING_POOL_PORT);
    connect(s, (struct sockaddr *)&server, sizeof(server));

    // Send fake mining request
    send(s, message, strlen(message), 0);
    closesocket(s);
    WSACleanup();

    // Simulate an HTTP request to mimic real-world miner traffic
    printf("[*] Sending fake HTTP request to simulate miner traffic...\n");
    system("powershell.exe -Command Invoke-WebRequest -Uri " TEST_URL " -UseBasicParsing");
#else
    printf("[*] Pinging fake mining pool (%s)...\n", MINING_POOL_IP);
    system("ping -c 1 " MINING_POOL_IP);

    printf("[*] Sending fake HTTP request to simulate miner traffic...\n");
    system("curl -s " TEST_URL " > /dev/null");
#endif
}

// Function to create registry persistence
void add_registry_persistence() {
#ifdef _WIN32
    HKEY hKey;
    char exePath[MAX_PATH];

    // Get the current executable path
    GetModuleFileName(NULL, exePath, MAX_PATH);

    printf("[*] Adding registry persistence...\n");

    // Open the Run key
    if (RegOpenKeyEx(HKEY_CURRENT_USER, REG_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueEx(hKey, REG_VALUE_NAME, 0, REG_SZ, (BYTE *)exePath, (DWORD)(strlen(exePath) + 1)) == ERROR_SUCCESS) {
            printf("[+] Successfully added registry persistence: %s -> %s\n", REG_VALUE_NAME, exePath);
        } else {
            printf("[-] Failed to set registry value.\n");
        }
        RegCloseKey(hKey);
    } else {
        printf("[-] Failed to open registry key.\n");
    }
#else
    printf("[*] Registry persistence not supported on this OS.\n");
#endif
}

// Function to remove registry persistence
void remove_registry_persistence() {
#ifdef _WIN32
    HKEY hKey;
    
    printf("[*] Removing registry persistence...\n");

    // Open the Run key
    if (RegOpenKeyEx(HKEY_CURRENT_USER, REG_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegDeleteValue(hKey, REG_VALUE_NAME) == ERROR_SUCCESS) {
            printf("[+] Successfully removed registry persistence: %s\n", REG_VALUE_NAME);
        } else {
            printf("[-] Failed to delete registry value.\n");
        }
        RegCloseKey(hKey);
    } else {
        printf("[-] Failed to open registry key.\n");
    }
#endif
}

int main(void) {
    printf("[*] Starting Fake Cryptominer...\n");
    printf("[*] Connecting to pool: %s\n", MINING_POOL);
    printf("[*] Using wallet: FakeWallet1234567890\n");
    printf("[*] Mining as user: FakeMinerUser\n");
    printf("[*] This is a DEFANGED, benign test executable. No real mining occurs.\n");

    // Add registry persistence
    add_registry_persistence();

    for (int i = 0; i < 5; i++) {
        printf("[FakeMiner] Mining iteration %d...\n", i+1);
        simulate_network_activity();
#ifdef _WIN32
        Sleep(3000);
#else
        sleep(3);
#endif
    }

    // Remove registry persistence before exiting
    remove_registry_persistence();

    printf("[*] FakeMiner has completed its run.\n");
    return 0;
}
