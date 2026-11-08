/* Link against the generated library/header; this is not an iOS runtime test. */
#include "librclone.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check(char *result, const char *needle) {
    if (!result || !strstr(result, needle)) {
        fputs("C ABI envelope failed\n", stderr);
        exit(1);
    }
    MinisAppProxyFreeString(result);
}

int main(void) {
    char off[] = "{\"mode\":\"off\"}";
    char invalid[] = "unsupported://example";
    check(MinisAppProxyConfigure(off), "\"ok\":true");
    if (MinisAppProxyStrictEnabled()) return 1;
    check(MinisAppProxyStatus(), "\"mode\":\"off\"");
    check(MinisAppProxyImport(invalid), "\"issues\"");
    check(MinisAppProxyStop(), "\"mode\":\"blocked\"");
    if (!MinisAppProxyStrictEnabled()) return 1;
    check(MinisAppProxyConfigure(off), "\"ok\":true");
    if (MinisAppProxyStrictEnabled()) return 1;
    puts("C ABI configure/import/status/strict-state/stop/free: PASS");
    return 0;
}
