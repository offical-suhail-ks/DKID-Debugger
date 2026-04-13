/* dkid_log.c - thread-safe append log */
#include "dkid.h"

void Log(struct nk_color col, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    /* prepend timestamp */
    SYSTEMTIME st; GetLocalTime(&st);
    char line[560];
    snprintf(line, sizeof(line), "%02d:%02d:%02d.%03d  %s",
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);

    EnterCriticalSection(&g_log_cs);
    if (g_log_count < g_log_cap) {
        strncpy(g_log_lines[g_log_count].text, line, 511);
        g_log_lines[g_log_count].color = col;
        g_log_count++;
    }
    LeaveCriticalSection(&g_log_cs);

    /* also print to stdout for debugging */
    puts(buf);
}

void LogClear(void)
{
    EnterCriticalSection(&g_log_cs);
    g_log_count = 0;
    LeaveCriticalSection(&g_log_cs);
}

void LogSave(const char *path)
{
    FILE *fp = fopen(path, "w");
    if (!fp) { Log(IDA_RED,"[!] Cannot write %s", path); return; }
    EnterCriticalSection(&g_log_cs);
    for (int i = 0; i < g_log_count; i++)
        fprintf(fp, "%s\n", g_log_lines[i].text);
    LeaveCriticalSection(&g_log_cs);
    fclose(fp);
    Log(IDA_GREEN, "[+] Log saved: %s", path);
}
