/* dkid_ai.c - AI cleaned disassembly generation via NVIDIA API */
#include "dkid.h"

#define AI_ENDPOINT_HOST L"integrate.api.nvidia.com"
#define AI_ENDPOINT_PATH L"/v1/chat/completions"
#define AI_MODEL         "google/gemma-4-31b-it"
#define AI_REQ_TIMEOUT_MS 180000

static void TrimInPlace(char *s)
{
    int n = (int)strlen(s);
    int a = 0;
    while (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n') a++;
    int b = n - 1;
    while (b >= a && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) b--;
    if (a > 0 && b >= a) memmove(s, s + a, (size_t)(b - a + 1));
    if (b < a) s[0] = 0;
    else s[b - a + 1] = 0;
}

static bool StartsWithNoCase(const char *s, const char *prefix)
{
    while (*prefix && *s) {
        char a = (char)tolower((unsigned char)*s++);
        char b = (char)tolower((unsigned char)*prefix++);
        if (a != b) return false;
    }
    return *prefix == 0;
}

static bool ReadFirstLineFile(const char *path, char *out, int out_sz)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return false;
    size_t n = fread(out, 1, (size_t)(out_sz - 1), fp);
    fclose(fp);
    out[n] = 0;
    char *nl = strpbrk(out, "\r\n");
    if (nl) *nl = 0;
    TrimInPlace(out);
    return out[0] != 0;
}

static bool NormalizeApiKey(char *key, int key_sz)
{
    (void)key_sz;
    TrimInPlace(key);
    if (!key[0]) return false;
    if (StartsWithNoCase(key, "Bearer ")) {
        memmove(key, key + 7, strlen(key + 7) + 1);
        TrimInPlace(key);
    }
    return key[0] != 0;
}

static bool ResolveApiKey(char *key, int key_sz)
{
    DWORD n = GetEnvironmentVariableA("NVIDIA_API_KEY", key, (DWORD)key_sz);
    if (!n || n >= (DWORD)key_sz)
        n = GetEnvironmentVariableA("NVAPI_KEY", key, (DWORD)key_sz);

    if ((!n || n >= (DWORD)key_sz) && !ReadFirstLineFile("nvidia_api_key.txt", key, key_sz)) {
        ReadFirstLineFile("nvapi_key.txt", key, key_sz);
    }

    return NormalizeApiKey(key, key_sz);
}

bool AIReadConfiguredKey(char *out, int out_sz)
{
    if (!out || out_sz <= 1) return false;
    out[0] = 0;
    return ResolveApiKey(out, out_sz);
}

bool AISaveConfiguredKey(const char *input, char *status, int status_sz)
{
    char key[768];
    if (!input) {
        if (status && status_sz > 0) snprintf(status, status_sz, "No input key provided");
        return false;
    }

    snprintf(key, sizeof(key), "%s", input);
    if (!NormalizeApiKey(key, (int)sizeof(key))) {
        if (status && status_sz > 0) snprintf(status, status_sz, "Invalid key format");
        return false;
    }

    FILE *fp = fopen("nvidia_api_key.txt", "wb");
    if (!fp) {
        if (status && status_sz > 0) snprintf(status, status_sz, "Failed to write nvidia_api_key.txt");
        return false;
    }
    fwrite(key, 1, strlen(key), fp);
    fwrite("\n", 1, 1, fp);
    fclose(fp);

    if (status && status_sz > 0) snprintf(status, status_sz, "Saved API key to nvidia_api_key.txt");
    return true;
}

bool AIClearConfiguredKey(char *status, int status_sz)
{
    BOOL a = DeleteFileA("nvidia_api_key.txt");
    BOOL b = DeleteFileA("nvapi_key.txt");
    DWORD e = GetLastError();

    if (a || b || e == ERROR_FILE_NOT_FOUND) {
        if (status && status_sz > 0) snprintf(status, status_sz, "Cleared saved key file(s)");
        return true;
    }

    if (status && status_sz > 0) snprintf(status, status_sz, "Failed to clear key file(s)");
    return false;
}

static void JsonEscapeAppend(char *dst, int dst_sz, int *idx, const char *src)
{
    for (const char *p = src; *p && *idx < dst_sz - 2; ++p) {
        unsigned char c = (unsigned char)*p;
        if (c == '\\') {
            if (*idx < dst_sz - 2) { dst[(*idx)++] = '\\'; dst[(*idx)++] = '\\'; }
        } else if (c == '"') {
            if (*idx < dst_sz - 2) { dst[(*idx)++] = '\\'; dst[(*idx)++] = '"'; }
        } else if (c == '\n') {
            if (*idx < dst_sz - 2) { dst[(*idx)++] = '\\'; dst[(*idx)++] = 'n'; }
        } else if (c == '\r') {
            if (*idx < dst_sz - 2) { dst[(*idx)++] = '\\'; dst[(*idx)++] = 'r'; }
        } else if (c == '\t') {
            if (*idx < dst_sz - 2) { dst[(*idx)++] = '\\'; dst[(*idx)++] = 't'; }
        } else if (c < 0x20) {
            /* skip other control chars */
        } else {
            dst[(*idx)++] = (char)c;
        }
    }
}

static int HexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static void JsonUnescapeString(const char *in, char *out, int out_sz)
{
    int oi = 0;
    for (int i = 0; in[i] && oi < out_sz - 1; ++i) {
        char c = in[i];
        if (c != '\\') {
            out[oi++] = c;
            continue;
        }

        char n = in[++i];
        if (!n) break;
        if (n == 'n') out[oi++] = '\n';
        else if (n == 'r') out[oi++] = '\r';
        else if (n == 't') out[oi++] = '\t';
        else if (n == '"') out[oi++] = '"';
        else if (n == '\\') out[oi++] = '\\';
        else if (n == 'u') {
            /* best effort for \u00XX */
            int h1 = HexVal(in[i+1]), h2 = HexVal(in[i+2]), h3 = HexVal(in[i+3]), h4 = HexVal(in[i+4]);
            if (h1 >= 0 && h2 >= 0 && h3 >= 0 && h4 >= 0) {
                int cp = (h1 << 12) | (h2 << 8) | (h3 << 4) | h4;
                if (cp >= 32 && cp <= 126) out[oi++] = (char)cp;
                else out[oi++] = '?';
                i += 4;
            } else {
                out[oi++] = '?';
            }
        } else {
            out[oi++] = n;
        }
    }
    out[oi] = 0;
}

static bool ExtractFirstJsonStringForKey(const char *json, const char *key, char *out, int out_sz)
{
    const char *p = json;
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    while ((p = strstr(p, needle)) != NULL) {
        const char *colon = strchr(p + (int)strlen(needle), ':');
        if (!colon) return false;
        const char *q = colon + 1;
        while (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n') q++;

        if (*q == '"') {
            q++;
            const char *start = q;
            bool esc = false;
            while (*q) {
                if (!esc && *q == '"') break;
                if (!esc && *q == '\\') esc = true;
                else esc = false;
                q++;
            }
            if (*q != '"') return false;

            int len = (int)(q - start);
            if (len < 0) return false;
            if (len > out_sz * 4) len = out_sz * 4;

            char *tmp = (char*)malloc((size_t)len + 1);
            if (!tmp) return false;
            memcpy(tmp, start, (size_t)len);
            tmp[len] = 0;
            JsonUnescapeString(tmp, out, out_sz);
            free(tmp);
            return true;
        }

        p = q;
    }

    return false;
}

static bool BuildDisasmContext(char *out, int out_sz, int max_lines)
{
    int idx = 0;
    int lines = 0;

    EnterCriticalSection(&g_disasm_cs);
    int max_take = g_disasm_count < max_lines ? g_disasm_count : max_lines;
    for (int i = 0; i < max_take; i++) {
        char line[320];
        DisasmLine *ln = &g_disasm[i];
        if (ln->comment[0]) {
            snprintf(line, sizeof(line), "0x%016llX: %-10s %-44s ; %s\n",
                     (unsigned long long)ln->addr, ln->mnem, ln->operands, ln->comment);
        } else {
            snprintf(line, sizeof(line), "0x%016llX: %-10s %s\n",
                     (unsigned long long)ln->addr, ln->mnem, ln->operands);
        }

        int need = (int)strlen(line);
        if (idx + need >= out_sz - 1) break;
        memcpy(out + idx, line, (size_t)need);
        idx += need;
        lines++;
    }
    LeaveCriticalSection(&g_disasm_cs);

    out[idx] = 0;
    return lines > 0;
}

static bool PostNvidiaCleanRequest(const char *api_key, const char *prompt, char *out_text, int out_text_sz, char *err, int err_sz)
{
    bool ok = false;
    HINTERNET h_session = NULL, h_connect = NULL, h_request = NULL;
    WCHAR auth_w[1024];

    char escaped_prompt[128000];
    int ep = 0;
    escaped_prompt[0] = 0;
    JsonEscapeAppend(escaped_prompt, (int)sizeof(escaped_prompt), &ep, prompt);
    escaped_prompt[ep] = 0;

    char payload[131072];
    snprintf(payload, sizeof(payload),
        "{\"model\":\"" AI_MODEL "\","
        "\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}],"
        "\"max_tokens\":4096,"
        "\"temperature\":0.3,"
        "\"top_p\":0.95,"
        "\"stream\":false}"
        , escaped_prompt);

    int auth_len = MultiByteToWideChar(CP_UTF8, 0, api_key, -1, NULL, 0);
    if (auth_len <= 0 || auth_len > 900) {
        snprintf(err, err_sz, "Invalid API key format");
        return false;
    }

    WCHAR bearer_w[1024];
    bearer_w[0] = 0;
    wcscpy(bearer_w, L"Bearer ");
    MultiByteToWideChar(CP_UTF8, 0, api_key, -1, bearer_w + 7, 1024 - 7);
    swprintf(auth_w, 1024, L"Authorization: %ls\r\nContent-Type: application/json\r\nAccept: application/json\r\n", bearer_w);

    h_session = WinHttpOpen(L"DKID/3.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!h_session) {
        snprintf(err, err_sz, "WinHttpOpen failed (%lu)", GetLastError());
        goto done;
    }

    WinHttpSetTimeouts(h_session, 30000, 30000, 30000, AI_REQ_TIMEOUT_MS);

    h_connect = WinHttpConnect(h_session, AI_ENDPOINT_HOST, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!h_connect) {
        snprintf(err, err_sz, "WinHttpConnect failed (%lu)", GetLastError());
        goto done;
    }

    h_request = WinHttpOpenRequest(h_connect, L"POST", AI_ENDPOINT_PATH,
                                   NULL, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   WINHTTP_FLAG_SECURE);
    if (!h_request) {
        snprintf(err, err_sz, "WinHttpOpenRequest failed (%lu)", GetLastError());
        goto done;
    }

    DWORD payload_len = (DWORD)strlen(payload);
    if (!WinHttpSendRequest(h_request,
            auth_w, (DWORD)-1L,
            (LPVOID)payload, payload_len, payload_len, 0)) {
        snprintf(err, err_sz, "WinHttpSendRequest failed (%lu)", GetLastError());
        goto done;
    }

    if (!WinHttpReceiveResponse(h_request, NULL)) {
        DWORD werr = GetLastError();
        if (werr == ERROR_WINHTTP_TIMEOUT) {
            snprintf(err, err_sz, "AI request timed out (12002). Retrying with smaller context...");
        } else {
            snprintf(err, err_sz, "WinHttpReceiveResponse failed (%lu)", werr);
        }
        goto done;
    }

    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    WinHttpQueryHeaders(h_request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &status_code, &status_size, WINHTTP_NO_HEADER_INDEX);

    char *resp = NULL;
    int resp_cap = 0, resp_len = 0;

    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(h_request, &avail)) {
            snprintf(err, err_sz, "WinHttpQueryDataAvailable failed (%lu)", GetLastError());
            goto done;
        }
        if (avail == 0) break;

        if (resp_len + (int)avail + 1 > resp_cap) {
            int new_cap = resp_cap ? resp_cap * 2 : 8192;
            while (new_cap < resp_len + (int)avail + 1) new_cap *= 2;
            char *new_buf = (char*)realloc(resp, (size_t)new_cap);
            if (!new_buf) {
                free(resp);
                snprintf(err, err_sz, "Out of memory while reading API response");
                return false;
            }
            resp = new_buf;
            resp_cap = new_cap;
        }

        DWORD got = 0;
        if (!WinHttpReadData(h_request, resp + resp_len, avail, &got)) {
            free(resp);
            snprintf(err, err_sz, "WinHttpReadData failed (%lu)", GetLastError());
            return false;
        }
        resp_len += (int)got;
    }

    if (!resp) {
        snprintf(err, err_sz, "Empty API response");
        goto done;
    }

    resp[resp_len] = 0;

    if (status_code < 200 || status_code >= 300) {
        char snippet[220];
        snprintf(snippet, sizeof(snippet), "%.200s", resp);
        snprintf(err, err_sz, "API HTTP %lu: %s", (unsigned long)status_code, snippet);
        free(resp);
        goto done;
    }

    if (!ExtractFirstJsonStringForKey(resp, "content", out_text, out_text_sz)) {
        if (ExtractFirstJsonStringForKey(resp, "text", out_text, out_text_sz)) {
            ok = true;
        } else {
            char snippet[220];
            snprintf(snippet, sizeof(snippet), "%.200s", resp);
            snprintf(err, err_sz, "Could not parse model output: %s", snippet);
        }
    } else {
        ok = true;
    }

    free(resp);

done:
    if (h_request) WinHttpCloseHandle(h_request);
    if (h_connect) WinHttpCloseHandle(h_connect);
    if (h_session) WinHttpCloseHandle(h_session);
    return ok;
}

static DWORD WINAPI CleanDisasmThread(LPVOID param)
{
    (void)param;

    char key[768] = {0};
    if (!ResolveApiKey(key, (int)sizeof(key))) {
        EnterCriticalSection(&g_clean_disasm_cs);
        g_clean_disasm_running = false;
        snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status),
                 "Missing API key (env or nvidia_api_key.txt)");
        LeaveCriticalSection(&g_clean_disasm_cs);
        Log(IDA_RED, "[!] Cleaned disassembly: set NVIDIA_API_KEY/NVAPI_KEY or create nvidia_api_key.txt");
        return 0;
    }

    char disasm_blob[65536];
    if (!BuildDisasmContext(disasm_blob, (int)sizeof(disasm_blob), 180)) {
        EnterCriticalSection(&g_clean_disasm_cs);
        g_clean_disasm_running = false;
        snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status), "No disassembly available");
        LeaveCriticalSection(&g_clean_disasm_cs);
        Log(IDA_RED, "[!] Cleaned disassembly: no disassembly lines to analyze");
        return 0;
    }

    char result[131072];
    char err[256] = {0};
    bool ok = false;

    for (int attempt = 0; attempt < 2 && !ok; attempt++) {
        int max_lines = (attempt == 0) ? 180 : 80;
        int max_tokens = (attempt == 0) ? 2048 : 1024;

        if (!BuildDisasmContext(disasm_blob, (int)sizeof(disasm_blob), max_lines)) {
            break;
        }

        char prompt[90000];
        snprintf(prompt, sizeof(prompt),
            "You are a reverse engineering assistant. Convert this x64 disassembly into a concise, human-readable explanation. "
            "Return plain text with these sections: Function Purpose, Key Blocks, Data Flow, APIs/Calls, Security Notes, and Pseudocode (high level). "
            "Do not hallucinate unknown symbols. Mark uncertain inferences clearly. Keep response under %d tokens.\n\n"
            "Target process: %s\n"
            "Target module: %s\n\n"
            "Disassembly:\n%s",
            max_tokens,
            g_target_name[0] ? g_target_name : "<unknown>",
            g_dll_name[0] ? g_dll_name : "<unknown>",
            disasm_blob);

        ok = PostNvidiaCleanRequest(key, prompt, result, (int)sizeof(result), err, (int)sizeof(err));
        if (!ok && attempt == 0 && strstr(err, "12002")) {
            EnterCriticalSection(&g_clean_disasm_cs);
            snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status),
                     "Timeout on first try, retrying with smaller context...");
            LeaveCriticalSection(&g_clean_disasm_cs);
        }
    }

    EnterCriticalSection(&g_clean_disasm_cs);
    g_clean_disasm_running = false;
    if (ok) {
        strncpy(g_clean_disasm_text, result, sizeof(g_clean_disasm_text) - 1);
        g_clean_disasm_text[sizeof(g_clean_disasm_text) - 1] = 0;
        snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status), "Generated successfully");
        Log(IDA_GREEN, "[+] Cleaned disassembly generated by AI");
    } else {
        if (strstr(err, "12002")) {
            snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status),
                     "Timed out (12002). Check internet/proxy and try again.");
        } else {
            snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status), "%s", err[0] ? err : "Request failed");
        }
        Log(IDA_RED, "[!] Cleaned disassembly failed: %s", g_clean_disasm_status);
    }
    LeaveCriticalSection(&g_clean_disasm_cs);

    return 0;
}

void CleanDisasmRequest(void)
{
    if (g_clean_disasm_running) {
        Log(IDA_YELLOW, "[*] Cleaned disassembly request already running");
        return;
    }

    if (!g_attached || !g_target || !g_dll_base || g_disasm_count <= 0) {
        Log(IDA_RED, "[!] Attach, select module, and run Disasm first");
        EnterCriticalSection(&g_clean_disasm_cs);
        snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status), "Need attached disassembly first");
        LeaveCriticalSection(&g_clean_disasm_cs);
        return;
    }

    EnterCriticalSection(&g_clean_disasm_cs);
    g_clean_disasm_running = true;
    snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status), "Sending request to NVIDIA API...");
    LeaveCriticalSection(&g_clean_disasm_cs);

    DWORD tid = 0;
    HANDLE h = CreateThread(NULL, 0, CleanDisasmThread, NULL, 0, &tid);
    if (!h) {
        EnterCriticalSection(&g_clean_disasm_cs);
        g_clean_disasm_running = false;
        snprintf(g_clean_disasm_status, sizeof(g_clean_disasm_status), "Failed to start worker thread");
        LeaveCriticalSection(&g_clean_disasm_cs);
        Log(IDA_RED, "[!] Failed to start AI worker thread (%lu)", GetLastError());
        return;
    }
    CloseHandle(h);
    Log(IDA_CYAN, "[*] Cleaned disassembly analysis started");
}
