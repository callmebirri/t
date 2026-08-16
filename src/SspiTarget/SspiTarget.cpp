#include <winsock2.h>
#include <windows.h>

#define SECURITY_WIN32
#include <sspi.h>
#include <schannel.h>
#include <ws2tcpip.h>
#include <winhttp.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

static std::mutex g_printMutex;
static long g_delayMs = 0;

static void PrintLn(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_printMutex);
    printf("%s\n", line.c_str());
    fflush(stdout);
}

struct SspiConnection {
    SOCKET sock = INVALID_SOCKET;
    CredHandle cred = {};
    CtxtHandle ctx = {};
    std::vector<char> recvBuf;
};

static bool ConnectSocket(SspiConnection& c, const std::string& host, int port, std::string& err) {
    c.sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (c.sock == INVALID_SOCKET) {
        err = "socket failed";
        return false;
    }
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
        err = "getaddrinfo failed for " + host;
        return false;
    }
    int rc = connect(c.sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);
    if (rc != 0) {
        err = "connect failed";
        return false;
    }
    return true;
}

static bool DoHandshake(SspiConnection& c, const std::string& host, std::string& err) {
    SCHANNEL_CRED sc = {};
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
    sc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;    SECURITY_STATUS st = AcquireCredentialsHandleW(nullptr, const_cast<LPWSTR>(UNISP_NAME_W), SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &c.cred, nullptr);
    if (st != SEC_E_OK) {
        err = "AcquireCredentialsHandleW failed: " + std::to_string(st);
        return false;
    }
    if (g_delayMs > 0) {
        Sleep(static_cast<DWORD>(g_delayMs));
    }
    std::wstring target(host.begin(), host.end());
    ULONG reqFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
    DWORD attr = 0;
    bool first = true;
    SecBufferDesc outDesc = {SECBUFFER_VERSION, 1, nullptr};
    SecBuffer outBuf = {SECBUFFER_TOKEN, 0, nullptr};
    outDesc.pBuffers = &outBuf;
    SecBufferDesc inDesc = {SECBUFFER_VERSION, 1, nullptr};
    SecBuffer inBuf = {SECBUFFER_TOKEN, 0, nullptr};
    inDesc.pBuffers = &inBuf;
    for (int round = 0; round < 32; ++round) {
        st = InitializeSecurityContextW(&c.cred, first ? nullptr : &c.ctx, target.data(), reqFlags, 0, 0,
                                        first ? nullptr : &inDesc, 0, &c.ctx, &outDesc, &attr, nullptr);
        if (outBuf.cbBuffer > 0 && outBuf.pvBuffer) {
            int sent = send(c.sock, static_cast<const char*>(outBuf.pvBuffer), static_cast<int>(outBuf.cbBuffer), 0);
            FreeContextBuffer(outBuf.pvBuffer);
            outBuf.pvBuffer = nullptr;
            outBuf.cbBuffer = 0;
            if (sent == SOCKET_ERROR) {
                err = "send handshake token failed";
                return false;
            }
        }
        if (st == SEC_E_OK) {
            SecPkgContext_ConnectionInfo ci = {};
            if (QueryContextAttributesW(&c.ctx, SECPKG_ATTR_CONNECTION_INFO, &ci) == SEC_E_OK) {
                std::lock_guard<std::mutex> lock(g_printMutex);
                printf("[sspi] negotiated protocol 0x%lx cipher 0x%lx attrs 0x%lx\n", static_cast<unsigned long>(ci.dwProtocol), static_cast<unsigned long>(ci.aiCipher), static_cast<unsigned long>(attr));
            }
            return true;
        }
        if (st == SEC_I_CONTINUE_NEEDED) {
            c.recvBuf.resize(64 * 1024);
            int n = recv(c.sock, c.recvBuf.data(), static_cast<int>(c.recvBuf.size()), 0);
            if (n <= 0) {
                err = "recv handshake token failed";
                return false;
            }
            inBuf.pvBuffer = c.recvBuf.data();
            inBuf.cbBuffer = static_cast<ULONG>(n);
            first = false;
            continue;
        }
        err = "InitializeSecurityContextW round " + std::to_string(round) + " failed: " + std::to_string(st);
        return false;
    }
    err = "handshake rounds exceeded";
    return false;
}

static bool EncryptAndSend(SspiConnection& c, const std::string& data, std::string& err) {
    SecPkgContext_StreamSizes sizes = {};
    SECURITY_STATUS qst = QueryContextAttributesW(&c.ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    if (qst != SEC_E_OK) {
        err = "QueryContextAttributes STREAM_SIZES failed: " + std::to_string(qst);
        return false;
    }
    std::lock_guard<std::mutex> lock(g_printMutex);
    printf("[sspi] stream sizes header=%lu maxmsg=%lu trailer=%lu\n", static_cast<unsigned long>(sizes.cbHeader), static_cast<unsigned long>(sizes.cbMaximumMessage), static_cast<unsigned long>(sizes.cbTrailer));
    std::vector<char> header(sizes.cbHeader);
    std::vector<char> trailer(sizes.cbTrailer);
    SecBuffer bufs[4] = {};
    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer = header.data();
    bufs[0].cbBuffer = static_cast<ULONG>(header.size());
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].pvBuffer = const_cast<char*>(data.data());
    bufs[1].cbBuffer = static_cast<ULONG>(data.size());
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer = trailer.data();
    bufs[2].cbBuffer = static_cast<ULONG>(trailer.size());
    bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};
    SECURITY_STATUS st = EncryptMessage(&c.ctx, 0, &desc, 0);
    if (st == SEC_E_BUFFER_TOO_SMALL) {
        err = "EncryptMessage needs " + std::to_string(bufs[3].cbBuffer) + " bytes total";
        return false;
    }
    if (st != SEC_E_OK) {
        err = "EncryptMessage failed: " + std::to_string(st);
        return false;
    }
    WSABUF ws[3];
    ws[0].buf = header.data();
    ws[0].len = bufs[0].cbBuffer;
    ws[1].buf = const_cast<char*>(data.data());
    ws[1].len = bufs[1].cbBuffer;
    ws[2].buf = trailer.data();
    ws[2].len = bufs[2].cbBuffer;
    DWORD sent = 0;
    if (WSASend(c.sock, ws, 3, &sent, 0, nullptr, nullptr) == SOCKET_ERROR) {
        err = "WSASend failed";
        return false;
    }
    return true;
}

static bool ResponseComplete(const std::string& out) {
    size_t sep = out.find("\r\n\r\n");
    if (sep == std::string::npos) {
        return false;
    }
    size_t headEnd = sep;
    size_t pos = 0;
    size_t contentLength = 0;
    bool haveLength = false;
    while (pos < headEnd) {
        size_t eol = out.find("\r\n", pos);
        if (eol == std::string::npos || eol > headEnd) {
            eol = headEnd;
        }
        std::string line = out.substr(pos, eol - pos);
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string name = line.substr(0, colon);
            for (auto& ch : name) {
                ch = static_cast<char>(toupper(static_cast<unsigned char>(ch)));
            }
            if (name == "CONTENT-LENGTH") {
                contentLength = static_cast<size_t>(std::strtoul(line.substr(colon + 1).c_str(), nullptr, 10));
                haveLength = true;
            }
        }
        if (eol == headEnd) {
            break;
        }
        pos = eol + 2;
    }
    size_t bodyLen = out.size() - (headEnd + 4);
    return !haveLength || bodyLen >= contentLength;
}

static bool ReceivePlaintext(SspiConnection& c, std::string& out, bool& contextExpired, std::string& err) {
    std::vector<char> net(64 * 1024);
    int n = recv(c.sock, net.data(), static_cast<int>(net.size()), 0);
    if (n <= 0) {
        return false;
    }
    SecBuffer bufs[4] = {};
    bufs[0].BufferType = SECBUFFER_DATA;
    bufs[0].pvBuffer = net.data();
    bufs[0].cbBuffer = static_cast<ULONG>(n);
    bufs[1].BufferType = SECBUFFER_EMPTY;
    bufs[2].BufferType = SECBUFFER_EMPTY;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    SecBufferDesc desc = {SECBUFFER_VERSION, 4, bufs};
    ULONG qop = 0;
    SECURITY_STATUS st = DecryptMessage(&c.ctx, &desc, 0, &qop);
    if (st == SEC_E_OK) {
        out.append(static_cast<const char*>(bufs[0].pvBuffer), bufs[0].cbBuffer);
        return true;
    }
    if (st == SEC_I_CONTEXT_EXPIRED) {
        contextExpired = true;
        return true;
    }
    err = "DecryptMessage failed: " + std::to_string(st);
    return false;
}

static void CloseConnection(SspiConnection& c) {
    if (c.sock != INVALID_SOCKET) {
        shutdown(c.sock, SD_BOTH);
        closesocket(c.sock);
        c.sock = INVALID_SOCKET;
    }
    DeleteSecurityContext(&c.ctx);
    FreeCredentialsHandle(&c.cred);
}

static void SspiClientTask(const std::string& host, int port, const std::string& marker, bool raw) {
    std::string err;
    SspiConnection c;
    if (!ConnectSocket(c, host, port, err)) {
        PrintLn("[sspi:" + marker + "] connect failed: " + err);
        return;
    }
    if (!DoHandshake(c, host, err)) {
        PrintLn("[sspi:" + marker + "] handshake failed: " + err);
        CloseConnection(c);
        return;
    }
    std::string payload;
    if (raw) {
        payload = "BIRRI-RAW-" + marker + "-" + std::string(64, 'x') + "\r\n\r\n";
    } else {
        payload = "GET /?marker=" + marker + " HTTP/1.1\r\nHost: " + host + ":" + std::to_string(port) +
                  "\r\nX-Marker: " + marker + "\r\nConnection: close\r\n\r\n";
    }
    if (!EncryptAndSend(c, payload, err)) {
        PrintLn("[sspi:" + marker + "] send failed: " + err);
        CloseConnection(c);
        return;
    }
    std::string plain;
    bool expired = false;
    int rounds = 0;
    while (rounds < 64) {
        ++rounds;
        if (!ReceivePlaintext(c, plain, expired, err)) {
            break;
        }
        if (expired) {
            break;
        }
        if (raw) {
            if (!plain.empty()) {
                break;
            }
        } else if (ResponseComplete(plain)) {
            break;
        }
    }
    PrintLn("[sspi:" + marker + "] sent " + std::to_string(payload.size()) + " bytes, received " + std::to_string(plain.size()) + " plaintext bytes" + (expired ? " (context expired)" : ""));
    CloseConnection(c);
}

static void WinhttpGet(const std::string& host, int port) {
    std::wstring h(host.begin(), host.end());
    HINTERNET hSession = WinHttpOpen(L"BirriMonitor-SspiTarget/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        PrintLn("[winhttp] WinHttpOpen failed");
        return;
    }
    HINTERNET hConnect = WinHttpConnect(hSession, h.c_str(), static_cast<INTERNET_PORT>(port), 0);
    if (!hConnect) {
        PrintLn("[winhttp] WinHttpConnect failed");
        WinHttpCloseHandle(hSession);
        return;
    }
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/", nullptr, nullptr, nullptr, WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        PrintLn("[winhttp] WinHttpOpenRequest failed");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return;
    }
    DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
    BOOL ok = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, nullptr, 0, 0, 0);
    if (ok) {
        ok = WinHttpReceiveResponse(hRequest, nullptr);
    }
    DWORD status = 0;
    DWORD statusSize = sizeof(status);
    if (ok) {
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusSize, WINHTTP_NO_HEADER_INDEX);
    }
    std::string body;
    if (ok) {
        DWORD available = 0;
        while (WinHttpQueryDataAvailable(hRequest, &available) && available > 0) {
            std::vector<char> buf(available > 4096 ? 4096 : available);
            DWORD read = 0;
            if (!WinHttpReadData(hRequest, buf.data(), static_cast<DWORD>(buf.size()), &read) || read == 0) {
                break;
            }
            body.append(buf.data(), read);
        }
    }
    PrintLn("[winhttp] status " + std::to_string(status) + ", body " + std::to_string(body.size()) + " bytes");
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

static void PrintUsage() {
    printf("usage: SspiTarget.exe <host> <port> [--send] [--winhttp] [--count N] [--threads N] [--marker M] [--delay-ms N]\n");
    printf("  default : direct SSPI/Schannel HTTP request over TLS\n");
    printf("  --send  : send a non-HTTP raw payload over TLS\n");
    printf("  --winhttp: also open one HTTPS request via WinHTTP in the same process\n");
    printf("  --count N : repeat the exchange N times sequentially\n");
    printf("  --threads N : run N concurrent exchanges with distinct markers\n");
    printf("  --marker M : custom marker string\n");
    printf("  --delay-ms N : sleep N ms after credential acquire (lets DLL hooks install)\n");
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        PrintUsage();
        return 1;
    }
    std::string host;
    {
        int len = WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, nullptr, 0, nullptr, nullptr);
        std::vector<char> tmp(static_cast<size_t>(len));
        WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, tmp.data(), len, nullptr, nullptr);
        host = tmp.data();
    }
    int port = _wtoi(argv[2]);
    bool raw = false;
    bool winhttp = false;
    int count = 1;
    int threads = 1;
    std::string marker;
    for (int i = 3; i < argc; ++i) {
        if (wcscmp(argv[i], L"--send") == 0 || wcscmp(argv[i], L"/raw") == 0) {
            raw = true;
        } else if (wcscmp(argv[i], L"--winhttp") == 0) {
            winhttp = true;
        } else if (wcscmp(argv[i], L"--count") == 0 && i + 1 < argc) {
            count = _wtoi(argv[++i]);
        } else if (wcscmp(argv[i], L"--threads") == 0 && i + 1 < argc) {
            threads = _wtoi(argv[++i]);
        } else if (wcscmp(argv[i], L"--marker") == 0 && i + 1 < argc) {
            int len = WideCharToMultiByte(CP_UTF8, 0, argv[++i], -1, nullptr, 0, nullptr, nullptr);
            std::vector<char> tmp(static_cast<size_t>(len));
            WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, tmp.data(), len, nullptr, nullptr);
            marker = tmp.data();
        } else if (wcscmp(argv[i], L"--delay-ms") == 0 && i + 1 < argc) {
            g_delayMs = _wtoi(argv[++i]);
        } else {
            PrintUsage();
            return 1;
        }
    }
    if (port <= 0 || port > 65535) {
        printf("invalid port\n");
        return 1;
    }

    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    std::vector<std::thread> workers;
    for (int t = 0; t < threads; ++t) {
        std::string m = marker.empty() ? ("T" + std::to_string(t)) : marker;
        workers.emplace_back([host, port, m, raw, count]() {
            for (int i = 0; i < count; ++i) {
                SspiClientTask(host, port, m, raw);
            }
        });
    }
    for (auto& w : workers) {
        w.join();
    }
    if (winhttp) {
        WinhttpGet(host, port);
    }
    WSACleanup();
    return 0;
}
