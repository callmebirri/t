#include "IpcCommon/IpcCommon.h"

#include <windows.h>
#include <zlib.h>
#include <brotli/decode.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

static constexpr uint64_t kDisplayBodyBytes = 64 * 1024;
static constexpr uint64_t kSweepIntervalMs = 1000;

static HANDLE g_stopEvent = nullptr;
static std::vector<HANDLE> g_readerThreads;
static std::mutex g_threadsMutex;
static std::mutex g_debugMutex;
static uint64_t g_timeoutMs = 300000;

struct Transaction {
    uint64_t startMs = 0;
    uint64_t endMs = 0;
    std::string method;
    std::string url;
    std::string protocol;
    std::string reqHeaders;
    std::string reqBody;
    uint64_t reqTotalBytes = 0;
    bool reqTruncated = false;
    std::string respRawHeaders;
    std::string respBody;
    uint64_t respTotalBytes = 0;
    bool respTruncated = false;
    bool responseComplete = false;
    bool finalized = false;
    bool rendered = false;
    bool timedOut = false;
};

struct SchannelStream {
    uint64_t streamId = 0;
    uint64_t startMs = 0;
    uint64_t endMs = 0;
    std::string target;
    std::string sendData;
    std::string recvData;
    uint64_t sendBytes = 0;
    uint64_t recvBytes = 0;
    bool sendTruncated = false;
    bool recvTruncated = false;
    bool finalized = false;
    bool rendered = false;
    bool timedOut = false;
};

static std::mutex g_txMutex;
static std::map<std::pair<uint32_t, uint64_t>, Transaction> g_txs;
static std::mutex g_streamMutex;
static std::map<std::pair<uint32_t, uint64_t>, SchannelStream> g_streams;
static std::atomic<uint64_t> g_displaySeq{0};

static void WriteConsoleOut(const std::wstring& line) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written = 0;
    if (hOut != INVALID_HANDLE_VALUE && hOut != nullptr) {
        if (WriteConsoleW(hOut, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr)) {
            WriteConsoleW(hOut, L"\n", 1, &written, nullptr);
            return;
        }
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), utf8.data(), len, nullptr, nullptr);
    fwrite(utf8.data(), 1, utf8.size(), stdout);
    fwrite("\n", 1, 1, stdout);
    fflush(stdout);
}

static void WriteConsoleErr(const std::wstring& line) {
    HANDLE hErr = GetStdHandle(STD_ERROR_HANDLE);
    DWORD written = 0;
    if (hErr != INVALID_HANDLE_VALUE && hErr != nullptr) {
        if (WriteConsoleW(hErr, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr)) {
            WriteConsoleW(hErr, L"\n", 1, &written, nullptr);
            return;
        }
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), nullptr, 0, nullptr, nullptr);
    std::string utf8(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, line.c_str(), static_cast<int>(line.size()), utf8.data(), len, nullptr, nullptr);
    fwrite(utf8.data(), 1, utf8.size(), stderr);
    fwrite("\n", 1, 1, stderr);
    fflush(stderr);
}

static std::wstring ToDisplayText(const std::string& utf8) {
    int wlen = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), w.data(), wlen);
    std::wstring out;
    out.reserve(w.size());
    for (wchar_t c : w) {
        if (c == L'\n' || c == L'\t') {
            out += c;
            continue;
        }
        if (c < 0x20 || c == 0x7f) {
            wchar_t esc[8];
            swprintf_s(esc, L"\\x%02X", static_cast<unsigned>(c));
            out += esc;
        } else {
            out += c;
        }
    }
    return out;
}

static std::wstring FormatTimestamp(uint64_t ms) {
    uint64_t ft100 = ms * 10000 + 116444736000000000ULL;
    FILETIME ft;
    ft.dwLowDateTime = static_cast<DWORD>(ft100 & 0xFFFFFFFFu);
    ft.dwHighDateTime = static_cast<DWORD>(ft100 >> 32);
    FILETIME local;
    FileTimeToLocalFileTime(&ft, &local);
    SYSTEMTIME st;
    FileTimeToSystemTime(&local, &st);
    wchar_t buf[64];
    swprintf_s(buf, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::wstring FormatDuration(uint64_t elapsedMs) {
    wchar_t buf[64];
    if (elapsedMs < 1000) {
        swprintf_s(buf, L"%.2fms", static_cast<double>(elapsedMs));
    } else {
        swprintf_s(buf, L"%.2fs", static_cast<double>(elapsedMs) / 1000.0);
    }
    return buf;
}

static std::vector<std::string> SplitLines(const std::string& text) {
    std::vector<std::string> lines;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        size_t end = (eol == std::string::npos) ? text.size() : eol;
        size_t len = end - pos;
        while (len > 0 && text[pos + len - 1] == '\r') {
            --len;
        }
        lines.push_back(text.substr(pos, len));
        if (eol == std::string::npos) {
            break;
        }
        pos = eol + 1;
    }
    return lines;
}

static std::vector<std::pair<std::string, std::string>> ParseHeaders(const std::string& raw) {
    std::vector<std::pair<std::string, std::string>> headers;
    for (const std::string& line : SplitLines(raw)) {
        if (line.empty()) {
            continue;
        }
        size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string name = line.substr(0, colon);
        size_t start = colon + 1;
        while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) {
            ++start;
        }
        std::string value = line.substr(start);
        headers.emplace_back(name, value);
    }
    return headers;
}

static std::string LowerAscii(const std::string& in) {
    std::string out = in;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        if (c >= 'A' && c <= 'Z') {
            return static_cast<char>(c + ('a' - 'A'));
        }
        return static_cast<char>(c);
    });
    return out;
}

static std::string FindHeader(const std::vector<std::pair<std::string, std::string>>& headers, const std::string& name) {
    std::string target = LowerAscii(name);
    for (const auto& h : headers) {
        if (LowerAscii(h.first) == target) {
            return h.second;
        }
    }
    return {};
}

static bool InflateZlib(const std::string& in, std::string& out) {
    z_stream zs = {};
    if (inflateInit2(&zs, MAX_WBITS + 32) != Z_OK) {
        return false;
    }
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    std::vector<char> buf(64 * 1024);
    int rc = Z_OK;
    while (rc == Z_OK) {
        zs.next_out = reinterpret_cast<Bytef*>(buf.data());
        zs.avail_out = static_cast<uInt>(buf.size());
        rc = inflate(&zs, Z_NO_FLUSH);
        out.append(buf.data(), buf.size() - zs.avail_out);
        if (rc == Z_STREAM_END) {
            break;
        }
        if (rc != Z_OK && rc != Z_BUF_ERROR) {
            inflateEnd(&zs);
            return false;
        }
        if (zs.avail_in == 0 && zs.avail_out != 0) {
            break;
        }
    }
    inflateEnd(&zs);
    return true;
}

static bool BrotliDecode(const std::string& in, std::string& out) {
    size_t outSize = in.size() * 4 + 1024;
    std::vector<uint8_t> buf(outSize);
    if (BrotliDecoderDecompress(in.size(), reinterpret_cast<const uint8_t*>(in.data()), &outSize, buf.data()) == BROTLI_DECODER_RESULT_SUCCESS) {
        out.assign(reinterpret_cast<const char*>(buf.data()), outSize);
        return true;
    }
    BrotliDecoderState* st = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    if (!st) {
        return false;
    }
    const uint8_t* nextIn = reinterpret_cast<const uint8_t*>(in.data());
    size_t availIn = in.size();
    std::vector<uint8_t> obuf(64 * 1024);
    bool ok = false;
    while (true) {
        size_t availOut = obuf.size();
        uint8_t* nextOut = obuf.data();
        BrotliDecoderResult r = BrotliDecoderDecompressStream(st, &availIn, &nextIn, &availOut, &nextOut, nullptr);
        out.append(reinterpret_cast<const char*>(obuf.data()), obuf.size() - availOut);
        if (r == BROTLI_DECODER_RESULT_SUCCESS) {
            ok = true;
            break;
        }
        if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && availIn == 0) {
            ok = true;
            break;
        }
        if (r != BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) {
            break;
        }
    }
    BrotliDecoderDestroyInstance(st);
    return ok;
}

static bool Dechunk(const std::string& in, std::string& out) {
    size_t pos = 0;
    while (pos < in.size()) {
        size_t lineEnd = in.find("\r\n", pos);
        if (lineEnd == std::string::npos) {
            return false;
        }
        std::string sizeStr = in.substr(pos, lineEnd - pos);
        size_t ext = sizeStr.find(';');
        if (ext != std::string::npos) {
            sizeStr = sizeStr.substr(0, ext);
        }
        char* endPtr = nullptr;
        unsigned long chunkSize = std::strtoul(sizeStr.c_str(), &endPtr, 16);
        if (endPtr == sizeStr.c_str()) {
            return false;
        }
        if (chunkSize == 0) {
            return true;
        }
        pos = lineEnd + 2;
        if (pos + chunkSize + 2 > in.size()) {
            return false;
        }
        out.append(in, pos, chunkSize);
        pos += chunkSize + 2;
    }
    return false;
}

struct DecodedBody {
    std::string data;
    bool decodeFailed = false;
};

static DecodedBody DecodeBody(const std::string& raw, const std::vector<std::pair<std::string, std::string>>& headers) {
    DecodedBody result;
    result.data = raw;
    std::string transfer = LowerAscii(FindHeader(headers, "Transfer-Encoding"));
    if (transfer.find("chunked") != std::string::npos) {
        std::string dechunked;
        if (Dechunk(raw, dechunked)) {
            result.data = dechunked;
        }
    }
    std::string encoding = LowerAscii(FindHeader(headers, "Content-Encoding"));
    if (encoding.empty()) {
        return result;
    }
    std::string decoded;
    bool ok = false;
    if (encoding.find("gzip") != std::string::npos || encoding.find("deflate") != std::string::npos) {
        ok = InflateZlib(result.data, decoded);
    } else if (encoding.find("br") != std::string::npos) {
        ok = BrotliDecode(result.data, decoded);
    }
    if (ok) {
        result.data = decoded;
    } else {
        result.decodeFailed = true;
    }
    return result;
}

static std::wstring PadRight(const std::wstring& s, size_t width) {
    std::wstring out = s;
    if (out.size() < width) {
        out.append(width - out.size(), L' ');
    }
    return out;
}

static void RenderHeaderLines(const std::vector<std::pair<std::string, std::string>>& headers, std::vector<std::wstring>& lines) {
    if (headers.empty()) {
        lines.push_back(L"|     (none)");
        return;
    }
    size_t maxName = 0;
    std::vector<std::pair<std::wstring, std::wstring>> wide;
    for (const auto& h : headers) {
        std::wstring name = ToDisplayText(h.first);
        std::wstring value = ToDisplayText(h.second);
        maxName = std::max(maxName, name.size());
        wide.emplace_back(name, value);
    }
    for (const auto& h : wide) {
        lines.push_back(L"|     " + PadRight(h.first, maxName) + L"  : " + h.second);
    }
}

static void RenderBodyLines(const std::string& body, bool truncated, const std::wstring& extraNote, std::vector<std::wstring>& lines) {
    std::string display = body;
    bool cut = truncated;
    if (display.size() > kDisplayBodyBytes) {
        display = display.substr(0, static_cast<size_t>(kDisplayBodyBytes));
        cut = true;
    }
    for (const std::string& line : SplitLines(display)) {
        lines.push_back(L"|     " + ToDisplayText(line));
    }
    if (cut) {
        lines.push_back(L"|     ... (truncated, full in debug log)");
    }
    if (!extraNote.empty()) {
        lines.push_back(L"|     " + extraNote);
    }
}

static std::wstring HexPreview32(const std::string& data) {
    size_t n = std::min<size_t>(32, data.size());
    std::wstring hex;
    std::wstring ascii;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = static_cast<unsigned char>(data[i]);
        wchar_t b[4];
        swprintf_s(b, L"%02X ", c);
        hex += b;
        ascii += (c >= 0x20 && c < 0x7f) ? static_cast<wchar_t>(c) : L'.';
    }
    return hex + L"|" + ascii + L"|";
}

static void RenderTransaction(const Transaction& tx, uint64_t seq) {
    std::vector<std::wstring> lines;
    lines.push_back(L"+----[ TRANSACTION #" + std::to_wstring(seq) + L" ]----+ " + FormatTimestamp(tx.startMs));

    lines.push_back(L"| REQUEST");
    lines.push_back(L"|   Method  : " + ToDisplayText(tx.method));
    lines.push_back(L"|   URL     : " + ToDisplayText(tx.url));
    lines.push_back(L"|   Protocol: " + ToDisplayText(tx.protocol));
    lines.push_back(L"|   Headers :");
    RenderHeaderLines(ParseHeaders(tx.reqHeaders), lines);
    if (tx.reqBody.empty()) {
        lines.push_back(L"|   Body    : (none)");
    } else {
        lines.push_back(L"|   Body    :");
        std::wstring note;
        if (tx.reqTruncated) {
            note = L"(truncated at source, total " + std::to_wstring(tx.reqTotalBytes) + L" bytes)";
        }
        RenderBodyLines(tx.reqBody, tx.reqTruncated, note, lines);
    }

    lines.push_back(L"|");
    lines.push_back(L"| RESPONSE");
    if (tx.respRawHeaders.empty() && !tx.responseComplete && !tx.finalized) {
        lines.push_back(L"|   Status  : (pending)");
        lines.push_back(L"|");
        lines.push_back(L"+------------------------------------------+");
        for (const auto& l : lines) {
            WriteConsoleOut(l);
        }
        return;
    }

    std::string statusText;
    std::string respProtocol;
    std::vector<std::pair<std::string, std::string>> respHeaders;
    if (!tx.respRawHeaders.empty()) {
        std::vector<std::string> headLines = SplitLines(tx.respRawHeaders);
        if (!headLines.empty()) {
            std::string first = headLines[0];
            size_t sp = first.find(' ');
            if (sp != std::string::npos && first.compare(0, 5, "HTTP/") == 0) {
                respProtocol = first.substr(0, sp);
                statusText = first.substr(sp + 1);
            } else {
                statusText = first;
            }
        }
        std::string rest;
        for (size_t i = 1; i < headLines.size(); ++i) {
            if (i > 1) {
                rest += "\n";
            }
            rest += headLines[i];
        }
        respHeaders = ParseHeaders(rest);
    }

    if (statusText.empty()) {
        if (tx.timedOut) {
            lines.push_back(L"|   Status  : (no response - timed out or connection lost)");
        } else {
            lines.push_back(L"|   Status  : (no response)");
        }
    } else {
        lines.push_back(L"|   Status  : " + ToDisplayText(statusText));
        lines.push_back(L"|   Protocol: " + ToDisplayText(respProtocol.empty() ? tx.protocol : respProtocol));
        lines.push_back(L"|   Headers :");
        RenderHeaderLines(respHeaders, lines);
        if (tx.respBody.empty()) {
            lines.push_back(L"|   Body    : (none)");
        } else {
            DecodedBody decoded = DecodeBody(tx.respBody, respHeaders);
            lines.push_back(L"|   Body    :");
            std::wstring note;
            if (tx.respTruncated) {
                note = L"(truncated at source, total " + std::to_wstring(tx.respTotalBytes) + L" bytes)";
            }
            if (decoded.decodeFailed) {
                if (!note.empty()) {
                    note += L" ";
                }
                note += L"(decompression failed, showing raw)";
            }
            RenderBodyLines(decoded.data, tx.respTruncated, note, lines);
        }
    }

    std::wstring bottom = L"+------------------------------------------+ ";
    if (tx.endMs >= tx.startMs) {
        bottom += FormatDuration(tx.endMs - tx.startMs);
    } else {
        bottom += L"(pending)";
    }
    lines.push_back(bottom);
    for (const auto& l : lines) {
        WriteConsoleOut(l);
    }
}

static void RenderSchannel(const SchannelStream& st, uint64_t seq) {
    std::vector<std::wstring> lines;
    lines.push_back(L"+----[ SCHANNEL #" + std::to_wstring(seq) + L" ]----+ " + FormatTimestamp(st.startMs));
    lines.push_back(L"| REQUEST (est.)");
    lines.push_back(L"|   Stream  : 0x" + std::to_wstring(st.streamId));
    std::wstring target = st.target.empty() ? L"(schannel-tls)" : ToDisplayText(st.target);
    lines.push_back(L"|   Target  : " + target);
    if (st.sendData.empty()) {
        lines.push_back(L"|   Data    : (none)");
    } else {
        lines.push_back(L"|   Data    :");
        std::wstring note;
        if (st.sendTruncated) {
            note = L"(truncated at source, total " + std::to_wstring(st.sendBytes) + L" bytes)";
        }
        RenderBodyLines(st.sendData, st.sendTruncated, note, lines);
    }

    lines.push_back(L"|");
    lines.push_back(L"| RESPONSE (parsed)");
    if (st.recvData.empty()) {
        if (st.timedOut) {
            lines.push_back(L"|   Status  : (no response - timed out or connection lost)");
        } else {
            lines.push_back(L"|   Status  : (none)");
        }
    } else {
        size_t sep = st.recvData.find("\r\n\r\n");
        size_t bodyStart = st.recvData.size();
        if (sep != std::string::npos) {
            bodyStart = sep + 4;
        } else {
            sep = st.recvData.find("\n\n");
            if (sep != std::string::npos) {
                bodyStart = sep + 2;
            }
        }
        std::string head = st.recvData.substr(0, bodyStart == st.recvData.size() ? bodyStart : bodyStart - 4);
        std::string body = (bodyStart < st.recvData.size()) ? st.recvData.substr(bodyStart) : std::string();
        std::vector<std::string> headLines = SplitLines(head);
        bool isHttp = !headLines.empty() && headLines[0].compare(0, 5, "HTTP/") == 0;
        if (!isHttp) {
            lines.push_back(L"|   Note    : (non-HTTP schannel stream)");
            lines.push_back(L"|   Hex     : " + HexPreview32(st.recvData));
        } else {
            std::string first = headLines[0];
            size_t sp = first.find(' ');
            std::string protocol = (sp != std::string::npos) ? first.substr(0, sp) : first;
            std::string status = (sp != std::string::npos) ? first.substr(sp + 1) : std::string();
            lines.push_back(L"|   Status  : " + ToDisplayText(status));
            lines.push_back(L"|   Protocol: " + ToDisplayText(protocol));
            std::string rest;
            for (size_t i = 1; i < headLines.size(); ++i) {
                if (i > 1) {
                    rest += "\n";
                }
                rest += headLines[i];
            }
            auto headers = ParseHeaders(rest);
            lines.push_back(L"|   Headers :");
            RenderHeaderLines(headers, lines);
            if (body.empty()) {
                lines.push_back(L"|   Body    : (none)");
            } else {
                DecodedBody decoded = DecodeBody(body, headers);
                lines.push_back(L"|   Body    :");
                std::wstring note;
                if (st.recvTruncated) {
                    note = L"(truncated at source, total " + std::to_wstring(st.recvBytes) + L" bytes)";
                }
                if (decoded.decodeFailed) {
                    if (!note.empty()) {
                        note += L" ";
                    }
                    note += L"(decompression failed, showing raw)";
                }
                RenderBodyLines(decoded.data, st.recvTruncated, note, lines);
            }
        }
    }

    std::wstring bottom = L"+------------------------------------------+ ";
    if (st.endMs >= st.startMs) {
        bottom += FormatDuration(st.endMs - st.startMs);
    } else {
        bottom += L"(pending)";
    }
    lines.push_back(bottom);
    for (const auto& l : lines) {
        WriteConsoleOut(l);
    }
}

static void TryRenderTx(const std::pair<uint32_t, uint64_t>& key, Transaction tx) {
    uint64_t seq = g_displaySeq.fetch_add(1) + 1;
    RenderTransaction(tx, seq);
    std::lock_guard<std::mutex> lock(g_txMutex);
    g_txs.erase(key);
}

static void TryRenderStream(const std::pair<uint32_t, uint64_t>& key, SchannelStream st) {
    uint64_t seq = g_displaySeq.fetch_add(1) + 1;
    RenderSchannel(st, seq);
    std::lock_guard<std::mutex> lock(g_streamMutex);
    g_streams.erase(key);
}

static void ApplyTransactionStart(const ipc::Message& msg) {
    ipc::PayloadReader r(msg.payload.data(), msg.payload.size());
    Transaction tx;
    tx.startMs = msg.header.timestampMs;
    tx.method = r.Str();
    tx.url = r.Str();
    tx.protocol = r.Str();
    tx.reqHeaders = r.Str();
    r.U32();
    if (!r.Ok()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_txMutex);
    g_txs[{msg.header.pid, msg.header.requestId}] = std::move(tx);
}

static void ApplyTransactionBody(const ipc::Message& msg) {
    ipc::PayloadReader r(msg.payload.data(), msg.payload.size());
    uint8_t direction = r.U8();
    uint64_t total = r.U64();
    uint8_t truncated = r.U8();
    std::string data = r.BytesN();
    if (!r.Ok()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_txMutex);
    auto it = g_txs.find({msg.header.pid, msg.header.requestId});
    if (it == g_txs.end() || it->second.finalized) {
        return;
    }
    Transaction& tx = it->second;
    if (direction == ipc::kBodyRequest) {
        tx.reqTotalBytes = total;
        if (!truncated && tx.reqBody.size() < ipc::kBodyLimitBytes) {
            size_t room = ipc::kBodyLimitBytes - tx.reqBody.size();
            tx.reqBody.append(data, 0, std::min(room, data.size()));
        }
    } else {
        tx.respTotalBytes = total;
        if (!truncated && tx.respBody.size() < ipc::kBodyLimitBytes) {
            size_t room = ipc::kBodyLimitBytes - tx.respBody.size();
            tx.respBody.append(data, 0, std::min(room, data.size()));
        }
    }
}

static void ApplyResponseHeaders(const ipc::Message& msg) {
    ipc::PayloadReader r(msg.payload.data(), msg.payload.size());
    std::string raw = r.Str();
    if (!r.Ok()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_txMutex);
    auto it = g_txs.find({msg.header.pid, msg.header.requestId});
    if (it != g_txs.end()) {
        it->second.respRawHeaders = std::move(raw);
    }
}

static void ApplyResponseEnd(const ipc::Message& msg) {
    Transaction tx;
    std::pair<uint32_t, uint64_t> key{msg.header.pid, msg.header.requestId};
    bool ready = false;
    {
        std::lock_guard<std::mutex> lock(g_txMutex);
        auto it = g_txs.find(key);
        if (it == g_txs.end() || it->second.rendered || it->second.finalized) {
            return;
        }
        it->second.responseComplete = true;
        it->second.endMs = msg.header.timestampMs;
        it->second.finalized = true;
        tx = std::move(it->second);
        ready = true;
    }
    if (ready) {
        TryRenderTx(key, std::move(tx));
    }
}

static void ApplyTransactionEnd(const ipc::Message& msg) {
    ipc::PayloadReader r(msg.payload.data(), msg.payload.size());
    uint32_t flags = r.U32();
    uint64_t reqTotal = r.U64();
    uint64_t respTotal = r.U64();
    if (!r.Ok()) {
        return;
    }
    Transaction tx;
    std::pair<uint32_t, uint64_t> key{msg.header.pid, msg.header.requestId};
    bool ready = false;
    {
        std::lock_guard<std::mutex> lock(g_txMutex);
        auto it = g_txs.find(key);
        if (it == g_txs.end() || it->second.rendered) {
            return;
        }
        it->second.reqTruncated = it->second.reqTruncated || (flags & ipc::kTransactionRequestTruncated) != 0;
        it->second.respTruncated = it->second.respTruncated || (flags & ipc::kTransactionResponseTruncated) != 0;
        it->second.reqTotalBytes = std::max(it->second.reqTotalBytes, reqTotal);
        it->second.respTotalBytes = std::max(it->second.respTotalBytes, respTotal);
        it->second.endMs = msg.header.timestampMs;
        it->second.finalized = true;
        tx = std::move(it->second);
        ready = true;
    }
    if (ready) {
        TryRenderTx(key, std::move(tx));
    }
}

static void ApplySchannelHandshake(const ipc::Message& msg) {
    ipc::PayloadReader r(msg.payload.data(), msg.payload.size());
    std::string target = r.Str();
    if (!r.Ok()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_streamMutex);
    SchannelStream st;
    st.streamId = msg.header.requestId;
    st.startMs = msg.header.timestampMs;
    st.target = std::move(target);
    g_streams[{msg.header.pid, msg.header.requestId}] = std::move(st);
}

static void ApplySchannelData(const ipc::Message& msg, bool isSend) {
    ipc::PayloadReader r(msg.payload.data(), msg.payload.size());
    std::string data = r.BytesN();
    if (!r.Ok()) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_streamMutex);
    auto it = g_streams.find({msg.header.pid, msg.header.requestId});
    if (it == g_streams.end() || it->second.finalized) {
        return;
    }
    SchannelStream& st = it->second;
    if (isSend) {
        st.sendBytes += data.size();
        if (st.sendData.size() < ipc::kBodyLimitBytes) {
            size_t room = ipc::kBodyLimitBytes - st.sendData.size();
            st.sendData.append(data, 0, std::min(room, data.size()));
        } else {
            st.sendTruncated = true;
        }
    } else {
        st.recvBytes += data.size();
        if (st.recvData.size() < ipc::kBodyLimitBytes) {
            size_t room = ipc::kBodyLimitBytes - st.recvData.size();
            st.recvData.append(data, 0, std::min(room, data.size()));
        } else {
            st.recvTruncated = true;
        }
    }
}

static void ApplySchannelStreamEnd(const ipc::Message& msg) {
    SchannelStream st;
    std::pair<uint32_t, uint64_t> key{msg.header.pid, msg.header.requestId};
    bool ready = false;
    {
        std::lock_guard<std::mutex> lock(g_streamMutex);
        auto it = g_streams.find(key);
        if (it == g_streams.end() || it->second.rendered) {
            return;
        }
        it->second.endMs = msg.header.timestampMs;
        it->second.finalized = true;
        st = std::move(it->second);
        ready = true;
    }
    if (ready) {
        TryRenderStream(key, std::move(st));
    }
}

static void Dispatch(const ipc::Message& msg) {
    std::lock_guard<std::mutex> dbgLock(g_debugMutex);
    WriteConsoleErr(L"[dbg] type=" + std::to_wstring(msg.header.type) + L" id=" + std::to_wstring(msg.header.requestId) + L" pid=" + std::to_wstring(msg.header.pid));
    switch (static_cast<ipc::MsgType>(msg.header.type)) {
        case ipc::MsgType::TransactionStart:
            ApplyTransactionStart(msg);
            break;
        case ipc::MsgType::TransactionBody:
            ApplyTransactionBody(msg);
            break;
        case ipc::MsgType::ResponseHeaders:
            ApplyResponseHeaders(msg);
            break;
        case ipc::MsgType::ResponseEnd:
            ApplyResponseEnd(msg);
            break;
        case ipc::MsgType::TransactionEnd:
            ApplyTransactionEnd(msg);
            break;
        case ipc::MsgType::SchannelHandshake:
            ApplySchannelHandshake(msg);
            break;
        case ipc::MsgType::SchannelDataSend:
            ApplySchannelData(msg, true);
            break;
        case ipc::MsgType::SchannelDataRecv:
            ApplySchannelData(msg, false);
            break;
        case ipc::MsgType::SchannelStreamEnd:
            ApplySchannelStreamEnd(msg);
            break;
        default:
            break;
    }
}

static void FeedBytes(std::vector<uint8_t>& accum, const uint8_t* data, size_t n) {
    accum.insert(accum.end(), data, data + n);
    size_t pos = 0;
    while (accum.size() - pos >= sizeof(ipc::WireHeader)) {
        ipc::WireHeader hdr;
        std::memcpy(&hdr, accum.data() + pos, sizeof(hdr));
        if (hdr.magic != ipc::kMagic) {
            ++pos;
            continue;
        }
        if (hdr.version != ipc::kVersion || hdr.payloadLength > ipc::kMaxMessageSize) {
            ++pos;
            continue;
        }
        size_t total = sizeof(ipc::WireHeader) + hdr.payloadLength;
        if (accum.size() - pos < total) {
            break;
        }
        ipc::Message msg;
        if (ipc::DeserializeMessage(accum.data() + pos, total, msg)) {
            Dispatch(msg);
        }
        pos += total;
    }
    if (pos > 0) {
        accum.erase(accum.begin(), accum.begin() + static_cast<std::ptrdiff_t>(pos));
    }
}

static DWORD WINAPI ReaderThreadMain(LPVOID param) {
    HANDLE hPipe = static_cast<HANDLE>(param);
    std::vector<uint8_t> accum;
    std::vector<uint8_t> chunk(64 * 1024);
    HANDLE readEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!readEvent) {
        CloseHandle(hPipe);
        return 1;
    }
    OVERLAPPED ov = {};
    ov.hEvent = readEvent;
    for (;;) {
        ResetEvent(readEvent);
        ov.Offset = 0;
        ov.OffsetHigh = 0;
        BOOL ok = ReadFile(hPipe, chunk.data(), static_cast<DWORD>(chunk.size()), nullptr, &ov);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        DWORD got = 0;
        if (!ok && err == ERROR_IO_PENDING) {
            HANDLE waiters[2] = {g_stopEvent, readEvent};
            DWORD w = WaitForMultipleObjects(2, waiters, FALSE, INFINITE);
            if (w == WAIT_OBJECT_0) {
                CancelIoEx(hPipe, &ov);
                WaitForSingleObject(readEvent, INFINITE);
                break;
            }
            ok = GetOverlappedResult(hPipe, &ov, &got, FALSE);
        } else if (ok) {
            ok = GetOverlappedResult(hPipe, &ov, &got, FALSE);
        }
        if (!ok) {
            break;
        }
        if (got == 0) {
            break;
        }
        FeedBytes(accum, chunk.data(), got);
    }
    CloseHandle(readEvent);
    CloseHandle(hPipe);
    return 0;
}

static void FlushPending() {
    std::vector<std::pair<std::pair<uint32_t, uint64_t>, Transaction>> txs;
    {
        std::lock_guard<std::mutex> lock(g_txMutex);
        for (auto& kv : g_txs) {
            txs.emplace_back(kv.first, std::move(kv.second));
        }
        g_txs.clear();
    }
    for (auto& kv : txs) {
        TryRenderTx(kv.first, std::move(kv.second));
    }
    std::vector<std::pair<std::pair<uint32_t, uint64_t>, SchannelStream>> streams;
    {
        std::lock_guard<std::mutex> lock(g_streamMutex);
        for (auto& kv : g_streams) {
            streams.emplace_back(kv.first, std::move(kv.second));
        }
        g_streams.clear();
    }
    for (auto& kv : streams) {
        TryRenderStream(kv.first, std::move(kv.second));
    }
}

static DWORD WINAPI SweeperThreadMain(LPVOID) {
    for (;;) {
        if (WaitForSingleObject(g_stopEvent, static_cast<DWORD>(kSweepIntervalMs)) == WAIT_OBJECT_0) {
            break;
        }
        uint64_t now = ipc::NowMs();
        std::vector<std::pair<std::pair<uint32_t, uint64_t>, Transaction>> timedTxs;
        {
            std::lock_guard<std::mutex> lock(g_txMutex);
            for (auto& kv : g_txs) {
                if (!kv.second.finalized && now - kv.second.startMs > g_timeoutMs) {
                    kv.second.timedOut = true;
                    kv.second.finalized = true;
                    kv.second.endMs = now;
                    timedTxs.emplace_back(kv.first, std::move(kv.second));
                }
            }
            for (const auto& kv : timedTxs) {
                g_txs.erase(kv.first);
            }
        }
        for (auto& kv : timedTxs) {
            TryRenderTx(kv.first, std::move(kv.second));
        }
        std::vector<std::pair<std::pair<uint32_t, uint64_t>, SchannelStream>> timedStreams;
        {
            std::lock_guard<std::mutex> lock(g_streamMutex);
            for (auto& kv : g_streams) {
                if (!kv.second.finalized && now - kv.second.startMs > g_timeoutMs) {
                    kv.second.timedOut = true;
                    kv.second.finalized = true;
                    kv.second.endMs = now;
                    timedStreams.emplace_back(kv.first, std::move(kv.second));
                }
            }
            for (const auto& kv : timedStreams) {
                g_streams.erase(kv.first);
            }
        }
        for (auto& kv : timedStreams) {
            TryRenderStream(kv.first, std::move(kv.second));
        }
    }
    return 0;
}

static BOOL WINAPI CtrlHandler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        SetEvent(g_stopEvent);
        return TRUE;
    }
    return FALSE;
}

static void PrintUsage() {
    WriteConsoleErr(L"usage: BirriLogger.exe [--timeout <seconds>]");
}

static int ParseArgs(int argc, wchar_t** argv) {
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--timeout") == 0 && i + 1 < argc) {
            wchar_t* end = nullptr;
            unsigned long secs = wcstoul(argv[++i], &end, 10);
            if (end != argv[i] && secs > 0) {
                g_timeoutMs = static_cast<uint64_t>(secs) * 1000;
            }
        } else {
            PrintUsage();
            return 1;
        }
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (ParseArgs(argc, argv) != 0) {
        return 1;
    }
    HANDLE single = CreateMutexW(nullptr, TRUE, ipc::kLoggerMutexName);
    if (!single || GetLastError() == ERROR_ALREADY_EXISTS) {
        WriteConsoleErr(L"another BirriLogger instance is already running");
        if (single) {
            CloseHandle(single);
        }
        return 1;
    }
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        WriteConsoleErr(L"failed to create stop event");
        return 1;
    }
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    WriteConsoleErr(L"BirriLogger: listening on " + std::wstring(ipc::kPipeName) + L" (timeout " + std::to_wstring(g_timeoutMs / 1000) + L"s, Ctrl+C to stop)");

    HANDLE sweeper = CreateThread(nullptr, 0, SweeperThreadMain, nullptr, 0, nullptr);
    if (!sweeper) {
        WriteConsoleErr(L"failed to start sweeper thread");
    }

    for (;;) {
        HANDLE hPipe = CreateNamedPipeW(ipc::kPipeName,
                                        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                        PIPE_UNLIMITED_INSTANCES,
                                        65536,
                                        65536,
                                        0,
                                        nullptr);
        if (hPipe == INVALID_HANDLE_VALUE) {
            WriteConsoleErr(L"CreateNamedPipeW failed: " + std::to_wstring(GetLastError()));
            break;
        }
        HANDLE connectEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!connectEvent) {
            CloseHandle(hPipe);
            break;
        }
        OVERLAPPED ov = {};
        ov.hEvent = connectEvent;
        BOOL ok = ConnectNamedPipe(hPipe, &ov);
        DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        bool connected = false;
        if (!ok && err == ERROR_IO_PENDING) {
            HANDLE waiters[2] = {g_stopEvent, connectEvent};
            DWORD w = WaitForMultipleObjects(2, waiters, FALSE, INFINITE);
            if (w == WAIT_OBJECT_0) {
                CancelIoEx(hPipe, &ov);
                WaitForSingleObject(connectEvent, INFINITE);
                CloseHandle(connectEvent);
                CloseHandle(hPipe);
                break;
            }
            connected = true;
        } else if (err == ERROR_PIPE_CONNECTED) {
            connected = true;
        }
        CloseHandle(connectEvent);
        if (!connected) {
            CloseHandle(hPipe);
            continue;
        }
        HANDLE reader = CreateThread(nullptr, 0, ReaderThreadMain, hPipe, 0, nullptr);
        if (!reader) {
            CloseHandle(hPipe);
            continue;
        }
        std::lock_guard<std::mutex> lock(g_threadsMutex);
        g_readerThreads.push_back(reader);
    }

    SetEvent(g_stopEvent);
    if (sweeper) {
        WaitForSingleObject(sweeper, 2000);
        CloseHandle(sweeper);
    }
    FlushPending();
    std::vector<HANDLE> threads;
    {
        std::lock_guard<std::mutex> lock(g_threadsMutex);
        threads = g_readerThreads;
    }
    for (HANDLE t : threads) {
        WaitForSingleObject(t, 3000);
        CloseHandle(t);
    }
    CloseHandle(g_stopEvent);
    CloseHandle(single);
    return 0;
}
