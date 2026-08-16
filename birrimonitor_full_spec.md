# BirriMonitor — Đặc Tả Kỹ Thuật Đầy Đủ (A-Z)

## 0. Vai trò & mục tiêu

Xây dựng BirriMonitor — network traffic monitor dạng DLL injection cho 1 tiến trình Windows x64 cụ thể (single target), hiển thị traffic WinHTTP dưới dạng plaintext (method, full URL, headers, body) theo phong cách gọn như `curl -i`. Không dùng kiến trúc MITM-proxy — capture bằng cách hook trực tiếp API bên trong tiến trình target, tại đúng điểm dữ liệu còn ở dạng plaintext.

## 1. Phạm vi & ràng buộc

- Kiến trúc: x64 duy nhất.
- Target: 1 process cụ thể mà người vận hành sở hữu hoặc có quyền kiểm thử.
- Scope hook chính thức: **WinHTTP** (`winhttp.dll`). Các thư viện khác (Winsock, WinINet, Schannel, OpenSSL, BCrypt, mbedTLS, QUIC/HTTP3) thuộc phạm vi mở rộng — xem mục 15, không triển khai trong bản này trừ khi có yêu cầu riêng.
- Không spawn `cmd.exe`/process con để ghi log.
- Không cần tự động bypass custom application-level pinning ngoài chuẩn hệ thống.

## 2. Môi trường build & test

- Compiler: MSVC. Mở Developer Shell bằng:
  ```
  & "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\Launch-VsDevShell.ps1"
  ```
- Platform toolset: `v143`, đồng bộ trên toàn bộ `.vcxproj` và build CMake của các thư viện third-party (mục 2.1).
- Build config bắt buộc: `/W4` + `/WX` (treat warnings as errors) trên cả 3 project chính (`BirriMonitor.dll`, `BirriLauncher.exe`, `BirriLogger.exe`) — build phải sạch 0 warning trước khi coi là hoàn thành. Third-party code (mục 2.1) build theo flag riêng của chính nó, **không** áp `/W4 /WX` lên source của third-party (không kiểm soát được warning trong code người khác) — chỉ áp lên code của BirriMonitor tự viết.
- Thêm version resource cho DLL (product name, version, description) — không để trống.

### 2.1 Third-party dependencies (đóng gói sẵn, không clone lúc build)

Toàn bộ thư viện ngoài được **vendor sẵn** vào thư mục `third_party/` ngay trong repo (dưới dạng git submodule ghim commit cụ thể, hoặc copy source trực tiếp — chọn 1 trong 2 cách nhất quán cho cả 3 lib), **không** dùng script tự động clone lúc build (`git clone` trong CI/build step). Lý do: build phải chạy được offline/reproducible, không phụ thuộc GitHub uptime tại thời điểm build, và tránh trường hợp upstream đổi code đột ngột giữa 2 lần build làm behavior lệch mà không ai biết.

| Thư viện | Repo (hardcode) | Dùng cho | Cách vendor |
|---|---|---|---|
| MinHook | https://github.com/TsudaKageyu/minhook | Hook engine chính (mục 4) | `third_party/minhook/`, build bằng CMake của chính lib kèm `-T v143` |
| zlib | https://github.com/madler/zlib | Giải nén `Content-Encoding: gzip/deflate` (mục 11) | `third_party/zlib/`, build bằng CMake của chính lib |
| brotli | https://github.com/google/brotli | Giải nén `Content-Encoding: br` (mục 11) | `third_party/brotli/`, build bằng CMake của chính lib |

**Quy tắc vendor:**
- Ghim đúng 1 tag/commit cụ thể cho mỗi lib tại thời điểm implement, ghi rõ commit hash/tag trong `third_party/VERSIONS.md` (hoặc tương đương) — không kéo `HEAD`/`main` để tránh build không reproducible giữa các lần checkout khác nhau.
- Nếu dùng git submodule: `.gitmodules` trỏ đúng 3 URL trên, CI checkout kèm `--recurse-submodules`, không cần internet access thêm ngoài lần checkout ban đầu của chính repo.
- Nếu copy source trực tiếp (không submodule): giữ nguyên cấu trúc thư mục gốc của từng lib trong `third_party/<lib>/`, không sửa source trừ khi bắt buộc để build trên MSVC/v143 (nếu sửa, ghi chú rõ diff và lý do trong `third_party/VERSIONS.md`).
- Build output (`.lib`) của 3 thư viện này được cache trong CI theo đúng cơ chế đã có ở mục 13 (mở rộng phạm vi cache từ chỉ MinHook sang cả zlib/brotli), cache key tính theo hash của toàn bộ `third_party/` (không chỉ riêng config build) để tự invalidate khi source hoặc version ghim thay đổi.
- Không tải lib ở dạng prebuilt binary (`.dll`/`.lib` tải sẵn từ nguồn thứ 3, NuGet, vcpkg online...) — chỉ build từ source đã vendor, đảm bảo toàn bộ chain build nằm trong tầm kiểm soát/audit được.

## 3. Kiến trúc tổng thể

| Module | Loại | Vai trò |
|---|---|---|
| `BirriMonitor.dll` | DLL inject được vào target | Hook WinHTTP APIs, trích xuất dữ liệu, gửi qua IPC |
| `BirriLauncher.exe` | EXE | Khởi động/inject DLL vào target, quản lý handshake |
| `BirriLogger.exe` | EXE | Named pipe server, nhận dữ liệu qua IPC, hiển thị traffic |
| `HookEngine` | Shared static lib | Điều phối cài hook, quản lý state, gửi message qua IPC |
| `IpcClient` | Shared static lib | Named pipe client phía DLL, chạy trên background IO thread riêng |
| `IpcCommon` | Shared header | Struct giao thức IPC, hằng số, serialize/deserialize, timestamp |

**Nguyên tắc phân tách trách nhiệm:**
- `BirriMonitor.dll` (chạy trong tiến trình target) chỉ làm 2 việc: đặt hook, trích xuất buffer + gửi ngay qua IPC. Không parse HTTP, không giải nén, không format tại đây — giữ code path trong hook càng ngắn/nhẹ càng tốt.
- `BirriLogger.exe` (process độc lập) chịu trách nhiệm: nhận dữ liệu thô, ghép nối theo request, giải nén nếu cần, format và hiển thị.

## 4. Chọn thư viện hook

- Mặc định dùng **MinHook** (vendor sẵn tại `third_party/minhook/`, xem mục 2.1) cho toàn bộ hook point.
- Nếu trong quá trình implement gặp 1 API cụ thể mà MinHook không hook sạch được (trampoline lỗi, hàm quá ngắn để đặt jump...), được phép dùng **Detours** riêng cho điểm đó — không bắt buộc toàn project dùng chung 1 lib, miễn đảm bảo không xung đột symbol/trampoline giữa 2 lib nếu dùng chung trong cùng 1 binary. Ghi rõ lý do nếu phải dùng Detours cho 1 hook cụ thể. Nếu cần Detours, cũng vendor theo đúng nguyên tắc mục 2.1 (không tự clone lúc build).

## 5. Danh sách hook targets (WinHTTP — bắt buộc đầy đủ, không được thiếu bất kỳ hàm nào dưới đây)

| Hàm | Mục đích | Ghi chú bắt buộc |
|---|---|---|
| `WinHttpConnect` | Lấy host + port của kết nối | **Bắt buộc** — nếu thiếu hàm này, sẽ không thể dựng full URL đúng (chỉ có path, thiếu host). Lưu map `hConnect → (host, port)`. |
| `WinHttpOpenRequest` | Lấy verb, object name (path+query), cờ `WINHTTP_FLAG_SECURE` (xác định http/https) | Map `hRequest → hConnect`, kết hợp với map ở trên để dựng `scheme://host:port/path?query` đầy đủ. Gán 1 unique ID nội bộ cho mỗi `hRequest` (không dùng thẳng giá trị `HINTERNET` làm ID — xem mục 9). |
| `WinHttpAddRequestHeaders` | Header được thêm sau khi mở request | Bắt buộc hook nếu app dùng — nhiều app set header qua đường này thay vì gộp hết vào `WinHttpSendRequest`. |
| `WinHttpSendRequest` | Lấy header khởi tạo (`lpszHeaders`) + body nếu gửi trong 1 lần (`lpOptional`/`dwOptionalLength`) | Body ở tham số này **không đảm bảo là toàn bộ** — xem `WinHttpWriteData`. |
| `WinHttpWriteData` | Phần body còn lại khi app gửi theo nhiều lần gọi (POST/PUT lớn) | **Bắt buộc hook** — nếu bỏ qua hàm này sẽ mất phần lớn body của request lớn. Gộp buffer theo `hRequest`. |
| `WinHttpReceiveResponse` | Đánh dấu response đã sẵn sàng | Sau khi hàm này trả về, gọi `WinHttpQueryHeaders` (không phải hook thêm hàm khác của app — DLL tự chủ động gọi) với flag `WINHTTP_QUERY_RAW_HEADERS_CRLF` để lấy nguyên khối raw header (status line + toàn bộ header) trong 1 lần. |
| `WinHttpQueryDataAvailable` | Biết còn dữ liệu response hay không | Dùng kết hợp với `WinHttpReadData` để biết khi nào response đã đọc hết. |
| `WinHttpReadData` | Đọc body response, có thể gọi nhiều lần | Gộp buffer theo `hRequest` cho tới khi hết dữ liệu. **Phải xử lý đúng trường hợp `ReadFile` nội bộ trả về `FALSE` nhưng `GetLastError() == ERROR_MORE_DATA`** — đây không phải lỗi, vẫn cần lấy phần dữ liệu đã đọc được. |
| `WinHttpCloseHandle` | Dọn dẹp context khi request kết thúc | **Bắt buộc hook** — nếu không, context map sẽ rò rỉ, và giá trị `HINTERNET` bị tái sử dụng (xem mục 9) sẽ gây nhầm lẫn giữa các request khác nhau. |

## 6. Injection & Launcher — 2 phương án chính

**Method A — CreateProcess suspended + inject (ưu tiên khi có thể tự khởi động target):**
- `CreateProcess(..., CREATE_SUSPENDED, ...)` → `WriteProcessMemory` + `CreateRemoteThread` gọi `LoadLibraryW` → chờ handshake (mục 7) → `ResumeThread`.
- Chờ handshake bằng named event, **không dùng `Sleep()` cố định dưới bất kỳ hình thức nào** — đây là race condition rõ ràng (DLL init nhanh hơn thì lãng phí thời gian chờ, chậm hơn thì resume sớm và mất traffic đầu).

**Method B — inject vào process đang chạy:**
- `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` gọi `LoadLibraryW`.
- **Bắt buộc có fallback quyền**: thử `OpenProcess(PROCESS_ALL_ACCESS, ...)` trước; nếu fail (ví dụ do UAC/target chạy quyền khác), fallback sang tổ hợp quyền tối thiểu cần thiết: `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION`. Log rõ đang dùng quyền nào.
- Traffic phát sinh trước thời điểm inject sẽ không bắt được — giới hạn đã biết, không phải bug, không cần xử lý thêm.

### 6.1 Xử lý lỗi quyền hạn (`OpenProcess` fail cả 2 mức)

Khi cả `PROCESS_ALL_ACCESS` lẫn tổ hợp quyền tối thiểu đều thất bại (lỗi điển hình: `OpenProcess failed ... Access is denied.` với cả full và minimal rights), Launcher **không được** chỉ log "access denied" rồi dừng — phải chẩn đoán nguyên nhân cụ thể và báo đúng hướng khắc phục cho người vận hành:

| Nguyên nhân | Cách chẩn đoán trong code | Thông báo/hành vi bắt buộc |
|---|---|---|
| Launcher không chạy elevated trong khi cần | Kiểm tra token hiện tại bằng `GetTokenInformation(TokenElevation)` trước khi thử inject | Nếu chưa elevated và lần thử đầu fail với `ERROR_ACCESS_DENIED` (5): gợi ý "chạy lại Launcher với quyền Administrator", không tự động relaunch ngầm (tránh hành vi tự leo quyền không xin phép người dùng) |
| Target chạy ở integrity level cao hơn (ví dụ target chạy admin, Launcher chạy user thường) | So sánh integrity level qua `GetTokenInformation(TokenIntegrityLevel)` của Launcher vs target (lấy token target qua `OpenProcessToken` sau khi `OpenProcess` với quyền `PROCESS_QUERY_LIMITED_INFORMATION` — quyền này gần như luôn xin được kể cả khi các quyền khác bị từ chối) | Log rõ: "target chạy integrity level cao hơn Launcher, cần chạy Launcher với quyền tương đương hoặc cao hơn" |
| Target là Protected Process / Protected Process Light (PPL), hoặc có anti-tamper chủ động chặn `OpenProcess` | Không có cách chẩn đoán chắc chắn 100% từ user-mode; coi đây là kết luận mặc định khi đã elevated + integrity level tương đương mà vẫn fail | Log rõ: "process có khả năng được bảo vệ ở mức hệ thống (protected process/anti-tamper) — không thể inject bằng kỹ thuật user-mode thông thường"; **dừng lại, không thử các kỹ thuật bypass PPL/anti-tamper** — nằm ngoài phạm vi công cụ monitoring này |
| PID không tồn tại hoặc đã thoát giữa lúc liệt kê và lúc `OpenProcess` (race condition tự nhiên khi enumerate process) | Bọc case `OpenProcess` fail với `ERROR_INVALID_PARAMETER` (87) tách riêng khỏi `ERROR_ACCESS_DENIED` (5) | Log: "target process không còn tồn tại, có thể đã thoát trước khi inject — thử lại" |
| Phần mềm bảo mật (Defender/EDR) chặn hành vi `OpenProcess`+`WriteProcessMemory`+`CreateRemoteThread` (pattern injection kinh điển) | Không detect trực tiếp được; suy luận khi quyền hạn + integrity level đều ổn nhưng vẫn fail, đặc biệt nếu điểm fail là `WriteProcessMemory`/`CreateRemoteThread` chứ không phải `OpenProcess` | Log gợi ý: "có thể bị chặn bởi phần mềm bảo mật — cân nhắc thêm exclusion cho Launcher/target nếu đây là môi trường test do bạn kiểm soát"; không tự động thao tác với Defender/registry AV — ngoài phạm vi tool |

**Nguyên tắc chung cho toàn bộ luồng lỗi quyền hạn:**
- Mọi `OpenProcess`/`OpenProcessToken`/`VirtualAllocEx`/`WriteProcessMemory`/`CreateRemoteThread` fail đều phải log kèm mã lỗi số từ `GetLastError()` và text tương ứng qua `FormatMessageW` — không log tên hàm fail suông không kèm mã lỗi.
- Không retry tự động vô hạn, không tự động escalate quyền ngầm (tự nạp driver, tự bypass PPL). Nếu quyền không đủ, dừng lại và báo rõ, để người vận hành tự quyết định (chạy lại với quyền cao hơn, chọn target khác).
- Ưu tiên Method A (CreateProcess suspended) khi có thể tự khởi động target — né được phần lớn vấn đề quyền hạn của Method B, vì Launcher là chính process tạo ra target nên có handle đầy đủ quyền ngay từ đầu.

**Method C (DLL search-order hijacking, kiểu proxy loader) — ngoài phạm vi bản này**, để ngỏ cho phase mở rộng sau.

## 7. Handshake sequence (bắt buộc, áp dụng cho cả 2 method)

1. Launcher tạo named event (`HOOKS_READY_EVENT_NAME`) trước khi thực hiện injection.
2. DLL sau khi được `LoadLibraryW`, `DllMain(PROCESS_ATTACH)` **chỉ được trigger 1 background thread**, không làm bất kỳ việc nặng nào trực tiếp trong `DllMain` (xem lý do ở mục 8) — background thread mới là nơi thực hiện cài hook và kết nối IPC.
3. Background thread: cài hook (`MH_Initialize` → `MH_CreateHook` cho từng hàm ở mục 5 → `MH_EnableHook`) → kết nối `IpcClient` tới named pipe của Logger → khi cả 2 bước xong, `SetEvent(HOOKS_READY_EVENT_NAME)`.
4. Launcher (Method A) chờ event này với `WaitForSingleObject` (timeout hợp lý, ví dụ 10 giây) **trước khi** `ResumeThread`. Nếu timeout, log lỗi rõ ràng, không resume mù.
5. Launcher (Method B) cũng chờ cùng event (timeout ngắn hơn, ví dụ 3-5 giây) trước khi báo thành công cho người dùng — không có bước resume nhưng vẫn cần xác nhận hook đã sẵn sàng.

## 8. Yêu cầu về DllMain & khởi tạo (tránh loader lock)

- `DllMain(PROCESS_ATTACH)` chỉ được: gọi `DisableThreadLibraryCalls`, tạo 1 thread mới để làm phần khởi tạo thật sự, rồi return ngay. **Không được** gọi `LoadLibrary` cho DLL khác, không `WaitForSingleObject`, không làm việc nặng trực tiếp trong `DllMain` — vi phạm ràng buộc loader lock của Windows, dễ gây deadlock khi inject vào process phức tạp.
- Toàn bộ state khởi tạo (`đã init`, `đang init`, `hooks đã sẵn sàng`) dùng kiểu atomic (`std::atomic<bool>`), không dùng `bool` thường có thể bị race giữa các thread.
- `DllMain(PROCESS_DETACH)`: kiểm tra tham số `lpReserved` — nếu khác `nullptr` (process đang terminate), **bỏ qua toàn bộ cleanup** (an toàn hơn theo khuyến cáo của Windows, cleanup lúc này không cần thiết và có thể gây crash). Nếu `lpReserved == nullptr` (bị `FreeLibrary` tường minh), mới thực hiện shutdown/gỡ hook đầy đủ.
- Guard chống re-entrancy khi hook tự gọi lại chính nó (ví dụ code gửi log lỡ gọi lại API đang hook): dùng `thread_local` (ưu tiên hơn `TlsAlloc`/`TlsSetValue` vì future-proof hơn với C++), lưu giá trị rõ ràng kiểu `bool`/enum thay vì ép kiểu `bool` sang `LPVOID` (dễ gây undefined behavior nếu cast sai kiểu).

## 9. Thiết kế IPC (DLL ↔ Logger)

**Phía DLL (`IpcClient`):**
- Gửi message **không bao giờ được block bên trong hàm hook**. Hook chỉ enqueue message vào 1 queue nội bộ thread-safe (mutex hoặc lock-free); 1 background IO thread riêng của `IpcClient` chịu trách nhiệm lấy từ queue và ghi qua named pipe (overlapped I/O).
- Nếu ghi pipe timeout hoặc lỗi, phải `CancelIo` đúng cách trước khi đóng handle/event — không được để `OVERLAPPED` struct bị huỷ trong khi I/O vẫn đang pending (gây memory corruption khi kernel ghi vào vùng nhớ đã giải phóng).
- Nếu pipe đứt, chấp nhận drop message (không cố gắng reconnect ngay trong send path) — reconnect nên là hành vi riêng biệt, không lồng vào code path gửi message.
- Toàn bộ member liên quan connect/disconnect dùng `std::atomic`/`std::mutex` phù hợp — không có race giữa thread gọi hook và IO thread.

**Phía Logger (`BirriLogger.exe`):**
- Named pipe server dùng `PIPE_UNLIMITED` instances (không giới hạn 1), có cơ chế shutdown sạch qua stop event (không dùng busy-loop với timeout cố định).
- **Message framing phải đúng**: named pipe không đảm bảo 1 lần `ReadFile` = 1 message hoàn chỉnh. Bắt buộc dùng length-prefix (đã có trong header của wire format) và tích luỹ buffer cho tới khi đủ độ dài khai báo mới parse — không parse ngay sau 1 lần đọc.
- Validate `header.length` trước khi dùng (so với kích thước buffer thực nhận, và giới hạn tối đa hợp lý) — không tin tưởng mù dữ liệu nhận từ pipe.
- `g_transactions` (hoặc cấu trúc tương đương lưu các transaction đang xử lý) phải được bảo vệ bằng mutex — không giả định single-threaded nếu có khả năng mở rộng sau này.
- Response body nhận nhiều lần phải **append**, không được ghi đè — nếu không, response nhiều chunk sẽ chỉ còn giữ lại phần cuối.
- Dùng wire format có kiểm soát rõ ràng (memcpy vào/từ buffer byte, không dùng kiểu "struct hack"/reinterpret_cast vi phạm strict aliasing).

**Correlation & ID:**
- **Không dùng trực tiếp giá trị `HINTERNET` làm ID để match request-response** — giá trị này có thể bị tái sử dụng sau khi `WinHttpCloseHandle`, dẫn tới nhầm response của request cũ sang request mới nếu có nhiều request nối tiếp nhau. Cấp 1 unique ID tăng dần (atomic counter) cho mỗi `WinHttpOpenRequest`, dùng ID này xuyên suốt IPC message thay vì giá trị handle thô.

## 10. Endpoint/URL resolution (tổng hợp từ mục 5 + 9)

- Full URL hiển thị luôn phải đủ 4 phần: `scheme://host:port/path?query`. Không được thiếu bất kỳ phần nào.
- Scheme xác định theo cờ `WINHTTP_FLAG_SECURE` lúc `WinHttpOpenRequest` (có cờ này → https, không có → http).
- Host + port lấy từ `WinHttpConnect`, map theo `hConnect`.
- Path + query lấy từ `WinHttpOpenRequest` (object name).
- Luôn hiển thị port tường minh (kể cả port mặc định 80/443) để tránh mơ hồ — áp dụng nhất quán cho mọi request.

## 11. Xử lý dữ liệu (nén, chunked)

- Đọc header `Content-Encoding` (từ raw headers lấy qua `WinHttpQueryHeaders`), giải nén gzip/deflate (bằng **zlib**, vendor tại `third_party/zlib/`, xem mục 2.1) và br (bằng **brotli**, vendor tại `third_party/brotli/`, xem mục 2.1) trước khi hiển thị body. Nếu giải nén lỗi, fallback hiển thị raw kèm cảnh báo thay vì crash.
- WinHTTP thường tự động xử lý `Transfer-Encoding: chunked` trước khi trả dữ liệu qua `WinHttpReadData`, nhưng vẫn cần code phòng thủ: nếu phát hiện dữ liệu thô còn ở dạng chunked (chưa được decode), phải tự ghép chunk lại đúng cách trước khi hiển thị.

Tôi sẽ viết lại section 12 với layout mới, đẹp và dễ nhìn hơn, trong khi vẫn giữ đúng các yêu cầu kỹ thuật (không hex dump, ASCII-safe, ghép request-response theo unique ID):

---

## 12. Output Layout (Logger hiển thị)

### Yêu cầu chung
- **Không hiển thị hex dump** dưới bất kỳ hình thức nào.
- **Không dùng ký tự Unicode box-drawing** (`─────`, `━━━━`) — dễ lỗi codepage console Windows. Chỉ dùng ký tự ASCII an toàn.
- Log debug nội bộ (nếu có) phải tách kênh riêng, không được lẫn vào output transaction chính.

### Cấu trúc mỗi transaction
Mỗi transaction là 1 khối hoàn chỉnh gồm **Request + Response ghép chung** theo unique ID (mục 9), không in rời rạc theo thứ tự hook gọi tới. Các khối cách nhau bằng dòng trắng.

**Mẫu chi tiết (agent có thể tinh chỉnh, giữ đúng tinh thần, khong can phai can space cho that chuan nhu example):**

```
+----[ TRANSACTION #1 ]----+ 2026-07-31 10:15:03.456
| REQUEST
|   Method  : GET
|   URL     : https://tedne.site:443/dns-query?name=tedne.site&type=1
|   Protocol: HTTP/1.1
|   Headers :
|     Host            : tedne.site
|     Accept          : application/dns-json
|     User-Agent      : Mozilla/5.0 ...
|   Body    : (none)
|
| RESPONSE
|   Status  : 200 OK
|   Protocol: HTTP/1.1
|   Headers :
|     Content-Type    : application/dns-json
|     Content-Length  : 69
|   Body    :
|     {
|       "Status": 0,
|       "TC": false,
|       "RD": true,
|       "RA": true,
|       "AD": false,
|       "CD": false
|     }
+------------------------------------------+ 23.45ms
```

### Quy tắc hiển thị từng phần

**Headers:**
- Format: `│     <Tên Header>  : <giá trị>`
- Nếu không có header đặc biệt nào cần log, ghi `(none)`.

**Body:**
- Chỉ in section Body nếu **có body thật sự** (không in section rỗng).
- Body text được indent 2 level để phân biệt với metadata.
- Nếu body quá dài, cắt bớt và ghi chú `... (truncated, full in debug log)`.

**Timing:**
- Góc trên phải: timestamp lúc bắt đầu request.
- Góc dưới phải: tổng thời gian request→response (nếu đã có response), hoặc ghi `(pending)`.

**Trạng thái pending:**
- Nếu response chưa nhận được tại thời điểm hiển thị:
```
+----[ TRANSACTION #2 ]----+ 2026-07-31 10:15:04.123
| REQUEST
|   Method  : POST
|   URL     : https://api.example.com/data
|   ...
|
| RESPONSE
|   Status  : (pending)
+------------------------------------------+
```

### Ví dụ nhiều transaction liên tiếp

```
+----[ TRANSACTION #1 ]----+ 2026-07-31 10:15:03.456
| REQUEST
|   Method  : GET
|   URL     : https://tedne.site:443/dns-query?name=tedne.site&type=1
|   ...
| RESPONSE
|   Status  : 200 OK
|   ...
+------------------------------------------+ 23.45ms

+----[ TRANSACTION #2 ]----+ 2026-07-31 10:15:04.789
| REQUEST
|   Method  : CONNECT
|   URL     : https://proxy.example.com:8080
|   ...
| RESPONSE
|   Status  : 200 Connection Established
|   ...
+------------------------------------------+ 12.10ms
```

## 13. GitHub Actions Workflow (build + cache + upload artifact)

- Runner: `windows-latest` (đã có sẵn MSVC2022/v143 mặc định).
- Checkout repo kèm `--recurse-submodules` nếu third-party deps (mục 2.1) vendor theo git submodule — không có bước `git clone` riêng nào khác nhắm tới GitHub của MinHook/zlib/brotli trong workflow (đã vendor sẵn trong repo, không clone online lúc CI chạy).
- `PlatformToolset=v143` khai báo tường minh cho cả bước build solution (msbuild) lẫn build CMake của cả 3 thư viện third-party (MinHook, zlib, brotli — tham số `-T v143` cho mỗi lib) — đảm bảo đồng bộ với mục 2, không lệch giữa CI và `.vcxproj`.
- Cache build output (`.lib`) của cả 3 thư viện third-party, cache key dựa theo hash toàn bộ thư mục `third_party/` (không chỉ riêng MinHook như trước, mở rộng theo mục 2.1) — tự invalidate khi bất kỳ lib nào trong 3 lib đổi source/version ghim.
- Trigger: `push`/`pull_request` vào `main`, có thêm `workflow_dispatch`.
- Sau khi build Release x64 thành công, xác nhận đủ file output cần thiết tồn tại (build phải fail rõ ràng nếu thiếu file, không được "xanh" giả), rồi upload đúng các file output (dll/exe/pdb liên quan) làm artifact, đặt tên kèm run number/commit sha. Không upload toàn bộ thư mục intermediate/object.

## 14. Kế hoạch test

1. Build Release x64, xác nhận 0 warning với `/W4 /WX`.
2. Chạy Logger, dùng Method A khởi động target — xác nhận nhận handshake trong timeout quy định, không resume mù khi timeout.
3. Thao tác 1 request HTTPS đơn giản qua WinHTTP trong target — đối chiếu output: full URL đúng đủ 4 phần, body plaintext đọc được, layout đúng mục 12.
4. Test Method B vào target đã chạy sẵn — xác nhận fallback quyền hoạt động khi launcher không chạy admin.
5. Test tải cao: nhiều request đồng thời — xác nhận không mất/lẫn transaction, response không bị ghi đè bởi request khác.
6. Test kill Logger đột ngột trong khi target đang gửi request — xác nhận target không bị block/treo, message chỉ bị drop chứ không gây deadlock hoặc crash target.
7. Test response lớn cần nhiều lần `WinHttpReadData`/nhiều lần ghi qua named pipe — xác nhận buffer tích luỹ theo length hoạt động đúng, không parse nhầm message chưa đủ.
8. Test request có body lớn cần nhiều lần `WinHttpWriteData` — xác nhận body được ghép đủ, không bị cắt cụt.
9. Test app đóng handle liên tục (nhiều request nối tiếp nhanh) — xác nhận không có hiện tượng response bị match nhầm sang request khác do tái sử dụng `HINTERNET`.
10. Test inject vào target chạy quyền cao hơn Launcher (ví dụ target elevated, Launcher user thường) — xác nhận Launcher fail đúng thông báo ở mục 6.1 (chẩn đoán integrity level), không crash, không treo.
11. Test inject vào target là process hệ thống được bảo vệ (ví dụ thử với 1 process PPL bất kỳ có sẵn trên máy, không cần tạo riêng) — xác nhận Launcher dừng đúng cách với log "protected process/anti-tamper", không thử fallback vô hạn.
12. Test PID không tồn tại (đưa PID giả hoặc PID của process vừa thoát) — xác nhận log đúng "process không còn tồn tại", không nhầm với lỗi access denied.
13. Test target 32-bit trên máy 64-bit (kiến trúc không khớp) — xác nhận Launcher phát hiện và từ chối sớm kèm thông báo rõ, không cố `LoadLibraryW` một DLL x64 vào process x86 rồi crash mù mờ.
14. Test named pipe bị chiếm bởi tiến trình khác hoặc Logger khởi động 2 lần cùng lúc — xác nhận instance thứ 2 phát hiện và thoát có log rõ, không giành pipe gây lỗi khó hiểu cho DLL.
15. Test disk đầy hoặc không ghi được log (nếu Logger có ghi file) — xác nhận Logger không crash, chỉ mất khả năng ghi file kèm cảnh báo, output console vẫn hoạt động.

## 14.1 Xử lý Edge Case (tổng hợp toàn hệ thống)

Mục này tổng hợp các trường hợp biên xuyên suốt toàn bộ pipeline (Launcher → DLL/Hook → IPC → Logger) chưa được liệt kê chi tiết ở các mục trên, hoặc cần nhấn mạnh lại vì dễ bị bỏ sót khi implement.

### 14.1.1 Injection & khởi động (Launcher)

- **Kiến trúc process không khớp (x86 vs x64)**: trước khi inject, Launcher phải kiểm tra kiến trúc của target bằng `IsWow64Process2` (hoặc `IsWow64Process` cho máy không hỗ trợ API mới) và so với kiến trúc của `BirriMonitor.dll` (luôn x64 theo mục 1). Nếu không khớp, từ chối ngay với log rõ ràng — không cố `LoadLibraryW` để rồi fail mù mờ hoặc crash target.
- **Target thoát ngay sau khi inject nhưng trước handshake**: nếu `WaitForSingleObject` trên handshake event trả về do process handle bị signaled (target đã chết) thay vì event, Launcher phải phân biệt được 2 trường hợp này (dùng `WaitForMultipleObjects` chờ đồng thời cả handshake event lẫn process handle của target) — báo đúng "target đã thoát trước khi hoàn tất khởi tạo hook" thay vì báo chung chung "timeout".
- **`LoadLibraryW` remote thất bại do path DLL không tồn tại/không load được từ góc nhìn target** (ví dụ target chạy trong sandbox/container có filesystem view khác): `CreateRemoteThread` vẫn có thể trả về thành công (thread được tạo) dù `LoadLibraryW` bên trong fail — Launcher nên lấy exit code của remote thread qua `GetExitCodeThread` sau khi thread kết thúc (giá trị trả về của `LoadLibraryW` chính là exit code, `0` = fail) để phát hiện case này thay vì tin nhầm là đã inject thành công chỉ vì `CreateRemoteThread` không lỗi.
- **`CreateRemoteThread` bị chặn (một số EDR chặn API này nhưng cho qua `OpenProcess`)**: nếu `OpenProcess` + `WriteProcessMemory` đều thành công nhưng `CreateRemoteThread` fail, log riêng case này (không gộp chung nhóm lỗi quyền ở mục 6.1) vì nguyên nhân khác — gợi ý dùng `NtCreateThreadEx` chỉ nếu người vận hành chủ động chọn chế độ nâng cao; mặc định không tự fallback sang kỹ thuật ít phổ biến hơn để tránh hành vi giống công cụ né tránh phát hiện.

### 14.1.2 Trong tiến trình target (DLL/Hook)

- **`MH_CreateHook`/`MH_EnableHook` fail cho 1 hàm cụ thể** (ví dụ do 1 EDR khác đã hook trước lên cùng địa chỉ, gây xung đột trampoline): không được để 1 hook fail làm sập toàn bộ init. Log rõ hàm nào fail, hook nào còn lại vẫn tiếp tục hoạt động bình thường — DLL chạy ở chế độ "capture một phần" thay vì toàn bộ `MH_Initialize` fail thì abort sạch.
- **Target multi-thread gọi WinHTTP đồng thời trên nhiều `hRequest` khác nhau**: toàn bộ map (`hConnect→(host,port)`, `hRequest→hConnect`, `hRequest→unique ID`, buffer tích luỹ theo `hRequest`) phải dùng lock phù hợp (`std::shared_mutex` nếu đọc nhiều/ghi ít, hoặc `std::mutex` đơn giản nếu không cần tối ưu) — không giả định single-thread dù target hiện tại chỉ dùng 1 thread.
- **`WinHttpCloseHandle` gọi 2 lần trên cùng handle (double-close, lỗi từ phía app target)**: hook phải kiểm tra handle có trong map trước khi xoá; nếu không có (đã bị xoá từ lần gọi trước), bỏ qua an toàn thay vì crash do double-free logic nội bộ.
- **Handle `hRequest`/`hConnect` được đóng bất đối xứng** (ví dụ app đóng `hConnect` trước khi đóng hết các `hRequest` con của nó — hợp lệ theo WinHTTP docs): cleanup phải xử lý theo thứ tự phụ thuộc đúng, không giả định `hConnect` luôn đóng sau cùng.
- **Hook bị gọi lại trong lúc DLL đang unload (`FreeLibrary` đang chạy song song với 1 request WinHTTP khác)**: dùng flag atomic "đang shutdown" kiểm tra ở đầu mỗi hook — nếu đang shutdown, pass-through thẳng tới hàm gốc, không cố gắng ghi vào state đã/đang bị huỷ.
- **Buffer body/response cực lớn (ví dụ download file nhiều GB qua WinHTTP)**: đặt giới hạn tích luỹ hợp lý trong buffer per-`hRequest` (ví dụ cấu hình được, mặc định vài chục MB); vượt ngưỡng thì báo qua IPC dạng "truncated tại nguồn" kèm tổng kích thước thật, không cố giữ toàn bộ trong RAM của target gây OOM ảnh hưởng đến chính target đang được giám sát.

### 14.1.3 IPC

- **Logger khởi động sau DLL (thứ tự ngược)**: `IpcClient` phải tự retry connect theo chu kỳ hợp lý (ví dụ backoff tăng dần, không busy-loop) thay vì chỉ thử 1 lần lúc init rồi bỏ cuộc vĩnh viễn — vì handshake ở mục 7 yêu cầu kết nối thành công thì mới `SetEvent`, nếu không retry thì toàn bộ DLL sẽ treo ở bước handshake cho tới timeout rồi Launcher báo lỗi dù Logger có thể chỉ khởi động chậm vài giây.
- **Pipe full/server đọc chậm hơn tốc độ ghi** (target sinh traffic nhanh hơn Logger xử lý): queue nội bộ ở `IpcClient` (mục 9) cần giới hạn kích thước tối đa; vượt ngưỡng thì drop message cũ nhất hoặc mới nhất (chọn 1 chính sách rõ ràng, khuyến nghị drop mới nhất để không làm rối thứ tự transaction đã bắt đầu gửi) kèm đếm số message đã drop để Logger có thể hiển thị cảnh báo "N message bị bỏ qua do quá tải".
- **2 DLL instance cùng connect 1 Logger** (ví dụ inject nhầm 2 lần vào cùng target, hoặc Logger giám sát nhiều target cùng lúc nếu tương lai mở rộng): unique ID theo mục 9 chỉ tăng dần trong phạm vi 1 process — nếu Logger nhận từ nhiều nguồn, cần thêm định danh nguồn (ví dụ PID kèm theo trong header wire format) để tránh 2 request từ 2 process khác nhau bị trùng ID và ghép nhầm response.

### 14.1.4 Logger hiển thị

- **Response không bao giờ tới** (target crash giữa chừng, hoặc connection bị RST): transaction ở trạng thái pending vĩnh viễn nếu không có cơ chế dọn — cần timeout hiển thị hợp lý (ví dụ sau N phút không có update, tự chuyển trạng thái hiển thị thành "(no response — timed out or connection lost)" thay vì giữ "(pending)" mãi mãi gây hiểu lầm là đang chờ).
- **Ký tự không in được / control character trong header hoặc body** (dữ liệu network không đảm bảo sạch): trước khi in ra console, escape hoặc lọc bỏ control character (trừ `\n`/`\t` hợp lệ trong ngữ cảnh format) để tránh phá layout hoặc gây side-effect lạ trên console (ví dụ ANSI escape injection từ dữ liệu network không tin cậy).
- **Encoding header/body không phải UTF-8 hợp lệ**: khi convert sang text hiển thị, dùng chế độ thay thế ký tự lỗi (không throw/crash) — dữ liệu nhị phân lẫn trong body tưởng là text (ví dụ Content-Type khai sai) vẫn phải hiển thị được ở dạng an toàn thay vì làm Logger treo hoặc thoát.

## 15. Phạm vi mở rộng trong tương lai (không triển khai trong bản này)

Chỉ thực hiện khi có yêu cầu riêng, không tự ý mở rộng khi chưa được yêu cầu:

| Thư viện/lớp | Hàm cần hook (khi triển khai) | Ghi chú |
|---|---|---|
| Winsock (`ws2_32.dll`) | `send`, `recv`, `WSASend`, `WSARecv`, `connect`, `WSAConnect`, `getaddrinfo` | Chỉ hữu ích cho traffic không TLS, hoặc lấy IP:port đích |
| WinINet (`wininet.dll`) | `HttpSendRequest[A/W]`, `InternetReadFile`, `HttpQueryInfo`, `HttpOpenRequest` | Dùng bởi app legacy/IE-based |
| URLMon (`urlmon.dll`) | `URLOpenStream`/`IBindStatusCallback` | Hiếm gặp với app hiện đại |
| Schannel/SSPI | `EncryptMessage`, `DecryptMessage`, `InitializeSecurityContext` | **Đã triển khai** — xem mục 16 |
| OpenSSL | `SSL_write`, `SSL_read` | Kiểm tra dynamic/static link trước khi hook |
| BCrypt/CNG | `BCryptEncrypt`, `BCryptDecrypt` | Xác nhận app thực sự dùng CNG cho TLS trước khi hook |
| mbedTLS | `mbedtls_ssl_write`, `mbedtls_ssl_read` | Thường static-link, cần signature scanning |
| QUIC/HTTP3 | API stream tầng ứng dụng hoặc TLS provider bên dưới | Cần xác định trước target dùng msquic hay lib QUIC riêng |

Method C (DLL search-order hijacking kiểu proxy loader) cũng thuộc phạm vi mở rộng này, chưa triển khai trong bản đặc tả hiện tại.

---

## 16. Schannel/SSPI Capture Layer (layer capture thứ 2)

### 16.0 Phạm vi & ràng buộc

- Layer này **bổ sung**, không thay thế WinHTTP hooks (mục 5) — cả 2 chạy song song trong cùng 1 DLL, cùng 1 target process.
- Ba đường TLS mà app Windows có thể dùng, và vị trí của từng đường trong toàn bộ spec:
  - **Qua WinHTTP** → đã capture bằng hooks hiện tại (mục 5), không thuộc phạm vi mục 16.
  - **Qua SSPI/Schannel trực tiếp** (ví dụ RDP client, custom HTTPS library tự quản lý socket + gọi thẳng SSPI, WebSocket tự implement TLS thay vì dùng WinHTTP) → **đây là phạm vi triển khai của mục 16**.
  - **Qua OpenSSL/BCrypt(CNG)/mbedTLS** → ngoài phạm vi, vẫn thuộc mục 15 (phạm vi mở rộng tương lai), không đụng tới trong mục 16.
- Target vẫn giữ nguyên ràng buộc mục 1: x64 duy nhất, 1 process cụ thể người vận hành sở hữu/có quyền kiểm thử, không MITM-proxy — layer Schannel cũng capture bằng hook trực tiếp API trong tiến trình target, đúng tinh thần kiến trúc gốc.
- Không mở rộng sang QUIC/HTTP3 dù chúng cũng có thể dùng Schannel cho phần TLS — QUIC giữ nguyên trong mục 15, chưa triển khai.
- Không có thay đổi nào về injection/launcher (mục 6), handshake (mục 7), hay DllMain (mục 8) — layer Schannel dùng chung toàn bộ hạ tầng đó, chỉ thêm hook point + message type mới.

### 16.1 Mục đích

App Windows có thể dùng TLS theo 3 đường: qua WinHTTP (đã capture bằng hooks mục 5),
qua SSPI/Schannel trực tiếp (RDP client, custom HTTPS library, WebSocket tự implement
TLS) — **layer này bắt đường thứ 2**, hoặc qua OpenSSL/BCrypt/mbedTLS (ngoài scope, mục 15).
Layer này chạy song song với WinHTTP hooks — **không thay thế, không sửa code path WinHTTP**.

### 16.2 Hook targets

| Hàm (secur32.dll) | Mục đích | Thời điểm dữ liệu |
|---|---|---|
| `InitializeSecurityContextW` | Phát hiện stream mới, gán `stream_id`, lấy target hint (SNI) | Handshake — không có plaintext data |
| `EncryptMessage` | Bắt plaintext **trước khi** mã hóa | Ngay trước khi TLS encrypt → có plaintext |
| `DecryptMessage` | Bắt plaintext **sau khi** giải mã | Ngay sau khi TLS decrypt → có plaintext |
| `DeleteSecurityContext` | Tín hiệu đóng stream (gửi `SchannelStreamEnd`) | Teardown |

**Điểm khác so với bản follow-up spec:** thêm `DeleteSecurityContext` làm hook thứ 4 —
là cơ chế đáng tin cậy duy nhất để phát hiện "stream đóng" (`SchannelStreamEnd`). Ngoài ra
`DecryptMessage` trả về `SEC_E_CONTEXT_EXPIRED` cũng finalize stream.

### 16.3 Nguyên lý capture

- `EncryptMessage`: capture **trước** khi gọi trampoline — schannel mã hóa in-place, sau khi
  hàm gốc chạy các buffer `SECBUFFER_DATA` đã là ciphertext. Capture `SECBUFFER_DATA` (chính);
  `SECBUFFER_STREAM` chỉ dùng fallback khi không có DATA buffer (cbBuffer của nó trùm cả vùng
  header/trailer nên có thể kèm rác — Logger tự xử lý qua HTTP parse).
- `DecryptMessage`: capture **sau** khi gọi trampoline (plaintext chỉ tồn tại sau khi giải mã),
  chỉ buffer `SECBUFFER_DATA`.
- Không có request object như `hRequest` → correlation bằng **context handle** (có trong cả 4
  hàm hook), `stream_id` giữ nguyên dạng `(thread_id << 32) | seq` theo spec gốc.
- Hook hoàn toàn passive với handshake: không chặn/sửa, không verify certificate.

### 16.4 Detection — chỉ hook khi cần

- Trước khi cài hooks: `GetModuleHandleW(L"schannel.dll")`, fallback `ncrypt.dll`. Không có → skip.
- **Method A (inject lúc suspended) chưa load gì cả** — `GetModuleHandleW` lúc init sẽ luôn trả
  về NULL và bỏ sót toàn bộ. Vì vậy ngoài check tức thì, có thêm 1 thread late-bind nhẹ poll
  mỗi 100ms; khi `schannel.dll`/`ncrypt.dll` xuất hiện thì cài hooks ngay rồi thoát. Target
  không bao giờ dùng TLS → hooks không bao giờ được cài (đúng tinh thần "không hook mù").
- Giới hạn đã biết: stream SSPI đầu tiên có thể bị bỏ lỡ nếu toàn bộ TLS session hoàn tất
  trong ~100ms kể từ lúc `schannel.dll` được load (chỉ ảnh hưởng Method A target làm TLS ngay
  lúc khởi động).

### 16.5 Tránh double-capture với WinHTTP

WinHTTP tự dùng schannel nội bộ cho HTTPS — nếu hook Schannel capture luôn, HTTPS qua WinHTTP
sẽ hiện 2 lần (`[TRANSACTION]` + `[SCHANNEL]`). Giải pháp: **re-entrancy guard dùng chung** cho
cả 2 layer (`hook_common.h`). `InitializeSecurityContext` gọi từ trong một WinHTTP hook
(`WinHttpSendRequest`/`WinHttpWriteData`/`WinHttpReadData`...) sẽ pass-through, context không
được đăng ký → `EncryptMessage`/`DecryptMessage` trên context đó không tìm thấy stream → bỏ qua.
Context tạo trên thread WinHTTP không nằm trong hook (async WinHTTP) là giới hạn đã biết — hiếm gặp.

### 16.6 IPC & Logger

- Message types mới (mục 3, `IpcCommon.h`): `SchannelHandshake = 0x10`,
  `SchannelDataSend = 0x11`, `SchannelDataRecv = 0x12`, `SchannelStreamEnd = 0x13`.
- Wire format: `[stream_id: uint64_t] [data_length: uint32_t] [data: bytes...]`;
  `header.requestId` mang cùng `stream_id`.
- Logger: map `stream_id → SchannelTransaction`, append từng chunk (không ghi đè), finalize khi
  nhận `SchannelStreamEnd` (hoặc shutdown — `FlushPending`).
- Render theo layout `[SCHANNEL #N]` mục 6 follow-up spec:
  - `REQUEST (est.)` — data thô (không parse request), kèm `Stream` + `Target` (SNI hoặc
    `(schannel-tls)`).
  - `RESPONSE (parsed)` — tự parse status line + headers + body từ raw plaintext của
    `DecryptMessage`, decode chunked/gzip/deflate/brotli dùng chung code path với WinHTTP.
  - Không parse được (không phải HTTP) → **hex preview 32 bytes đầu** + ghi chú
    `(non-HTTP schannel stream)` — ngoại lệ hex duy nhất.
  - Target hint: ưu tiên `pszTargetName` của `InitializeSecurityContext` (chính là hostname
    đưa vào SNI extension), fallback parse TLS ClientHello trong `pInput` (mục 4.1 spec gốc),
    cuối cùng là `(schannel-tls)`.

### 16.7 Test plan & verification

Test layer Schannel dùng chung target/server helper với mục 14 khi hợp lý, thêm 2 công cụ mới:
- `SspiTarget.exe` — target tối giản tự implement SSPI/Schannel client (không qua WinHTTP), có mode `--send`/`/raw` để gửi non-HTTP payload qua TLS, và mode `--winhttp` để đồng thời mở thêm 1 request HTTPS qua WinHTTP trong cùng process.
- `tls_server.ps1` (hoặc tương đương) — server TLS đơn giản phía test, trả response HTTP hợp lệ, có thể cấu hình độ trễ để test timing/race.

**Sequential (đơn luồng, đúng thứ tự — baseline correctness):**

1. `SspiTarget.exe` (SSPI trực tiếp, không WinHTTP) gửi HTTP request qua TLS tới `tls_server.ps1` — xác nhận capture plaintext từ `EncryptMessage`/`DecryptMessage` (`[SCHANNEL]` block với request + response parsed đúng).
2. `SspiTarget --winhttp` (cùng process vừa SSPI vừa WinHTTP HTTPS, chạy tuần tự không đồng thời) — 2 layer chạy song song, không xung đột, output phân biệt rõ `[TRANSACTION]` và `[SCHANNEL]`, không double-capture (mục 16.5).
3. Target không dùng Schannel (WinHTTP HTTP thuần, không TLS) — không cài Schannel hooks (late-bind không bao giờ kích hoạt), behavior WinHTTP không đổi so với trước khi có layer này.
4. Non-HTTP stream (`--send`/`/raw`) — Logger hiện hex preview 32 bytes + ghi chú `(non-HTTP schannel stream)`; chunked/gzip/br qua Schannel được decode đúng bằng zlib/brotli đã vendor (mục 2.1, mục 11).
5. Stream đóng bình thường qua `DeleteSecurityContext` — `SchannelStreamEnd` được gửi, Logger finalize transaction đúng lúc, không còn ở trạng thái pending.
6. Stream kết thúc qua `DecryptMessage` trả `SEC_E_CONTEXT_EXPIRED` (không qua `DeleteSecurityContext` tường minh) — Logger vẫn finalize đúng, không phụ thuộc duy nhất vào `DeleteSecurityContext`.

**Concurrent (đa luồng, đồng thời — trọng tâm test race condition):**

7. **Nhiều SSPI stream mở đồng thời trên nhiều thread khác nhau của cùng `SspiTarget`** (ví dụ 10-50 thread, mỗi thread tự handshake + gửi request riêng tới `tls_server.ps1` cùng lúc) — xác nhận: mỗi `stream_id` (`(thread_id << 32) | seq`) không bị trùng giữa các thread; mỗi transaction trong Logger chứa đúng data của đúng stream, không lẫn chunk từ stream khác (kiểm tra bằng cách mỗi thread gửi 1 payload có marker riêng biệt, assert Logger nhận đúng marker cho đúng `stream_id`).
8. **SSPI concurrent + WinHTTP concurrent trong cùng process** (`--winhttp` kết hợp nhiều thread ở test 7) — xác nhận re-entrancy guard dùng chung (mục 16.5) không có race: context tạo từ thread WinHTTP luôn được pass-through đúng dù nhiều thread WinHTTP/SSPI chạy chồng chéo thời điểm; dùng ThreadSanitizer hoặc kiểm tra thủ công bằng cách chạy lặp lại (ví dụ 100 lần) tìm flaky output.
9. **Nhiều context handshake đồng thời rồi đóng gần như cùng lúc** (`InitializeSecurityContext` hàng loạt → `DeleteSecurityContext` hàng loạt trong khoảng thời gian ngắn) — xác nhận map `context handle → stream_id` (mục 16.3) không bị corrupt do 2 thread cùng ghi/xoá map cùng lúc; lock bảo vệ map này (cùng nguyên tắc với mục 14.1.2 cho map WinHTTP) phải được xác minh đủ chặt bằng stress test lặp nhiều vòng.
10. **Race giữa `DeleteSecurityContext` và `EncryptMessage`/`DecryptMessage` đang xử lý dở trên cùng context** (1 thread đóng context trong khi thread khác vẫn đang encrypt/decrypt trên context đó — hợp lệ nếu app tự có bug, nhưng hook không được crash vì lỗi từ app): xác nhận hook tra map an toàn (không dùng dangling pointer sau khi context bị xoá), nếu không tìm thấy `stream_id` thì bỏ qua an toàn thay vì crash — tương tự nguyên tắc double-close ở mục 14.1.2.
11. **Kill Logger mid-flight khi có nhiều Schannel stream đang chạy đồng thời** (không chỉ 1 stream như bản gốc) — target không crash, không treo bất kỳ thread nào đang gọi `EncryptMessage`/`DecryptMessage`, `IpcClient` reconnect (theo cơ chế mục 14.1.3) và capture tiếp các stream còn sống sau khi Logger lên lại; các stream đã đóng trong lúc Logger mất kết nối chấp nhận mất dữ liệu (drop), không gây leak ở phía DLL.

**Memory leak & resource leak:**

12. **Chạy target với hàng nghìn stream ngắn liên tiếp** (handshake → gửi 1 request nhỏ → đóng, lặp lại N lần, N đủ lớn ví dụ 5000-10000) trên cả sequential lẫn concurrent — theo dõi bằng Windows Performance Toolkit/`VMMap`/`Process Explorer` (Private Bytes, Handle Count) trước và sau; xác nhận **không tăng dần tuyến tính theo số stream** (map `context → stream_id` phải được dọn đúng ở `DeleteSecurityContext` và ở nhánh `SEC_E_CONTEXT_EXPIRED`, không rò rỉ entry).
13. **Test riêng nhánh lỗi**: ép `tls_server.ps1` đóng kết nối đột ngột giữa handshake (trước khi `DeleteSecurityContext` được app gọi tường minh) — xác nhận context vẫn được dọn khỏi map nội bộ của DLL (qua timeout dọn định kỳ hoặc qua phát hiện lỗi ở lần gọi SSPI kế tiếp trên context đó), không để entry mồ côi tồn tại vĩnh viễn trong map.
14. **Buffer tích luỹ per-stream** (tương tự nguyên tắc buffer per-`hRequest` ở mục 14.1.2): stream Schannel gửi payload cực lớn liên tục qua nhiều lần `EncryptMessage`/`DecryptMessage` — xác nhận có giới hạn tích luỹ hợp lý áp dụng nhất quán với WinHTTP, không OOM target khi 1 stream chạy rất lâu.
15. **So sánh handle count/private bytes của target chạy có BirriMonitor.dll (layer Schannel bật) vs chạy không có DLL** sau cùng khối lượng traffic — chênh lệch phải ổn định (không tăng dần theo thời gian chạy), dùng làm tiêu chí pass/fail khách quan cho leak thay vì chỉ quan sát định tính.
16. Áp dụng lại test 12-15 cho riêng nhánh IPC (`IpcClient` phía DLL) — queue nội bộ (mục 14.1.3) khi nhận traffic Schannel dồn dập cùng lúc với WinHTTP không phình to không kiểm soát; xác nhận chính sách drop khi quá tải (đã định nghĩa ở mục 14.1.3) áp dụng đúng cho cả 2 loại message (`Transaction*` và `Schannel*`) dùng chung 1 queue.

I'll add the two code quality requirements and the commit instruction to the spec. Here's the new section to be added:

## 17. Code Quality & Commit Requirements

### 17.1 No Comments or Documentation in Code

- **Strict prohibition**: The codebase (`BirriMonitor.dll`, `BirriLauncher.exe`, `BirriLogger.exe`, shared static libs, headers, and all implementation files) **must not contain any comments**—neither inline comments (`//`), block comments (`/* */`), nor doc comments (`///`, `/** */`).
- This includes:
  - Function-level documentation
  - Parameter descriptions
  - Section separators (e.g., `// ==== SECTION ====`)
  - TODO/FIXME/HACK markers
  - Explanatory comments on complex logic
  - File header comments
  - Commented-out code (dead code must be removed entirely, not commented out)
- **Rationale**: The code must be self-documenting through clear naming, small functions, and straightforward structure. Comments become stale, mislead readers, and add maintenance burden.
- **Exception**: The `third_party/` source tree (MinHook, zlib, brotli) is exempt—do not modify or strip comments from vendor code. Only BirriMonitor-authored code is subject to this rule.

### 17.2 No Comments in Solution/Project Files

- The `.vcxproj`, `.vcxproj.filters`, and `.sln` files **must not contain any comments** (i.e., `<!-- -->` XML comments in project files, or commented-out property groups/items).
- All project configurations must be explicit and complete without explanatory notes inside the XML.
- This ensures deterministic parsing by MSBuild and avoids accidental semantic drift.

### 17.3 Commit After Each Successful Change

- **Immediate commit**: After completing any change that results in a successful build (0 warnings, `Release x64` artifacts generated), you **must commit the change immediately**—do not batch multiple unrelated changes into a single commit.
- **Commit message format**: Use conventional commit format:
  ```
  <type>(<scope>): <subject>
  ```
  Where `<type>` is one of: `feat`, `fix`, `refactor`, `perf`, `test`, `build`, `ci`, `docs` (only if updating spec), `chore`; `<scope>` is the affected module (e.g., `logger`, `dll`, `launcher`, `ipc`, `schannel`); `<subject>` is a concise imperative description.
- **Rationale**: Small, focused commits enable bisection, rollback, and code review. A broken intermediate state must never be committed—only states that build cleanly and pass the smoke test (test #1 from section 14: Release x64 build with 0 warnings) are eligible for commit.
- **Edge case**: If a change partially implements a feature but leaves the code in a non-buildable state, it must not be committed. Break work into smaller logical chunks that each maintain a buildable state.
- **Merge commits**: No merge commits allowed in feature branches—use rebase + fast-forward only to keep history linear.