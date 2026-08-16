# Third-party vendored dependencies

All third-party libraries are vendored as plain source copies under `third_party/`.
No git submodules, no downloads at build time, no prebuilt binaries.
Build them locally with CMake (see `scripts/build.ps1`) using `-T v143`.

| Library | Upstream repo | Pinned tag | Pinned commit | Build output |
|---|---|---|---|---|
| MinHook | https://github.com/TsudaKageyu/minhook | master @ 2026-06-13 | d94c64d32ea37bc4f5ee47d580709f70c6fb6080 | `minhook.lib` (static) |
| zlib | https://github.com/madler/zlib | v1.3.1 | 51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf | `zlibstatic.lib` (static) |
| brotli | https://github.com/google/brotli | v1.1.0 | ed738e842d2fbdf2d6459e39267a633c4a9b2f5d | `brotlidec-static.lib`, `brotlicommon-static.lib` (static) |

## Source modifications

None. The vendored source trees are unmodified upstream checkouts.

## Build notes

- MinHook: CMake with default options produces the static library `minhook.lib`.
  Note: the v1.3.3 release tag predates CMake support; the pinned commit is on
  master (2026-06-13) and is the one that includes `CMakeLists.txt`.
- zlib: build with `-DBUILD_SHARED_LIBS=OFF`; the static library is `zlibstatic.lib`.
- brotli: build with `-DBUILD_SHARED_LIBS=OFF`; decoding needs `brotlidec-static.lib`
  and its dependency `brotlicommon-static.lib`.
- All three must be built with `-A x64 -T v143` to stay in sync with the main solution.
