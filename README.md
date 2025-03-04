# QUICHE modified
## Modification:
- `quic/core/crypto/quic_client_session_cache.h/.cc` are modified to write the session ticket, address validation token, server transport parameters and server SETTINGS to `/tmp/chrome_session_cache.txt` if the host/domain name is `www.localdomain.com`

QUICHE stands for QUIC, Http, Etc. It is Google's production-ready
implementation of QUIC, HTTP/2, HTTP/3, and related protocols and tools. It
powers Google's servers, Chromium, Envoy, and other projects. It is actively
developed and maintained.

There are two public QUICHE repositories. Either one may be used by embedders,
as they are automatically kept in sync:

*   https://quiche.googlesource.com/quiche
*   https://github.com/google/quiche

To embed QUICHE in your project, platform APIs need to be implemented and build
files need to be created. Note that it is on the QUICHE team's roadmap to
include default implementation for all platform APIs and to open-source build
files. In the meanwhile, take a look at open source embedders like Chromium and
Envoy to get started:

*   Platform implementations in Chromium:
    +   [quic/platform](https://source.chromium.org/chromium/chromium/src/+/main:net/quic/platform/impl/)
    +   [http2/platform](https://source.chromium.org/chromium/chromium/src/+/main:net/http2/platform/impl/)
    +   [quiche/common/platform](https://source.chromium.org/chromium/chromium/src/+/main:net/quiche/common/platform/impl/)
*   [Build file in Chromium](https://source.chromium.org/chromium/chromium/src/+/main:net/third_party/quiche/BUILD.gn)
*   [Platform implementations in Envoy](https://github.com/envoyproxy/envoy/tree/master/source/common/quic/platform)
*   [Build file in Envoy](https://github.com/envoyproxy/envoy/blob/main/bazel/external/quiche.BUILD)

To contribute to QUICHE, follow instructions at
[CONTRIBUTING.md](CONTRIBUTING.md).

QUICHE is only supported on little-endian platforms.
