# btcminer — đào Bitcoin (SHA-256d) bằng CPU qua giao thức Stratum v1

> **English:** [README.md](README.md)

Phần mềm đào BTC viết bằng **C++17**, kết nối tới pool qua **Stratum v1**
(`mining.subscribe` / `mining.authorize` / `mining.notify` / `mining.submit`),
tính block header, tìm nonce thoả mãn target của pool và gửi share về pool.

* **Một file `.exe` duy nhất**, biên dịch tĩnh: không cần runtime, không cần
  thư viện ngoài (chỉ Winsock2 của Windows).
* **Ba kernel băm tự chọn**: SHA-NI trên CPU đời mới, AVX2 8 làn trên CPU
  Haswell/Zen, và kernel scalar dự phòng (tự phát hiện bằng CPUID) cùng
  **midstate**: 64 byte đầu của header chỉ băm một lần cho mỗi job, mỗi nonce
  chỉ cần 2 lần nén SHA-256.
* Đa luồng bằng `std::thread` (mặc định = số CPU luận lý) để tận dụng mọi core.
* Tự động xử lý: `mining.set_difficulty`, `mining.set_extranonce`,
  `client.get_version`, `client.reconnect`, mất kết nối (reconnect + backoff).
* Có `--self-test` (kiểm tra thuật toán bằng vector chuẩn của Bitcoin),
  `--benchmark` (đo hashrate, không cần pool) và bộ test đầu-cuối với pool giả.

> ⚠️ **Lưu ý thực tế:** đào BTC bằng CPU không còn hiệu quả kinh tế. Với
> ~5–18 MH/s, xác suất tìm được block (solo) là cực nhỏ. Dự án này phù hợp để
> **học giao thức Stratum, kiểm thử, hoặc đào trên regtest/testnet**. Đừng kỳ
> vọng có lãi.


---

## 1. Yêu cầu

* Windows 10/11 64-bit (chỉ cần `KERNEL32`, `WS2_32` và UCRT có sẵn của hệ thống).
* Kết nối Internet tới pool (TCP, không hỗ trợ TLS trong bản này).
* Tài khoản/địa chỉ nhận của pool (ví dụ pool solo dùng chính địa chỉ BTC làm
  username).
* **Chỉ khi tự build:** MinGW-w64 `g++` (đã kiểm thử với WinLibs g++ 16.1.0,
  UCRT). Không cần CMake, không cần Visual Studio.

## 2. Chạy nhanh

```powershell
# 1) kiểm tra thuật toán + khả năng đào (không cần mạng)
.\dist\btcminer.exe --self-test

# 2) đo hashrate trong 15 giây
.\dist\btcminer.exe --benchmark 15

# 3) đào thật (ví dụ pool solo của ckpool)
.\dist\btcminer.exe -o stratum+tcp://solo.ckpool.org:3333 `
                    -u <DIA_CHI_BTC_CUA_BAN>.cpu1 -p x -t 4
```

Hoặc dùng file cấu hình:

```powershell
Copy-Item config.example.json config.json
# sửa config.json: url / user / processes ...
.\dist\btcminer.exe
```

`config.json` (nếu có trong thư mục hiện tại) được tự động nạp; tham số dòng
lệnh luôn ghi đè file cấu hình.

## 2.1. Bản chạy sẵn: `dist\btcminer.exe`

Không cần cài gì cả — dùng file đã build sẵn **`dist\btcminer.exe`** (~2.9 MB,
một file, biên dịch tĩnh, không cần runtime). Bản phát hành chính thức kèm file
tải về nằm ở [GitHub Releases](https://github.com/Linh2244/btcminer/releases/latest):

```powershell
.\dist\btcminer.exe --version
.\dist\btcminer.exe --self-test                 # kiểm tra thuật toán rồi thoát
.\dist\btcminer.exe --benchmark 15              # đo hashrate
.\dist\btcminer.exe -o stratum+tcp://solo.ckpool.org:3333 `
                    -u <DIA_CHI_BTC>.cpu1 -p x -t 4
```

* File `config.json` được đọc từ **thư mục hiện tại** (nơi bạn gõ lệnh), không
  phải nơi đặt file exe. Muốn dùng cấu hình: `Copy-Item config.example.json config.json`
  rồi chạy exe trong cùng thư mục đó.
* Khởi động tức thì (không giải nén như bản PyInstaller cũ).
* Bản Python cũ chỉ còn để tham khảo trong `legacy\` (`legacy\btcminer_py.exe`,
  mã nguồn + test) — không nằm trong `dist\` nữa.
* **Cảnh báo antivirus:** file `.exe` đào coin đôi khi bị Windows
  Defender/SmartScreen báo nhầm. Đây là false positive; nếu tin tưởng mã nguồn,
  hãy thêm file vào danh sách loại trừ hoặc tự build từ mã nguồn (mục 2.2).

### 2.2. Tự build lại exe

```powershell
# chỉ cần g++ trên PATH (MinGW-w64 / WinLibs)
powershell -ExecutionPolicy Bypass -File .\build.ps1        # -> dist\btcminer.exe
```

Script sẽ biên dịch từng file (`sha256_avx2.cpp` dùng `-mavx2`,
`sha256_shani.cpp` dùng `-msha -mssse3 -msse4.1`), link
tĩnh với `-static -static-libgcc -static-libstdc++ -lws2_32` rồi **tự chạy
`--self-test`**. Các tuỳ chọn:

| Tuỳ chọn | Tác dụng |
| --- | --- |
| `-Clean` | xoá `build/` + `dist/` trước khi build |
| `-Tools` | build thêm `build\bench.exe` (kiểm tra kernel + tốc độ) và `build\check.exe` (đối chiếu target/header) |

Hoặc gọi `g++` trực tiếp:

```powershell
g++ -O3 -std=c++17 -c cpp/sha256.cpp      -o build/sha256.o
g++ -O3 -std=c++17 -mavx2 -c cpp/sha256_avx2.cpp -o build/sha256_avx2.o
g++ -O3 -std=c++17 -msha -mssse3 -msse4.1 -c cpp/sha256_shani.cpp -o build/sha256_shani.o
foreach ($s in "util","json","job","stratum","worker","miner","main") {
    g++ -O3 -std=c++17 -c "cpp/$s.cpp" -o "build/$s.o"
}
g++ -O3 -std=c++17 -static -static-libgcc -static-libstdc++ `
    build/util.o build/json.o build/job.o build/stratum.o build/worker.o `
    build/miner.o build/main.o build/sha256.o build/sha256_avx2.o `
    build/sha256_shani.o -o dist/btcminer.exe -lws2_32
```

> Máy nào tắt script (Execution Policy) thì dùng
> `powershell -ExecutionPolicy Bypass -File .\build.ps1`.


## 3. Cấu hình

| Khoá trong `config.json` | Ý nghĩa | Mặc định |
| --- | --- | --- |
| `url` | URL pool `stratum+tcp://host:port` | — |
| `user` | worker name, thường là `<địa chỉ BTC>.<tên worker>` | — |
| `password` | mật khẩu worker (hầu hết pool bỏ qua) | `"x"` |
| `processes` | số thread đào (giữ tên cũ cho tương thích bản Python) | số CPU luận lý |
| `stats_interval` | giây giữa các lần in hashrate | `30` |
| `idle_timeout` | reconnect nếu pool im lặng quá N giây | `300` |
| `log_level` | `DEBUG` / `INFO` / `WARNING` / `ERROR` | `INFO` |
| `duration` | tự dừng sau N giây (tiện test) | không giới hạn |
| `suggest_difficulty` | gợi ý difficulty cho pool | không gửi |
| `seed` | seed RNG (nonce bắt đầu lặp lại được) | ngẫu nhiên |

## 4. Tuỳ chọn dòng lệnh

```
.\dist\btcminer.exe --help
```

| Tuỳ chọn | Mô tả |
| --- | --- |
| `-o, --url` | URL pool (`stratum+tcp://host:port`, hoặc `host:port`) |
| `-u, --user` | worker name / địa chỉ |
| `-p, --password` | mật khẩu worker |
| `-t, --processes` | số thread đào |
| `-c, --config` | file JSON cấu hình |
| `--duration` | dừng sau N giây |
| `--stats-interval` | chu kỳ in hashrate |
| `--idle-timeout` | ngưỡng reconnect khi pool im lặng |
| `--suggest-difficulty` | gửi `mining.suggest_difficulty` |
| `--user-agent` | chuỗi version gửi pool |
| `--seed` | seed RNG |
| `--benchmark [N]` | đo hashrate N giây (mặc định 30) |
| `--self-test` | kiểm tra thuật toán rồi thoát |
| `--log-level` | mức log |
| `--version` | in phiên bản |

Ví dụ chạy nền, ghi log ra file (PowerShell):

```powershell
.\dist\btcminer.exe -o stratum+tcp://solo.ckpool.org:3333 -u bc1....cpu1 -t 4 *> miner.log
```

## 5. Kiểm thử

```powershell
# bản C++: tự kiểm tra thuật toán, target và đào thử
.\dist\btcminer.exe --self-test

# kiểm tra kernel vector + tốc độ từng kernel (cần build.ps1 -Tools)
.\build\bench.exe

# test đầu-cuối với pool giả (pool tự dựng lại header để xác nhận share)
python tests/fake_pool_check.py

# bộ unittest của bản Python tham khảo (trong legacy/)
cd legacy; python -m unittest discover -v; cd ..
```

Bộ test gồm:

* **Vector chuẩn Bitcoin**: header block 125552 phải băm ra
  `00000000000000001e8d6829a8a21adc5d38d0a473b144b6765798e61f98bd1d`
  (kiểm tra cho cả kernel scalar, AVX2 và SHA-NI).
* **Đối chiếu AVX2/SHA-NI với scalar** trên 2048–4096 nonce ngẫu nhiên: sai lệch
  phải bằng 0.
* **Dữ liệu thật từ pool**: một `mining.notify` lấy từ `solo.ckpool.org` được
  dùng để kiểm tra cách đổi byte-order của `prevhash`, `version`, `ntime`,
  `nbits` (đối chiếu với hash block cha trên chuỗi).
* **Test đầu-cuối**: một pool giả (TCP server) nhận share và **tự dựng lại
  header bằng công thức độc lập** (`hashlib`, `struct.pack`) để xác nhận share
  hợp lệ — nhờ vậy lỗi endianness sẽ bị phát hiện. Lần chạy gần nhất:
  3383/3383 share hợp lệ, 0 share sai.
* **Target math**: `difficulty -> target` dùng phép chia số nguyên 256-bit nên
  khớp chính xác với giá trị `floor(0xFFFF * 2^208 / difficulty)`.

## 6. Cách hoạt động

### 6.1. Luồng Stratum

```
miner                                     pool
  |-- mining.subscribe(user_agent) -------->|
  |<-- [subscriptions, extranonce1, xn2_size]
  |-- mining.authorize(user, pass) -------->|
  |<-- true
  |<-- mining.set_difficulty(diff) ---------|
  |<-- mining.notify(job_id, prevhash, coinb1, coinb2,
  |                   merkle_branches, version, nbits, ntime, clean)
  |      ... đào ...
  |-- mining.submit(user, job_id, xn2_hex, ntime_hex, nonce_hex) -->|
  |<-- true / error
```

### 6.2. Dựng block header (80 byte)

```
 offset 0   : version    (4 byte, little-endian)
 offset 4   : prevhash   (32 byte)
 offset 36  : merkle root(32 byte)
 offset 68  : ntime      (4 byte, little-endian)
 offset 72  : nbits      (4 byte, little-endian)
 offset 76  : nonce      (4 byte, little-endian)
```

Coinbase và merkle root:

```
coinbase   = coinb1 + extranonce1 + extranonce2 + coinb2
merkle_root = SHA256d(coinbase)
for branch in merkle_branches:
    merkle_root = SHA256d(merkle_root + branch)
```

Kiểm tra share:

```
hash = SHA256d(header)                 # 32 byte, thứ tự "wire"
hợp lệ nếu  int.from_bytes(hash, "little") <= target
target = 0x00000000FFFF0000...0000 / difficulty
```

### 6.3. Quy ước byte-order của Stratum (dễ sai nhất)

| Trường | Cách xử lý |
| --- | --- |
| `prevhash` | `word_swap(bytes.fromhex(s))` — đảo byte trong từng nhóm 4 byte |
| `version`, `nbits`, `ntime` | `int(s, 16)` rồi `struct.pack("<I", ...)` |
| `coinb1`, `coinb2`, merkle branch | dùng nguyên bytes (`bytes.fromhex`) |
| `nonce` khi submit | `"%08x" % nonce` (hex big-endian, đúng giá trị bộ đếm) |
| `nonce` trong header | 4 byte little-endian của bộ đếm; từ (word) đưa vào SHA-256 là **byte-swap** của bộ đếm |
| `ntime` khi submit | gửi lại đúng chuỗi đã nhận (hoặc `"%08x" % ntime`) |
| so sánh hash | đảo 32 byte (hiển thị big-endian) rồi so với target |

> Lưu ý: bộ đếm nonce và từ nonce trong block là **hai cách nhìn khác nhau của
> cùng 4 byte** (một bên little-endian, một bên big-endian). Nhầm chỗ này sẽ
> khiến miner tìm được share nhưng pool luôn trả `above target` — đúng lỗi đã
> gặp và sửa trong bản C++.

Các quy ước này đã được kiểm chứng bằng dữ liệu thật từ pool và mã nguồn
`ckpool`/`cpuminer-opt`.

### 6.4. Kiến trúc

```
cpp/
  sha256.h/.cpp    # SHA-256d, midstate, dispatch SHA-NI/AVX2/scalar, quét nonce
  sha256_avx2.cpp  # kernel 8 làn bằng AVX2 (biên dịch với -mavx2)
  sha256_shani.cpp # kernel SHA-NI (biên dịch với -msha -mssse3 -msse4.1)
  job.h/.cpp       # parse mining.notify, coinbase/merkle, header prefix, midstate
  stratum.h/.cpp   # client JSON-RPC qua TCP (Winsock2, buffer, backlog)
  worker.h/.cpp    # WorkerPool (std::thread, chia dải nonce, double-check share)
  miner.h/.cpp     # vòng đời session, xử lý message, submit share, thống kê
  util.h/.cpp      # hex, difficulty <-> target (256-bit), format, logging
  json.h/.cpp      # JSON parser/serializer tối giản
  main.cpp         # CLI, config JSON, --self-test, --benchmark
  tools/bench.cpp  # kiểm tra kernel + đo tốc độ
  tools/check.cpp  # in target/header để đối chiếu với bản Python
legacy/            # bản Python + test của nó, chỉ để đối chiếu
tests/fake_pool_check.py  # test đầu-cuối cho exe C++ (pool giả)
```

* Luồng chính (1 thread): giữ kết nối Stratum, dựng midstate + target, publish
  `Work` cho pool thread, nhận share và submit.
* Mỗi worker thread: quét một dải nonce riêng (mỗi dải 2^32/N), kiểm tra job
  mới sau mỗi 8192 nonce nên chuyển job gần như tức thì khi có block mới.
* Mọi share do kernel SIMD (AVX2/SHA-NI) tìm ra đều được **băm lại bằng kernel
  scalar** trước khi gửi — lỗi SIMD không thể tạo share rác.

## 7. Hiệu năng (số đo thực trên máy kiểm thử)

Máy test: Windows 11, Intel i5-8365U (4 core / 8 thread, **không có SHA-NI**,
có AVX2 + BMI2), bị giới hạn điện năng ~15 W.

| Số thread | Bản C++ (AVX2) | Bản Python (tham khảo) | Nhanh hơn |
| --- | --- | --- | --- |
| 1 | ~5.9 MH/s | ~0.36 MH/s | ~16× |
| 2 | ~9.2 MH/s | ~0.6 MH/s | ~15× |
| 4 | ~13.6 MH/s | ~0.81 MH/s | ~17× |
| 8 | ~17.7 MH/s | ~1.02 MH/s | ~17× |

* Kernel AVX2 đơn luồng đạt ~8 MH/s khi CPU được cấp đủ điện (đo bằng
  `build\bench.exe`); khi chạy đủ 8 thread, xung nhịp bị hạ nên hashrate/thread
  giảm — tổng vẫn tăng.
* CPU **không có SHA-NI** vẫn nhanh hơn Python ~17× vì nút cổ chai của Python
  là vòng lặp `for` chứ không phải hàm băm.
* Nếu CPU có AVX2, `--self-test` sẽ in `kernel avx2 (8 lanes)`; nếu có SHA-NI
  thì in `kernel sha-ni`; máy chỉ có SSE/không AVX2 vẫn chạy được bằng kernel
  scalar (chậm hơn ~5×).
* Kernel SHA-NI chạy 1 nonce mỗi chuỗi (không đan nhiều nonce) nhưng mỗi lần nén
  chỉ tốn vài lệnh `SHA256RNDS2`/`SHA256MSG1`/`SHA256MSG2`. Máy kiểm thử không
  có SHA-NI nên không có số MH/s cho kernel này; tính đúng đắn được đối chiếu
  với kernel scalar bằng Intel SDE (`sde -tgl -- .\build\bench.exe`).
* Muốn nhanh hơn nữa: dùng GPU/ASIC, hoặc thêm kernel SHA-NI cho CPU có hỗ trợ.

## 8. Pool và độ khó

* Pool solo công khai: `stratum+tcp://solo.ckpool.org:3333`
  (username = địa chỉ BTC của bạn). Pool sẽ gán difficulty rất cao
  (ví dụ 10.000) → gần như không bao giờ thấy share accepted.
* Các pool khác: dùng đúng `stratum+tcp://host:port` mà pool cung cấp và
  worker name theo hướng dẫn của pool (`<địa chỉ>.<worker>` hoặc
  `<user>.<worker>`).
* Có thể thử `--suggest-difficulty 0.001` để xin difficulty thấp; pool có thể
  bỏ qua.
* Bản này **không hỗ trợ TLS** (`stratum+ssl://`) và không hỗ trợ version
  rolling (BIP310) — job vẫn dùng `version` mà pool gửi.

## 9. Bảo mật

* Phần mềm chỉ gửi: user agent, worker name, extranonce2, ntime, nonce.
  **Không bao giờ nhập private key / seed phrase vào phần mềm đào.**
* Mật khẩu worker của pool thường là `x` và không phải mật khẩu ví.
* Hãy kiểm tra mã nguồn trước khi chạy phần mềm đào từ Internet.

## 10. Xử lý sự cố

| Hiện tượng | Nguyên nhân / cách xử lý |
| --- | --- |
| `pool refused the worker credentials` | sai username/định dạng worker; pool yêu cầu địa chỉ ví hợp lệ |
| `job arrived before the first mining.set_difficulty` | pool gửi job trước difficulty; miner tạm dùng difficulty 1, sau đó cập nhật khi pool gửi |
| `no data from pool for 300 s` | kết nối bị treo/firewall; thử `--idle-timeout` nhỏ hơn |
| `share rejected: ... stale` | job đã cũ (block mới) — bình thường, share bị trễ |
| `share rejected: low difficulty` | target của bạn không khớp difficulty pool gửi; thường do pool đổi diff giữa chừng |
| `share rejected: ... above target` với mọi share | nghi lệch byte-order (nonce/prevhash/merkle); chạy `python tests/fake_pool_check.py` |
| Không thấy share nào | difficulty pool quá cao so với hashrate CPU — hãy dùng `--self-test` để chắc chắn miner hoạt động |
| `g++ not found on PATH` | cài MinGW-w64 (WinLibs) rồi mở lại terminal |
| `build.ps1 cannot be loaded ... running scripts is disabled` | `powershell -ExecutionPolicy Bypass -File .\build.ps1` |
| `kernel scalar` thay vì `sha-ni`/`avx2` trong log | CPU không có SHA-NI/AVX2 (hoặc VM không bật) — vẫn đúng, chỉ chậm hơn |

## 11. Tham khảo

* Stratum mining protocol — Bitcoin Wiki.
* `ckpool` (stratifier/generator) — cách pool kiểm tra share và byte-order.
* `cpuminer-opt`, `cpuminer` — tham khảo cách dựng header.
* Block 125552 — vector kiểm thử SHA-256d kinh điển.

## 12. Giấy phép / miễn trừ

Mã nguồn phát hành theo [Giấy phép MIT](LICENSE).

```
Copyright (c) 2026 btcminer contributors
```

Bạn được phép dùng, sao chép, sửa đổi, gộp, công bố, phân phối, cấp phép lại và
bán bản sao của phần mềm, miễn là giữ nguyên thông báo bản quyền và giấy phép.
Phần mềm được cung cấp **nguyên trạng**, không đi kèm bảo hành dưới bất kỳ hình
thức nào. Mã nguồn chủ yếu phục vụ mục đích học tập và nghiên cứu.

Bạn tự chịu trách nhiệm về
chi phí điện, thiết bị, quy định của nơi làm việc và pháp luật địa phương khi
sử dụng.
