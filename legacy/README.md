# legacy/ — bản Python tham khảo

Đây là bản Python đầu tiên của dự án, giữ lại để **tham khảo/đối chiếu**, không
phải bản chính. Bản chính là C++ trong `cpp/` (xem `README.md` ở thư mục gốc).

Nội dung:

```
btcminer/            # package Python (miner, job, stratum, worker, util, cli)
run.py               # entry point
requirements.txt     # không cần gì ngoài thư viện chuẩn (chỉ dùng khi build exe)
btcminer_py.spec     # spec PyInstaller
btcminer_py.exe      # bản đóng gói sẵn (PyInstaller one-file, ~9 MB)
tests/               # unittest của bản Python + check_cpp.py (đối chiếu với C++)
```

## Chạy bản Python

```powershell
# từ thư mục legacy/
python run.py --self-test
python run.py --benchmark 15
python run.py -o stratum+tcp://solo.ckpool.org:3333 `
              -u <DIA_CHI_BTC>.cpu1 -p x -t 4

# hoặc dùng exe đóng gói sẵn
.\btcminer_py.exe --version
```

## Chạy test của bản Python

```powershell
# từ thư mục legacy/
python -m unittest discover -v
```

## Đối chiếu target/header với bản C++

```powershell
# từ thư mục legacy/ (PYTHONPATH để import được package btcminer)
$env:PYTHONPATH = (Get-Location).Path
python tests\check_cpp.py                       # in target + header theo bản Python
..\build\check.exe                              # in cùng bộ số theo bản C++ (build.ps1 -Tools)
```

Khác biệt duy nhất đã biết: bản Python tính `difficulty -> target` bằng float nên
vài bit thấp bị lệch; bản C++ dùng phép chia số nguyên 256-bit nên chính xác
tuyệt đối.

## Build lại exe Python (không bắt buộc)

```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --console --name btcminer_py --clean --noconfirm run.py
```

Lưu ý: bản Python chậm hơn bản C++ khoảng **17 lần** (~1 MH/s so với ~17 MH/s
trên i5-8365U). Chỉ dùng để học giao thức/so sánh.
