# legacy/ — Python reference implementation

This is the original Python version of the project, kept for **reference and
cross-checking**. It is not the primary implementation — that is the C++ code in
`../cpp/` (see the root [README](../README.md)).

Contents:

```
btcminer/            # Python package (miner, job, stratum, worker, util, cli)
run.py               # entry point
requirements.txt     # nothing beyond the standard library (only needed to build the exe)
btcminer_py.spec     # PyInstaller spec
btcminer_py.exe      # prebuilt bundle (PyInstaller one-file, ~9 MB)
tests/               # Python unittests + check_cpp.py (diff against the C++ build)
```

## Running the Python version

```powershell
# from the legacy/ directory
python run.py --self-test
python run.py --benchmark 15
python run.py -o stratum+tcp://solo.ckpool.org:3333 `
              -u <BTC_ADDRESS>.cpu1 -p x -t 4

# or use the prebuilt executable
.\btcminer_py.exe --version
```

## Running the Python tests

```powershell
# from the legacy/ directory
python -m unittest discover -v
```

## Cross-checking target/header math against C++

```powershell
# from the legacy/ directory (PYTHONPATH so the btcminer package can be imported)
$env:PYTHONPATH = (Get-Location).Path
python tests\check_cpp.py                       # prints target + header from Python
..\build\check.exe                              # prints the same values from C++ (build.ps1 -Tools)
```

Known difference: the Python version computes `difficulty -> target` with
floating point, so a few low bits differ; the C++ version uses exact 256-bit
integer division and therefore matches `floor(0xFFFF * 2^208 / difficulty)`
exactly.

## Rebuilding the Python executable (optional)

```powershell
python -m pip install pyinstaller
python -m PyInstaller --onefile --console --name btcminer_py --clean --noconfirm run.py
```

Note: the Python version is about **17× slower** than the C++ one (~1 MH/s
versus ~17 MH/s on an i5-8365U). It is kept for learning the protocol and for
comparison only.
