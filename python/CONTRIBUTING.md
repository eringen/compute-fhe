# Developing the Python bindings

The package is a separate CMake project so Python dependencies remain optional
for C++ consumers. Install OpenFHE and this checkout's ComputeFHE shared library
first, then use `pip install -e ./python` from the repository root. CMake locates
the libraries through their installed package configuration files.

For a non-system installation:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/prefix -DCMAKE_INSTALL_PREFIX=/path/to/prefix
cmake --build build --target computefhe -j 4
cmake --install build
CMAKE_PREFIX_PATH=/path/to/prefix python -m pip install -e ./python
COMPUTEFHE_TEST_CRYPTO=1 python -m unittest discover -s python/tests -v
python python/examples/quickstart.py --simulation
```

Rebuild and reinstall the extension after changing C++ bindings. To test source
and wheel packaging, install `build` and run `python -m build python`.

The suite uses the actual native simulator, including exhaustive four-bit
arithmetic on both ALUs. Set `COMPUTEFHE_TEST_CRYPTO=1` to include real TOY
cryptography tests for arithmetic, signed division, selection, vectors, and
fixed-point operations. TOY parameters are only appropriate for tests.

Keep decryption explicit and preserve context ownership checks. The backend's
single global context requires operations to run in the creating thread; the
bindings retain the GIL. Tests must not replace native FHE with a Python mock.

Initial scope covers local client and simulator contexts. Server key exchange,
ciphertext serialization, fixed-point division, and the complete low-level ALU
API are not yet exposed. These need separate API and correctness reviews.
