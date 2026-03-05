# Three-Round Multiparty ECDSA

This repository provides a proof-of-concept implementation of three-round threshold ECDSA based on threshold CL encryption.

## Branches

- `main`: TECDSA-Normal
- `robust-tecdsa`: TECDSA-Robust

## Dependency Pinning

Current vendored dependency in this workspace:

- `bicycl`: local snapshot under `include/bicycl`

## Building

```bash
cmake -S . -B build
cmake --build build -j
```

## Running

```bash
./build/Three-Round-Multiparty-ECDSA
```

Default runtime parameters are currently set in `apps/cli/main.cpp`:

- party count `n = 5`
- threshold `t = 4`

## Testing

```bash
ctest --test-dir build --output-on-failure
```

## Quality Gates

```bash
cmake -S . -B build-werror -DTRECDSA_WARNINGS_AS_ERRORS=ON
cmake --build build-werror -j
ctest --test-dir build-werror --output-on-failure

cmake -S . -B build-asan -DTRECDSA_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Docker (Optional)

```bash
bash build.sh
```

## License

This project is licensed under the MIT License. See `LICENSE`.
