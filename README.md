# Three Round Threshold ECDSA based  Threshold CL Encryption

This project provides the proof-of-concept implementation for the [Three-Round (Robust) Threshold ECDSA from Threshold CL Encryption](https://dl.acm.org/doi/10.1007/978-981-96-9095-4_12), and includes two versions corresponding to different security properties of threshold ECDSA signature protocols:

- The **`main`** branch implements the **TECDSA-Normal** protocol.

- The **`robust-tecdsa`** branch implements the **TECDSA-Robust** protocol.

## Build & Run

This project uses Docker for cross-compilation, providing a reproducible build environment and complete toolchain isolation.

**Build Steps**

```shell
git clone https://github.com/Jiangjiang-jiang/Three-Round-Multiparty-ECDSA.git
cd ./Three-Round-Multiparty-ECDSA
chmod +x build.sh
bash build.sh
```

After the build completes, the executable will be located at `./build/Three-Round-Multiparty-ECDSA` with specified parties number $n$ and threshold value $t$, which can be configured in `src/main.cpp`.



