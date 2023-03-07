# Cipherfix

Cipherfix is a framework for finding and mitigating ciphertext side-channel leakage.
It combines dynamic binary instrumentation and dynamic taint analysis to analyze the target binaries and pinpoint potentially vulnerable code parts. Then, it uses static binary intrumentation to produce binaries hardened against ciphertext side-channels.

**Note:** This is a proof-of-concept implementation. We currently do not support the entire x86 instruction set and make some assumptions about the structure of the analyzed binaries, so it is possible that the analysis and/or instrumentation fail on certain systems or configurations.

In the following, we describe how to set up Cipherfix and its dependencies, and how to use it to harden a binary against ciphertext side-channel leakage.

If you just want to reproduce the analyzed targets from the Cipherfix paper, feel free to skip to the [Running the example targets](#running-the-example-targets) section.


## Prerequisites
The static instrumentation application and the evaluation tool are based on [.NET 6.0](https://dotnet.microsoft.com/download/dotnet/6.0), so the .NET 6.0 SDK is required for compiling.

The analysis tools all rely on [Intel Pin 3.26](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html). We assume that there is a `PIN_ROOT` environment variable that points to Pin's base directory. This can be done per session with `export PIN_ROOT=/path/to/pin`.


## Compiling
All framework modules can be compiled at once by running `./build-all.sh`.

## Usage

### Analyzing & Instrumenting a Binary
As a running example, we use a binary that computes an EdDSA signature using the WolfSSL library:
```
.../examples
  wolfssl/
    eddsa/
      app
```

#### Analysis

To run the taint and structure analysis run
```
./analyze.sh <working directory> <library path> <interesting images> <main binary> [<application arguments>]
```
Arguments:
- Working directory: Path to directory containg the application binary, e.g. `$(pwd)/examples/wolfssl/eddsa`.
- Library path: Path to needed shared libraries (for LD_LIBRARY_PATH), e.g., `$CF_WOLFSSL_DIR/lib`.
- Interesting images: List of image IDs which should be taken into consideration during analysis, e.g., `"1;4;5;6"`.  
  Whenever Pin instruments a binary (application or shared library), it assigns an *image Id*. Usually, ID 1 refers to the application itself, ID 2 and 3 refer to vDSO and the dynamic linker (which have to be ignored), and subsequent IDs to libc and the application's other dependencies (e.g. ID 4 for `libwolfssl.so.34`). The IDs can be determined by looking at the first few lines of the generated `$(pwd)/examples/wolfssl/eddsa/structure.out` file (specify only image ID `"1"` initially and then re-run).
- Main binary: Name of the application binary, e.g. `app`.
- Application arguments (optional): Arguments for the application itself, e.g. `10 perf` (run 10 iterations, do not output intermediate results).

The taint analysis may print a number of warnings and a few errors about unknown instructions. Usually, those instructions are rather obscure and can be ignored, as they do not touch secrets and thus don't need masking.

This will produce four files:
- `$(pwd)/examples/wolfssl/structure.out`: Results of the structure analysis. This file needs to be manually modified before static instrumentation (see below).
- `$(pwd)/examples/wolfssl/static-vars.out`: Static variables, needed for taint tracking.
- `$(pwd)/examples/wolfssl/taint.out`: Taint tracking results.
- `$(pwd)/examples/wolfssl/taint.out.memtrace`: Memory trace for evaluation. Only needed for leakage analysis of the instrumented binaries.

#### Static instrumentation

To statically instrument the application and its dependencies run
```
./instrument.sh <working directory> <mode> [<flags>]
```
Arguments:
- Working directory: Path to directory containing the application binary and the analysis results, e.g. `$(pwd)/examples/wolfssl/eddsa`.
- Mode: Instrumentation mode (`base`, `fast` or `enhanced`).
- Flags (optional): Instrumentation flags to specify the PRNG used for mask generation and various evaluation/debugging flags. If no flags are specified, the `rdrand` PRNG is used.

Relevant flags:
- `aesrng`: AES-based PRNG.
- `xsprng`: XorShift128+ PRNG.
- `evalmarker`: Include evaluation markers (needed to align traces of original and instrumented binaries)

Flags can be concatenated with `-`, e.g. `aesrng-evalmarker`.

On the first run, the instrumentation tool will most likely immediately exit and produce a list of heap allocation function candidates and call stacks. The following steps are difficult to automate reliably, and thus need to be done manually. For an example, see [Running the example targets](#running-the-example-targets) below.

1. Open `structure.out` in a text editor (or use `echo`-based concatenation, see example linked above).
2. Check the outputs of the static instrumentation run to identify heap (re)allocation functions and append them at the end.
   Those are both the entries that belong to `malloc`-style functions in the `.plt`-sections of the binaries and the actual allocation functions from libc (`malloc`, `calloc`, `realloc`). Allocations start with `Mm` (`malloc`) or `Mc` (`calloc`), whereas reallocations start with `Mr`, followed by the address that is output by the instrumentation tool. 
   
   The instrumentation tool automatically tries to fetch the symbol name associated with a given offset; if this fails, the symbol name may be extracted via
   ```
   objdump -d --start-address 0x<offset> --stop-address 0x<offset+1> /path/to/binary
   ```

Re-running the instrumentation tool should now produce instrumented binaries in a new `<working directory>/instr-<mode>[-<flags>]` directory, e.g.
```
.../examples/wolfssl/eddsa/
  app
  instr-base/
    app.instr
    libc.so.6.instr
    libm.so.6.instr
    libwolfssl.so.34.instr
```

The instrumented application binary is named `<main binary>.instr` and takes the same arguments as the original binary.

In the example, the instrumented binary can be run with
```
cd $(pwd)/examples/wolfssl/eddsa/instr-base/
chmod +x app.instr
./app.instr 10
```


### Running a Leakage Analysis
We offer a tool to check whether there are remaining ciphertext leakages after static instrumentation.

To run the leakage analysis, first re-instrument the binary with the `evalmarker` flag.
This will insert special marker instructions into the instrumented binary, that allow the memory trace comparison tool to align single memory writes from the original binary with memory write sequences from the instrumented binary.
The instrumented sequences then start with a `begin offset` and end with an `end offset` marker.

Then execute the following command:
```
./evaluate.sh <working directory> <instr directory> <interesting offsets> <main binary> [<application arguments>]
```
Arguments:
- Working directory: Path to directory containg the application binary, e.g. `$(pwd)/examples/wolfssl/eddsa`.
- Instr directory: Path to generated instrumentation directory, e.g., `$(pwd)/examples/wolfssl/eddsa/instr-base-evalmarker`.
- Interesting offsets: List of instruction offsets in the instrumented binaries that should be checked against their vulnerable counterparts in the original binary.  
  Format: `<image ID 1>.<begin offset 1>.<end offset 1>;<image ID 2>.<begin offset 2>.<end offset 2>;...`
- Main binary: Name of the application binary, e.g. `app`.
- Application arguments (optional): Arguments for the application itself, e.g. `3 perf`.

The resulting `<working directory>/eval-results.txt` file then contains a list of memory locations and information about observed block values (ciphertexts). Ideally, each location only has "unique" block values, else there are collisions and thus leakage.

If the comparison tool aborts early (i.e., before processing at least 98\% of all memory accesses), the instrumented trace may need some manual tweaking (the tool outputs the line number of the first detected misalignment).


## Running the example targets
In the following, we describe the steps needed to fully reproduce two different examples: MbedTLS AES (multiple rounds), and WolfSSL EdDSA (one signature).

The <examples> directory contains the test targets from the Cipherfix paper. To aid reproducibility, we offer two preconfigured Docker images:
- [uzl-its/cipherfix-examples](https://github.com/UzL-ITS/cipherfix/pkgs/container/cipherfix-examples): Contains all necessary dependencies and precompiled library binaries.
- [uzl-its/cipherfix-examples-full](https://github.com/UzL-ITS/cipherfix/pkgs/container/cipherfix-examples-full): Contains all necessary dependencies, precompiled library binaries, precompiled target binaries, and the precompiled Cipherfix framework. The image is generated by calling `/cipherfix/setup.sh` from the `uzl-its/cipherfix-examples` image.

Thus, a Docker installation and an x86 CPU (preferably AMD Zen 3) are sufficient. Both Docker images were built on an AMD Zen 3 system.

To analyze, instrument and run the examples, execute the following steps:
1. Pull and start the supplied Docker container:
   ```
   docker run -it ghcr.io/uzl-its/cipherfix-examples-full:latest
   ```
3. To analyze example `<name>` (either `mbedtls-aes` or `wolfssl-eddsa`), run
   ```
   ./analyze-<name>.sh
   ```
4. To instrument example `<name>`, run
   ```
   ./instrument-<name>.sh
   ```
   On the first run, this will produce a number of candidates for heap allocation functions, which can not be determined automatically and thus must be appended to `./cipherfix/examples/<library>/<target>/structure.out` manually (`<library>/<target>` is either `mbedtls/aes-multiround` or `wolfssl/eddsa`). Each entry consists of a function address and a type prefix (`Mm` for `malloc`, `Mc` for `calloc`, `Mr` for `realloc`).

   Appending can be done, for example, by running `echo -e "Mm ...\nMm ...\nMc ..." >> ./cipherfix/examples/<library>/<target>/structure.out`. Alternatively, `nano` is installed in the container.
   
   Allocation functions for `mbedtls-aes`:
   - `Mm`: `malloc@plt` in `app` (usually `+83a0`)
   - `Mm`: `malloc` in `libc.so.6` (usually `+22310`)
   - `Mc`: `mbedtls_calloc` in `app` (usually `+a120`)

   For example:
   ```
   Mm 0000562c6c1ce3a0
   Mm 00007fd169d9a310
   Mc 0000562c6c1d0120
   ```
   Appended with
   ```
   echo -e "Mm 0000562c6c1ce3a0\nMm 00007fd169d9a310\nMc 0000562c6c1d0120" >> cipherfix/examples/mbedtls/aes-multiround/structure.out
   ```
   
   Allocation functions for `wolfssl-eddsa`:
   - `Mm`: `malloc@plt` at low address in `app` (usually `+1200`)
   - `Mm`: `malloc` in `libc.so.6` (usually `+22310`)

   For example:
   ```
   Mm 0000559aad7e7200
   Mm 00007f39aee6d310
   ```
   Appended with
   ```
   echo -e "Mm 0000562c6c1ce3a0\nMm 00007fd169d9a310" >> cipherfix/examples/wolfssl/eddsa/structure.out
   ```
   
   After entering all allocation functions, re-run the instrumentation.
5. Finally, the original and instrumented programs for example `<name>` can be run with
   ```
   ./run-<name>.sh
   ```
   The command should print the computed ciphertexts/signatures and the required execution time of both programs, respectively.


## Replacing Framework Modules
It is possible to extend or replace the taint tracking and preprocessing modules by adding own tools that produce suitable trace files.

For building or using single modules, please use the provided `build.sh` and `run.sh` scripts in the respective subdirectories, or replace them by your own.

The existing modules are
- `structure-analysis`: Pintool to find all basic blocks and track the register and flag usage per instruction (preprocessing for static instrumentation); resulting trace file is needed for `static-instrumentation`.
- `static-variables`: Pintool to detect all static variables in the image memory itself; resulting trace file is needed for `taint-tracking`.
- `taint-tracking`: Pintool for tracking secrets (and all instructions touching them) and precisely determining stack frames and heap allocations; needs the results of `static-variables` and produces the needed trace file for `static-instrumentation`.
- `static-instrumentation`: C# static instrumentation tool to harden the binary against the ciphertext side-channel; takes as input the results from `structure-analysis` and `taint-tracking`.
- `memwrite-tracer`: Pintool to collect traces of memory writes and their contents for the hardened binary; resulting memory trace file is needed for `evaluation`.
- `evaluation`: C# leakage evaluation tool to compare and evaluate memory write traces of the uninstrumented and the hardened binary; takes as input the memory trace from `taint-tracking`, map/ignore files from `static-instrumentation` and the memory trace from `memwrite-tracer`.

To customize a module, please keep in mind that the static variable detection has to be executed before the taint tracking and that the dynamic analysis (static variables, taint tracking, structure analysis) has to be run before the static instrumentation takes place.


## Paper

For an extended description of the framework, please refer to our paper:
- Jan Wichelmann, Anna Pätschke, Luca Wilke, and Thomas Eisenbarth. 2023. **Cipherfix: Mitigating Ciphertext Side-Channel Attacks in Software**. To appear at 32nd USENIX Security Symposium (USENIX Security 2023). \[[arXiv](https://arxiv.org/abs/2210.13124)\]

For more background and a description of ciphertext side-channel attacks see
- Mengyuan Li, Luca Wilke, Jan Wichelmann, Thomas Eisenbarth, Radu Teodorescu and Yinqian Zhang. 2022. **A Systematic Look at Ciphertext Side Channels on AMD SEV-SNP**. In 2022 IEEE Symposium on Security and Privacy (S&P '22). \[[DOI](https://doi.org/10.1109/SP46214.2022.9833768)\]


## Contributing

Contributions are appreciated! Feel free to submit issues and pull requests.

## License

The project is licensed under the MIT license. For further information refer to the [LICENSE](LICENSE) file.