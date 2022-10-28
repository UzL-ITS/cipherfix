# Cipherfix

Cipherfix is a framework for finding and mitigating ciphertext side-channel leakage.
It combines dynamic binary instrumentation and dynamic taint analysis to analyze the target binaries and pinpoint potentially vulnerable code parts. Then, it uses static binary intrumentation to produce binaries hardened against ciphertext side-channels.

**Note:** This is a proof-of-concept implementation. We currently do not support the entire x86 instruction set and make some assumptions about the structure of the analyzed binaries, so it is possible that the analysis and/or instrumentation fail on certain systems or configurations.

In the following, we describe how to set up Cipherfix and its dependencies, and how to use it to harden a binary against ciphertext side-channel leakage.

If you just want to reproduce the analyzed targets from the Cipherfix paper, feel free to skip to the [Running the example targets](#running-the-example-targets) section.


## Prerequisites
The static instrumentation application and the evaluation tool are based on [.NET 6.0](https://dotnet.microsoft.com/download/dotnet/6.0), so the .NET 6.0 SDK is required for compiling.

The analysis tools all rely on [Intel Pin 3.23](https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html). We assume that there is a `PIN_ROOT` environment variable that points to Pin's base directory. This can be done per session with `export PIN_ROOT=/path/to/pin`.


## Compiling
All framework modules can be compiled at once by running `./build-all.sh`.

## Usage

### Analyzing & Instrumenting a Binary
As a running example, we use our TweetNaCl example binary:
```
.../tweetnacl/
  main
  obj/
    libtnacl.so
```
`main` is our target application, which has `obj/libtnacl.so` as its dependency.

#### Analysis

To run the taint and structure analysis, run
```
./analyze.sh <working directory> <library path> <interesting images> <main binary> [<application arguments>]
```
Arguments:
- Working directory: Path to directory containg the application binary, e.g. `.../tweetnacl`.
- Library path: Path to needed shared libraries (for LD_LIBRARY_PATH), e.g., `.../tweetnacl/obj`.
- Interesting images: List of image IDs which should be taken into consideration during analysis, e.g., `"1;4;5"`.  
  Whenever Pin instruments a binary (application or shared library), it assigns an *image Id*. Usually, ID 1 refers to the application itself, ID 2 and 3 refer to vDSO and the dynamic linker (which have to be ignored), ID 4 to libc, and subsequent IDs to the application's other dependencies (e.g. ID 5 for `libtnacl.so`). The IDs can be determined by looking at the first few lines of the generated `.../tweetnacl/structure.out` file (use `"1"` initially and then re-run).
- Main binary: Name of the application binary, e.g. `main`.
- Application arguments (optional): Arguments for the application itself.

This will produce four files:
- `.../tweetnacl/structure.out`: Results of the structure analysis. This file needs to be manually modified before static instrumentation (see below).
- `.../tweetnacl/static-vars.out`: Static variables, needed for taint tracking.
- `.../tweetnacl/taint.out`: Taint tracking results.
- `.../tweetnacl/taint.out.memtrace`: Memory trace for evaluation. Only needed for leakage analysis of the instrumented binaries.

#### Static instrumentation

To statically instrument the application and its dependencies run
```
./instrument.sh <working directory> <mode> [<flags>]
```
Arguments:
- Working directory: Path to directory containing the application binary and the analysis results, e.g. `.../tweetnacl`.
- Mode: Instrumentation mode (`base`, `fast` or `enhanced`).
- Flags (optional): Instrumentation flags, only for evaluation and debugging, e.g. `evalmarker`.

On the first run, the instrumentation tool will most likely immediately exit and produce a list of heap allocation function candidates and call stacks. The following steps are difficult to automate reliably, and thus need to be done manually:
1. Open `structure.out` in a text editor.
2. Check the outputs of the static instrumentation run to identify heap (re)allocation functions and append them at the end.
   Those are both the entries that belong to `malloc`-style functions in the `.plt`-sections of the binaries and the actual allocation functions from libc (`malloc`, `realloc`). Allocations start with `Mm` whereas reallocations start with `Mr`, followed by the address that is output by the instrumentation.
   
   The symbol name for a given offset can be extracted via
   ```
   objdump -d --start-address 0x<offset> --stop-address 0x<offset+1> /path/to/binary
   ```

Re-running the instrumentation tool should now produce instrumented binaries in a new `<working directory>/instr-<mode>[-<flags>]` directory, e.g.
```
.../tweetnacl/
  main
  instr-base/
    main.instr
    libc.so.6.instr
    libtnacl.so.6.instr
  obj/
    libtnacl.so
```

The instrumented application binary is named `<main binary>.instr` and takes the same arguments as the original binary.


### Running a Leakage Analysis
We offer a simple tool to check whether there are remaining ciphertext leakages after static instrumentation.

To run the leakage analysis, first re-instrument the binary with the `evalmarker` flag.
This will insert special marker instructions into the instrumented binary, that allow the memory trace comparison tool to map single memory writes from the original binary to memory write sequences from the instrumented binary.
The instrumented sequences then start with a `begin offset` and end with an `end offset` marker.

Then execute the following command:
```
./evaluate.sh <working directory> <instr directory> <interesting offsets> <main binary> [<application arguments>]
```
Arguments:
- Working directory: Path to directory containg the application binary, e.g. `.../tweetnacl`.
- Instr directory: Path to generated instrumentation directory, e.g., `.../tweetnacl/instr-base-evalmarker`.
- Interesting offsets: List of instruction offsets in the instrumented binaries that should be checked against their vulnerable counterparts in the original binary.  
  Format: `<image ID 1>.<begin offset 1>.<end offset 1>;<image ID 2>.<begin offset 2>.<end offset 2>;...`
- Main binary: Name of the application binary, e.g. `main`.
- Application arguments (optional): Arguments for the application itself.

The resulting `<working directory>/eval-results.txt` file then contains a list of memory locations and information about observed block values (ciphertexts). Ideally, each location only has "unique" block values, else there is leakage.


## Running the example targets
The <examples> directory contains the test targets from the Cipherfix paper. To ensure reproducibility, we offer a preconfigured Docker image which contains all necessary dependencies. Thus, a Docker installation and an x86 CPU (preferably AMD Zen 3) are sufficient.

To analyze, instrument and run the examples, execute the following steps:
1. Pull and start the supplied Docker container:
   ```
   docker run -it ghcr.io/uzl-its/cipherfix-examples:latest
   ```
2. In the resulting root shell, run
   ```
   ./setup.sh
   ```
   to pull the Cipherfix Git repository and build all framework modules.
3. To analyze example `<name>` (either `tweetnacl-eddsa` or `openssl-ecdsa`), run
   ```
   ./analyze-<name>.sh
   ```
4. To instrument example `<name>`, run
   ```
   ./instrument-<name>.sh
   ```
   On the first run, this will produce a number of candidates for heap allocation functions, which can not be determined automatically and thus must be appended to `./cipherfix/examples/<name>/structure.out` manually. Each entry consists of a function address and a type prefix (`Mm` for `malloc`, `Mr` for `realloc`).
   
   Allocation functions for `tweetnacl-eddsa`:
   - `Mm`: malloc@plt` at low address in `app` (usually `+1180`)
   - `Mm`: malloc` in `libc.so.6` (usually `+22310`)

   For example:
   ```
   Mm 000055de873bc180
   Mm 00007f6f9fac9310
   ```
   
   Allocation functions for `openssl-ecdsa`:
   - `Mm`: `malloc@plt` at low address in `app` (usually `+1230`)
   - `Mm`: `CRYPTO_malloc@plt` at low address in `app` (usually `+1250`)
   - `Mm`: `malloc` in `libc.so.6` (usually `+22310`)
   - `Mm`: `CRYPTO_malloc` in `libcrypto.so.1.1` (usually `+220070`)
   - `Mr`: `CRYPTO_realloc` in `libcrypto.so.1.1` (usually `+2200c0`)

   For example:
   ```
   Mm 000055c1a9c7a230
   Mm 000055c1a9c7a250
   Mm 00007f32ba31d310
   Mm 00007f32ba89e070
   Mr 00007f32ba89e0c0
   ```
   
   After entering all allocation functions, re-run the instrumentation.
5. Finally, the original and instrumented programs for example `<name>` can be run with
   ```
   ./run-<name>.sh
   ```


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
- Jan Wichelmann, Anna Pätschke, Luca Wilke, and Thomas Eisenbarth. 2022. **Cipherfix: Mitigating Ciphertext Side-Channel Attacks in Software**. [arXiv](https://arxiv.org/abs/2210.13124)

For more background and a description of ciphertext side-channel attacks see
- Mengyuan Li, Luca Wilke, Jan Wichelmann, Thomas Eisenbarth, Radu Teodorescu and Yinqian Zhang. 2022. **A Systematic Look at Ciphertext Side Channels on AMD SEV-SNP**. In 2022 IEEE Symposium on Security and Privacy (S&P '22). ([DOI](https://doi.org/10.1109/SP46214.2022.9833768))


## Contributing

Contributions are appreciated! Feel free to submit issues and pull requests.

## License

The project is licensed under the MIT license. For further information refer to the [LICENSE](LICENSE) file.