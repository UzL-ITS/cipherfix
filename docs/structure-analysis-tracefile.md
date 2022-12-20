# Format of the Structure Analysis Trace File
The `structure.out` file contains the results of the structure analysis. The start of each line indicates what kind of information is contained in the line. The file needs to be manually modified in order to reliably provide information about heap allocation functions before the static instrumentation takes place. 
For the first run, the static instrumentation will result output heap (re)allocation function candidates. They have to be matched to allocations (e.g., `malloc`) that have to start with `Mm` and reallocations (e.g., `realloc`) starting with `Mr`.
These entries of the form `M* <alloc-address>` have to be added to the end of the `structure.out` file.
The sections of the trace file (including the needed allocation information) are described in the following overview.

## Images
- `I`: Indicates that the following information belongs to images
- `imageStartAddress`: Absolute address of the image start 
- `imageEndAddress`: Absolute address of the image end 
- `imageName`: Image file name

## Basic Blocks
- `B`: Indicates that the following information belongs to basic blocks
- `basicBlockStartAddress`: Absolute address of the basic block start 
- `basicBlockEndAddress`: Absolute address of the basic block end 
- `hasFallthrough`: Flag whether block has fallthrough (1) or not (0)

## Instruction Data: Flag Tracking States & Register Tracking States
Instruction data is split into information for tracking the status flag states and the register usage. For each instruction, the `structure.out` file contains the information whether flags or registers are read, written or whether flag or register values have to be kept for further usages in the code. The information is given for the flags (`carry`, `parity`, `adjust`, `zero`, `sign`, `overflow`) and then the registers (`rdi`, `rsi`, `rbp`, `rsp`, `rbx`, `rdx`, `rcx`, `rax`, `r8` - `r15`, `ymm0` - `ymm15`).

- `N`: Indicates that the following information belongs to instruction data
- `instructionAddress`: Absolute address of the instruction 
- For each flag and register according to the list above:
  - Tripel of read / write / keep information:
    - `r` for read, else `-`
    - `w` for write, else `-`
    - `k` for keep, else `-`

## Register Usage Counts
- `R`: Indicates that the following information belongs to registers
- `regName`: Name of the register
- `regCount`: Register usage count (dec)
  
## System Calls
- `S`: Indicates that the following information belongs to system calls
- `syscallAddress`: Absolute address of the system call 

## (Re)Allocations
- `M*`: Indicates that the following information belongs to memory allocations
  - `Mm`: Function is an allocation function
  - `Mr`: Function is a reallocation function
- `allocationAddress`: Absolute address of the (re)allocation function 