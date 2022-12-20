# Format of Taint Analysis Output Files
The `taint.out` file contains an overview of the different taint analysis results. 
In the following, the different sections of the trace file are described.

## Images
- `imageCount`: Number of image files (dec)
- `imageCount` times:
  - `imageId`: Image file ID
  - `imageSize`: Total size of the image file (hex)
  - `imageName`: Image file name
  - `imageStartAddress`: Absolute address of the image start 
  - `imageEndAddress`: Absolute address of the image end 

## Stack Frames
- `stackBlockCount`: Number of stack memory blocks (dec)
- `stackBlockCount` times: 
  - `functionImageId`: ID of the image containing the function
  - `functionOffset`: Offset of the function start in the image (hex)
  - `maxFrameSize`: Maximal stack frame size of all seen executions of this function (hex)
  - `secOffCount`: Number of secret offsets of the stack frame (dec)
  - `secOffCount` times: 
    - `secretOffset`: Secret stack frame offset (hex)

## Heap Objects and Static Variables
- `nonStackBlockCount`: Number of non-stack memory blocks (number of heap objects and static variables) (dec)
- `nonStackBlockCount` times: 
  - `blockImageId`: ID of the image containing the memory block
  - `blockOffset`: Offset of the block start in the image (hex)
  - `blockId`: ID of the memory block (dec)
  - `blockSize`: Size of the memory block (hex)
  - `blockStartAddress`: Absolute address of the memory block start
  - `blockEndAddress`: Absolute address of the memory block end
  - `blockType`: Type of the memory block (1 - static variable; 3 - heap)
  - `secret`: Flag whether block is secret (1) or not (0)
  - `active`: Flag whether block is active (1) or not (0)

## Callstack Information
- `callstackEntryCount`: Number of callstack entries for heap allocations
- `callstackEntryCount` times: 
  - `sourceImageId`: ID of the source image
  - `sourceImageOffset`: Offset of the call / jump origin (hex)
  - `targetImageId`: ID of the target image
  - `targetImageOffset`: Offset of the jump target (hex)
  - `sourceAddress`: Absolute address of the origin
  - `targetAddress`: Absolute address of the target
  - `blockId`: ID of the allocated block for which we need the allocation tracking (dec)

## Instructions
- `instructionCount`: Number of instructions that have to be safeguarded (dec)
- `instructionCount` times:
  - `instructionAddress`: Absolute address of the instruction
  - `insImageId`: ID of the image containing the instruction
  - `insOffset`: Offset of the instruction in image memory (hex)
  - `insSize`: Size of the instruction (hex)
  - `accessType`: Memory access type of the instruction (1 - secret; 2 - public; 3 - both)