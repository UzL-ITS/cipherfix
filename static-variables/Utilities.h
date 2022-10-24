#pragma once

/* Contains helper functions */

/* INCLUDES */

#include "pin.H"
#include <string>

// Converts the given string into its decimal representation.
UINT64 getUint64FromStr(std::string& str);

// Contains metadata of loaded images.
struct ImageData {
    UINT32 imageId;
    UINT64 imageSize;
    std::string imageName;
    ADDRINT imageStartAddress;
    ADDRINT imageEndAddress;

public:
    // Constructor.
    ImageData(UINT32 imgId, UINT64 imgSize, std::string imgName, ADDRINT imgStartAddr, ADDRINT imgEndAddr);
};

// Contains metadata of all memory accesses
struct MemoryReadWrite {
    BOOL isWrite;
    UINT32 size;
    UINT64 instructionAddress;
    UINT64 memoryAddress;

public:
    // Constructor.
    MemoryReadWrite(BOOL isW, UINT32 accessSize, UINT64 insAddr, UINT64 memAddr);
};

// Contains metadata of image memory accesses only
struct ImageMemoryAccess {
    BOOL isWrite;
    UINT32 size;
    UINT32 instructionImageId;
    UINT64 instructionRelativeAddress;
    UINT32 memoryImageId;
    UINT64 memoryRelativeAddress;

public:
    // Constructor.
    ImageMemoryAccess(BOOL isW, UINT32 accessSize, UINT32 insImgId, UINT64 insRelAddr, UINT32 memImgId, UINT64 memRelAddr);
};

// Contains metadata of image memory chunks
struct ImageChunkData {
public:
    int arrayLength;
    int* hitCounts;

    // Constructor.
    ImageChunkData(int length);
};

//
struct ImageMemoryBlockRecord {
    int imageId;
    int offset;
    int size;

public:
    // Constructor.
    ImageMemoryBlockRecord(int id, int off, int sz);
};


// Contains metadata of memory blocks.
struct MemoryBlockData {
    UINT32 imageId;
    UINT64 offset;
    UINT64 blockId;
    UINT64 blockSize;
    UINT64 startAddress;
    UINT64 endAddress;

public:
    // Constructor.
    MemoryBlockData(UINT32 imgId, UINT64 off, UINT64 blkId, UINT64 blkSize, UINT64 startAddr, UINT64 endAddr);
};

// Contains metadata of instructions.
struct InstructionData {
    UINT64 instructionAddress;
    UINT32 instructionSize;
    UINT32 imageId;
    UINT64 memoryAddress;
    UINT8 instructionType; // holds value of entryType
    UINT64 offset;
    UINT64 memAddrBlockId;

public:
    // Constructor
    InstructionData(UINT64 insAddr, UINT32 insSize, UINT32 imgId, UINT64 memAddr, UINT8 type, UINT64 insOffset, UINT64 memAddrBlkId);
};