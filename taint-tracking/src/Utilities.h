#pragma once

/* Contains helper functions */

/* INCLUDES */

#include "pin.H"
#include <string>
#include <set>

// Converts the given string into its decimal representation.
UINT64 getUint64FromStr(std::string& str);

// Contains different trace entry types for memory blocks
// Enum similar to https://github.com/Fraunhofer-AISEC/DATA/blob/master/pintool/addrtrace.cpp enum
enum struct MemoryBlockType {
    UNKNOWN = 0,
    IMAGE = 1,
    STACK = 2,
    HEAP = 3
};

enum struct AccessType {
    NONE = 0,
    SECRET = 1,
    PUBLIC = 2,
    BOTH = SECRET | PUBLIC,
};

enum struct MemoryAccessCallBackIndex {
    READ1 = 0,
    READ2 = 1,
    WRITE = 2,
    CONTROL_FLOW = 3,
};

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

// Contains metadata of memory blocks.
struct MemoryBlockData {
    UINT32 imageId;
    UINT64 offset;
    UINT64 blockId;
    UINT64 blockSize;
    UINT64 startAddress;
    UINT64 endAddress;
    MemoryBlockType blockType;

    // Address of the function this stack frame belongs to.
    // Not valid for heap/image block.
    UINT64 functionStartAddress;

    // Stores whether a heap block is secret.
    // Not valid for stack blocks.
    bool secret;

    bool active;

    // Identified secret offsets of stack blocks.
    std::set<UINT32> secretOffsets;

    // Instructions that access this heap/image block.
    // Not valid for stack blocks.
    std::set<UINT64> instructionAddresses;

public:
    // Constructor.
    MemoryBlockData(UINT32 imgId, UINT64 off, UINT64 blkId, UINT64 blkSize, UINT64 startAddr, UINT64 endAddr, MemoryBlockType blkType, UINT64 fctStartAddr, bool secr, bool act, std::set<UINT32> secOffs);
};

// Contains metadata of callstack entries.
struct CallstackEntry {
    UINT32 sourceImageId;
    UINT64 sourceImageOffset;
    UINT32 targetImageId;
    UINT64 targetImageOffset;
    ADDRINT sourceAddress;
    ADDRINT targetAddress;
    UINT64 blockId;

public:
    // Constructor
    CallstackEntry(UINT32 srcImgId, UINT64 srcImgOffset, UINT32 tgtImgId, UINT64 tgtImgOffset, ADDRINT srcAddr, ADDRINT tgtAddr, UINT64 blkId);
};

// Contains metadata of instructions.
struct InstructionData {
    UINT64 instructionAddress;
    UINT32 instructionSize;
    UINT32 imageId;
    UINT64 memoryAddress;
    UINT64 offset;

    // Performance optimization to avoid expensive block search in UpdateBlockTaintStatus.
    // Do not rely on this in Fini().
    MemoryBlockData* memBlock;

    AccessType accessType;
    
    bool isUnresolvableSegmentOrPltGotAccess;

public:
    // Constructor
    InstructionData(UINT64 insAddr, UINT32 insSize, UINT32 imgId, UINT64 memAddr, UINT64 insOffset, MemoryBlockData* memBlk, AccessType accType, bool unresolvableSegmOrPltGotAccess);
};

// Contains metadata of functions.
struct FunctionData 
{
    UINT64 startAddress;

    UINT64 maximumFrameSize;
    std::set<MemoryBlockData*> stackFrameMemoryBlocks;

    // Addresses of all instructions that access a stack frame belonging to this function, and the accessed stack offset.
    std::set<std::pair<UINT64, UINT64>> instructionsAndStackOffsets;
};

// Contains metadata of memory read and write accesses
struct AccessSecrecyData
{
    int secretReadCount;
    int secretWriteCount;
    int publicReadCount;
    int publicWriteCount;
};

// Contains metadata of syscall arguments
struct SyscallData {
    ADDRINT ip;
    UINT32 imageId;
    UINT64 offset;
    UINT32 callNumber;
    ADDRINT argCount;
    ADDRINT arg0;
    ADDRINT arg1;
    ADDRINT arg2;
    ADDRINT arg3;
    ADDRINT arg4;
    ADDRINT arg5;

public:
    // Constructor
    SyscallData(ADDRINT insPtr, UINT32 imgId, UINT64 insOffset, UINT32 callNo, ADDRINT argCnt, ADDRINT a0, ADDRINT a1, ADDRINT a2, ADDRINT a3, ADDRINT a4, ADDRINT a5);
};

#pragma pack(push, 1)
class MemoryTraceEntry {
public:
    UINT64 _offset;
    UINT32 _imageId;
    UINT16 _width;
    UINT16 _secret;
};
#pragma pack(pop)
static_assert(sizeof(MemoryTraceEntry) == 8 + 4 + 2 + 2, "Wrong size of MemoryTraceEntry struct");

class RegisterTaintStatus {
public:
    std::set<REG> ReagRegisters;
    std::set<REG> WriteRegisters;
    std::set<REG> SecretRegs;

    RegisterTaintStatus() {}
};

inline AccessType operator|(AccessType a, AccessType b)
{
    return static_cast<AccessType>(static_cast<int>(a) | static_cast<int>(b));
}

inline AccessType operator&(AccessType a, AccessType b)
{
    return static_cast<AccessType>(static_cast<int>(a) & static_cast<int>(b));
}

inline AccessType& operator |=(AccessType &a, AccessType b)
{
    a = a | b;
    return a;
}

// Utility type for using instruction/memory address pairs as keys in a map during final processing.
struct InstructionMemoryAddressPair
{
    UINT64 instructionAddress;
    UINT64 memoryAddress;

    bool operator==(const InstructionMemoryAddressPair& other) const
    {
        return instructionAddress == other.instructionAddress
            && memoryAddress == other.memoryAddress;
    }

public:
    InstructionMemoryAddressPair(UINT64 insAddress, UINT64 memAddress);
};

// Declare hash function for InstructionMemoryAddressPair
namespace std 
{
    template<>
    struct hash<InstructionMemoryAddressPair>
    {
        std::size_t operator()(const InstructionMemoryAddressPair& k) const
        {
            return hash<UINT64>()(k.instructionAddress) ^ hash<UINT64>()(k.memoryAddress);
        }
    };
}