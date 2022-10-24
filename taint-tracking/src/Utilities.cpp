
/* INCLUDES */

#include "Utilities.h"
#include <algorithm>
#include <cctype>


/* FUNCTIONS */
UINT64 getUint64FromStr(std::string& str) {
    const char *nbstr = str.c_str();
    auto intFromStr = (uint64_t) strtoull(nbstr, nullptr, 16);

    return intFromStr;
}

/* DATA */
MemoryBlockData::MemoryBlockData(UINT32 imgId, UINT64 off, UINT64 blkId, UINT64 blkSize, UINT64 startAddr, UINT64 endAddr, MemoryBlockType blkType, UINT64 fctStartAddr, bool secr, bool act, std::set<UINT32> secOffs) {
    imageId = imgId;
    offset = off;
    blockId = blkId;
    blockSize = blkSize;
    startAddress = startAddr;
    endAddress = endAddr;
    blockType = blkType;
    functionStartAddress = fctStartAddr;
    secret = secr;
    active = act;
    secretOffsets = secOffs;
}

CallstackEntry::CallstackEntry(UINT32 srcImgId, UINT64 srcImgOffset, UINT32 tgtImgId, UINT64 tgtImgOffset, ADDRINT srcAddr, ADDRINT tgtAddr, UINT64 blkId) {
    sourceImageId = srcImgId;
    sourceImageOffset = srcImgOffset;
    targetImageId = tgtImgId;
    targetImageOffset = tgtImgOffset;
    sourceAddress = srcAddr;
    targetAddress = tgtAddr;
    blockId = blkId;
}

ImageData::ImageData(UINT32 imgId, UINT64 imgSize, std::string imgName, ADDRINT imgStartAddr, ADDRINT imgEndAddr) {
    imageId = imgId;
    imageSize = imgSize;
    imageName = imgName;
    imageStartAddress = imgStartAddr;
    imageEndAddress = imgEndAddr;
}

InstructionData::InstructionData(UINT64 insAddr, UINT32 insSize, UINT32 imgId, UINT64 memAddr, UINT64 insOffset, MemoryBlockData* memBlk, AccessType accType, bool unresolvableSegmOrPltGotAccess) {
    instructionAddress = insAddr;
    instructionSize = insSize;
    imageId = imgId;
    memoryAddress = memAddr;
    offset = insOffset;
    memBlock = memBlk;
    accessType = accType;
    isUnresolvableSegmentOrPltGotAccess = unresolvableSegmOrPltGotAccess;
}

SyscallData::SyscallData(ADDRINT insPtr, UINT32 imgId, UINT64 insOffset, UINT32 callNo, ADDRINT argCnt, ADDRINT a0, ADDRINT a1, ADDRINT a2, ADDRINT a3, ADDRINT a4, ADDRINT a5) {
    ip = insPtr;
    imageId = imgId;
    offset = insOffset;
    callNumber = callNo;
    argCount = argCnt;
    arg0 = a0;
    arg1 = a1;
    arg2 = a2;
    arg3 = a3;
    arg4 = a4;
    arg5 = a5;
}

InstructionMemoryAddressPair::InstructionMemoryAddressPair(UINT64 insAddress, UINT64 memAddress)
{
    instructionAddress = insAddress;
    memoryAddress = memAddress;
}
