
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
ImageData::ImageData(UINT32 imgId, UINT64 imgSize, std::string imgName, ADDRINT imgStartAddr, ADDRINT imgEndAddr) {
    imageId = imgId;
    imageSize = imgSize;
    imageName = imgName;
    imageStartAddress = imgStartAddr;
    imageEndAddress = imgEndAddr;
}

MemoryReadWrite::MemoryReadWrite(BOOL isW, UINT32 accessSize, UINT64 insAddr, UINT64 memAddr) {
    isWrite = isW;
    size = accessSize;
    instructionAddress = insAddr;
    memoryAddress = memAddr;
}

ImageMemoryAccess::ImageMemoryAccess(BOOL isW, UINT32 accessSize, UINT32 insImgId, UINT64 insRelAddr, UINT32 memImgId, UINT64 memRelAddr) {
    isWrite = isW;
    size = accessSize;
    instructionImageId = insImgId;
    instructionRelativeAddress = insRelAddr;
    memoryImageId = memImgId;
    memoryRelativeAddress = memRelAddr;
}

ImageChunkData::ImageChunkData(int length) {
    arrayLength = length;
    hitCounts = new int[length];
}

ImageMemoryBlockRecord::ImageMemoryBlockRecord(int id, int off, int sz) {
    imageId = id;
    offset = off;
    size = sz;
}


MemoryBlockData::MemoryBlockData(UINT32 imgId, UINT64 off, UINT64 blkId, UINT64 blkSize, UINT64 startAddr, UINT64 endAddr) {
    imageId = imgId;
    offset = off;
    blockId = blkId;
    blockSize = blkSize;
    startAddress = startAddr;
    endAddress = endAddr;
}

InstructionData::InstructionData(UINT64 insAddr, UINT32 insSize, UINT32 imgId, UINT64 memAddr, UINT8 type, UINT64 insOffset, UINT64 memAddrBlkId) {
    instructionAddress = insAddr;
    instructionSize = insSize;
    imageId = imgId;
    memoryAddress = memAddr;
    instructionType = type;
    offset = insOffset;
    memAddrBlockId = memAddrBlkId;
}
