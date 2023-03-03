#include "pin.H"
#include "Utilities.h"
#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <unistd.h>
#include <string>

/* ================================================================== */
// Global variables
/* ================================================================== */
std::ostream* out = &std::cerr;

// The resulting trace file.
std::ofstream TraceFile;

// Data of loaded images.
std::vector<ImageData*> images;

// Data of all memory accesses.
std::vector<MemoryReadWrite*> memReadWriteAccesses;

// Data of all image memory accesses.
std::vector<ImageMemoryAccess*> imageMemoryAccesses;

// The granularity of the image memory block analysis in bytes.
int imageMemoryBlockChunkSize = 1;

// The minimum number of unused chunks between to different image memory blocks.
int imageMemoryBlockSpaceThreshold = 4;

// Interesting images whose memory blocks are part of the analysis
std::vector<int> interestingImages;

// Insert entries into the set of memory block records
// ordered by image id then by offset then by size
// This allows to find overlaps later on
struct ImageMemoryBlockRecordCmp {
    bool operator()(const ImageMemoryBlockRecord *b1, const ImageMemoryBlockRecord *b2) const {
        if (b1->imageId != b2->imageId) {
            return b1->imageId < b2->imageId;
        } else if (b1->offset != b2->offset) {
            return b1->offset < b2->offset;
        } else {
            return b1->size < b2->size;
        }
    }
};

// Set of image memory blocks that have been accessed
std::set<ImageMemoryBlockRecord*, ImageMemoryBlockRecordCmp> interestingImageMemoryBlocks;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "static-variables.out", "specify file name for static variables pintool output");

KNOB<std::string> KnobInterestingImageList(KNOB_MODE_WRITEONCE, "pintool", "i", "1;4", "specify interesting image IDs");

/* ===================================================================== */
// Utilities
/* ===================================================================== */
INT32 Usage() {
    std::cerr << "This tool prints out the static variables" << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

// Handles an internal exception of this trace tool.
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO *exceptionInfo, PHYSICAL_CONTEXT *physicalContext, VOID *v) {
    // Output exception data
    std::cerr << "[ERROR] Internal exception: " << PIN_ExceptionToString(exceptionInfo) << std::endl;
    return EHR_UNHANDLED;
}

VOID Fini(INT32 code, VOID* v);
/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

UINT32 FindImage(UINT64 address) {
    for (const auto &img: images) {
        if (img->imageStartAddress <= address && address <= img->imageEndAddress) {
            return img->imageId;
        }
    }
    return 0;
}

UINT64 FindImageStart(UINT32 imageId) {
    for (const auto &img: images) {
        if (img->imageId == imageId) {
            return img->imageStartAddress;
        }
    }
    return 0;
}

VOID InsertMemoryReadWriteEntry(ADDRINT instructionAddress, ADDRINT memoryAddress, UINT32 size, BOOL isWrite) {
    int imgId = (int)FindImage(memoryAddress); 
    BOOL found = false;
    for (const auto& img: interestingImages)
    {
        if (img == imgId)
        {
            found = true;
            break;
        }
    }    

    if (!found)
        return;

    memReadWriteAccesses.push_back(new MemoryReadWrite(isWrite, size, instructionAddress, memoryAddress));
}

VOID GetImageMemoryAccesses() {
    for (const auto &acc: memReadWriteAccesses) {
        UINT32 instructionImageId = FindImage(acc->instructionAddress);
        if (instructionImageId == 0) {
            std::cerr << "[ERROR] No image id found for instruction address " << std::hex << acc->instructionAddress << std::endl;
        }

        UINT64 instructionImageStartAddress = FindImageStart(instructionImageId);
        if (instructionImageStartAddress == 0) {
            std::cerr << "[ERROR] Invalid image start address for image " << std::dec << instructionImageId << std::endl;
        }
        UINT64 instructionRelativeAddress = acc->instructionAddress - instructionImageStartAddress;

        // If we find an accessed image, the memory access has been to the image area (not stack or heap)
        UINT32 accessedImageId = FindImage(acc->memoryAddress);
        if (accessedImageId > 0) {
            UINT64 accessedImageStartAddress = FindImageStart(accessedImageId);
            if (accessedImageStartAddress == 0) {
                std::cerr << "[ERROR] Invalid image start address for accessed image " << std::dec << accessedImageId << std::endl;
            }
            UINT64 memoryRelativeAddress = acc->memoryAddress - accessedImageStartAddress;

            imageMemoryAccesses.push_back(new ImageMemoryAccess(
                    acc->isWrite, acc->size, instructionImageId, instructionRelativeAddress, accessedImageId, memoryRelativeAddress
            ));
        }
    }
}

/*
    * Steps:
    *   1. Count data read/write accesses to each chunk in image memory.
    *   2. Identify and analyze blocks in image memory.
*/
VOID FindImageMemoryBlocks() {
    // Prepare image data
    std::unordered_map<UINT32, ImageChunkData*> imageMemoryData;
    int imageMemoryChunkMaxHits = 0;

    for (const auto &img: images) {
        // Allocate empty array with hit counters
        int length = ((int)(img->imageEndAddress - img->imageStartAddress) + imageMemoryBlockChunkSize - 1) / imageMemoryBlockChunkSize;
        ImageChunkData *imageChunk = new ImageChunkData(length);
        imageMemoryData.insert({img->imageId, imageChunk});
    }

    // Iterate trace entries and build image memory hit counters
    for (const auto &acc: imageMemoryAccesses) {
        // Update hit counters
        auto search = imageMemoryData.find(acc->memoryImageId);
        if (search != imageMemoryData.end()) {
            auto imageChunkData = search->second;
            int firstChunkOffset = (int)(acc->memoryRelativeAddress / imageMemoryBlockChunkSize);
            int lastChunkOffset = (int)((acc->memoryRelativeAddress + acc->size - 1) / imageMemoryBlockChunkSize);

            for (int i = firstChunkOffset; i <= lastChunkOffset; ++i) {
                ++imageChunkData->hitCounts[i];

                if(imageChunkData->hitCounts[i] > imageMemoryChunkMaxHits) {
                    imageMemoryChunkMaxHits = imageChunkData->hitCounts[i];
                }
            }
        }
    }

    // Identify interesting blocks in image memory
    // Indexed by image ID
    for (const auto& pair: imageMemoryData) {
        UINT32 imageId = pair.first;
        ImageChunkData *imageChunkData = pair.second;
        int i = 0;
        while (true) {
            // Find next block begin
            while(i < imageChunkData->arrayLength && imageChunkData->hitCounts[i] == 0) {
                ++i;
            }

            // Reached end of chunk list? -> no block found, we are done
            if(i == imageChunkData->arrayLength) {
                break;
            }

            // i now points to a block with hit count > 0
            // Find end of block by looking for consecutive chunks with hit count == 0
            int blockBegin = i;
            int lastNonEmptyChunk = i;
            int emptyChunksCount = 0;
            while(i < imageChunkData->arrayLength) {
                if(imageChunkData->hitCounts[i] == 0) {
                    ++emptyChunksCount;
                    if (emptyChunksCount >= imageMemoryBlockSpaceThreshold) {
                        break;
                    }
                } else {
                    lastNonEmptyChunk = i;
                }

                ++i;
            }

            // Record block
            // - Overlaps will be handled later
            // - Duplicates will be ignored by the underlying hash set
            int blockChunkCount = lastNonEmptyChunk - blockBegin + 1;
            auto imageMemoryBlockRecord = new ImageMemoryBlockRecord(imageId, blockBegin * imageMemoryBlockChunkSize, blockChunkCount * imageMemoryBlockChunkSize);
            interestingImageMemoryBlocks.insert(imageMemoryBlockRecord);

            // i now points to a chunk with hit count == 0 (or to the chunk list end)
        }
    }

    // Merge overlapping image memory blocks
    std::vector<ImageMemoryBlockRecord*> mergedImageMemoryBlocks;
    int currentImageId = -1;     // -1 := null
    int currentBlockStart = -1;  // -1 := null
    int currentBlockEnd = 0; // This variable is invalid when currentBlockStart == null

    for (const auto &block: interestingImageMemoryBlocks) {
        // Next image?
        if (currentImageId == -1 || block->imageId != currentImageId) {
            // Store last active block
            if(currentImageId != -1 && currentBlockStart != -1)
                mergedImageMemoryBlocks.push_back(new ImageMemoryBlockRecord(
                        currentImageId, currentBlockStart, currentBlockEnd - currentBlockStart
                ));

            // Reset state
            currentImageId = block->imageId;
            currentBlockStart = -1;
        }

        // If there is new active block, start a new one
        // Else, check for overlap
        if (currentBlockStart == -1) {
            currentBlockStart = block->offset;
            currentBlockEnd = block->offset + block->size;
        } else {
            if(block->offset >= currentBlockEnd) {
                // New block, store the old one
                mergedImageMemoryBlocks.push_back(new ImageMemoryBlockRecord(currentImageId, currentBlockStart, currentBlockEnd - currentBlockStart));

                currentBlockStart = block->offset;
                currentBlockEnd = block->offset + block->size;
            } else {
                // Overlap; extend the current block, if necessary
                // The blocks are ordered by offset, so the new block can not start before the current one; we thus only need to adjust the block end
                currentBlockEnd = std::max(currentBlockEnd, block->offset + block->size);
            }
        }
    }

    // Store last image block
    if(currentImageId != -1 && currentBlockStart != -1) {
        mergedImageMemoryBlocks.push_back(
                new ImageMemoryBlockRecord(currentImageId, currentBlockStart, currentBlockEnd - currentBlockStart));
    }

    // Print the image memory access information
    TraceFile << std::dec << mergedImageMemoryBlocks.size() << std::endl;
    for (const auto &block: mergedImageMemoryBlocks) {
        TraceFile << std::dec << block->imageId << "\t";
        TraceFile << std::hex << std::setw(8) << std::setfill('0') << block->offset << "\t";
        TraceFile << std::dec << block->size << std::endl;
    }
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


VOID InstrumentTrace(TRACE trace, VOID* v) {
    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        // Run through instructions
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
            // Ignore irrelevant instructions:

            // Ignore everything that uses segment registers (shouldn't be used by relevant software parts)
            if(INS_SegmentPrefix(ins))
                continue;

            // Ignore frequent and uninteresting instructions to reduce instrumentation time
            OPCODE opc = INS_Opcode(ins);
            if(opc >= XED_ICLASS_PUSH && opc <= XED_ICLASS_PUSHFQ)
                continue;
            if(opc >= XED_ICLASS_POP && opc <= XED_ICLASS_POPFQ)
                continue;
            if(opc == XED_ICLASS_LEA)
                continue;

            // Ignore control flow instructions
            if(INS_IsCall(ins) && INS_IsControlFlow(ins))
                continue;
            if(INS_IsBranch(ins) && INS_IsControlFlow(ins))
                continue;
            if(INS_IsRet(ins) && INS_IsControlFlow(ins))
                continue;

            // Find the current image id
            PIN_LockClient();
            IMG img = IMG_FindByAddress(INS_Address(ins));
            PIN_UnlockClient();
            int imageId = IMG_Id(img);
            BOOL interesting = false;

            // Filter for interesting images
            // HINT: give them as input for Knob values
            if (std::find(interestingImages.begin(), interestingImages.end(), imageId) != interestingImages.end()) {
                interesting = true;
            }

            if (!interesting)
                continue;

            // Trace instructions with memory reads
            if (INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins)) {
                // Add read to set of reads for block
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
                                         IARG_INST_PTR,
                                         IARG_MEMORYREAD_EA,
                                         IARG_MEMORYREAD_SIZE,
                                         IARG_BOOL, false,
                                         IARG_END);
            }

            // Trace instructions with second memory read operand
            if (INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins)) {
                // Add read to set of reads for block
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
                                         IARG_INST_PTR,
                                         IARG_MEMORYREAD2_EA,
                                         IARG_MEMORYREAD_SIZE,
                                         IARG_BOOL, false,
                                         IARG_END);
            }

            // Trace instructions with memory writes
            if (INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins)) {
                // Add write to set of writes for block
                INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
                                         IARG_INST_PTR,
                                         IARG_MEMORYWRITE_EA,
                                         IARG_MEMORYWRITE_SIZE,
                                         IARG_BOOL, true,
                                         IARG_END);
            }
        }
    }
}


VOID InstrumentImage(IMG img, VOID* v) {
    // Retrieve image name
    std::string imageName = IMG_Name(img);

    // Retrieve image memory offsets and id
    UINT64 imageStart = IMG_LowAddress(img);
    UINT64 imageEnd = 0;
    UINT32 imageId = IMG_Id(img);

    for (size_t i = 0; i < IMG_NumRegions(img); ++i) {
        if (IMG_RegionHighAddress(img, i) > imageEnd) {
            imageEnd = IMG_RegionHighAddress(img, i) + 1;
        }
    }

    UINT64 imageSize = imageEnd - imageStart;

    images.push_back(new ImageData(imageId, imageSize, imageName, imageStart, imageEnd));
}

VOID Fini(INT32 code, VOID* v) {
    // Print the image information
    TraceFile << std::dec << images.size() << std::endl;
    for (const auto &img: images) {
        TraceFile << img->imageId << "\t";
        TraceFile << std::hex << img->imageSize << "\t";
        TraceFile << 0 << "\t";
        TraceFile << img->imageName << std::endl;;
    }

    GetImageMemoryAccesses();

    FindImageMemoryBlocks();

    // Close the trace file.
    TraceFile.close();
}


int main(int argc, char* argv[]) {

    /*
     * In pintool-speech, the static variables are blocks in image memory.
     * Therefore, static variables are also called "image blocks" in this implementation.
    */

    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) {
        return Usage();
    }

    // Handle internal exceptions (for debugging)
    PIN_AddInternalExceptionHandler(HandlePinToolException, nullptr);

    std::string fileName = KnobOutputFile.Value();
    if (!fileName.empty()) {
        out = new std::ofstream(fileName.c_str());
    }

    // Split the list of interesting images
    std::stringstream ss(KnobInterestingImageList);
    std::string item;
    while (std::getline(ss, item, ';')) {
        if (!item.empty()) {
            interestingImages.push_back(atoi(item.c_str()));
        }
    }

    // Register function to be called to instrument traces
    TRACE_AddInstrumentFunction(InstrumentTrace, nullptr);

    // Register Image to be called to instrument images.
    IMG_AddInstrumentFunction(InstrumentImage, nullptr);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, nullptr);

    std::cerr << "==============================================================" << std::endl;
    std::cerr << "This application is instrumented by static variable detection" << std::endl;
    if (!KnobOutputFile.Value().empty()) {
        std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
    }
    std::cerr << "==============================================================" << std::endl;

    // Open the trace file
    TraceFile.open(KnobOutputFile.Value().c_str());

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}