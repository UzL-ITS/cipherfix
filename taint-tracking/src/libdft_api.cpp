/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "libdft_api.h"
#include "branch_pred.h"
#include "debug.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "Utilities.h"
#include <unistd.h>
#include "ins_helper.h"
#include "log.h"

#include <fstream>
#include <iostream>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <stack>
#include <sys/resource.h>

 // HACK for differing namespaces on Windows
#if _WIN32
#define unordered_set tr1::unordered_set
#define unordered_map tr1::unordered_map
#endif


 /* GLOBAL VARIABLES */

 // The resulting trace file.
std::ofstream TraceFile;

// The file with static variables (in Pin-speech called "image memory blocks") from static variable detection
std::ifstream infile;

// Have read system calls as taint source
BOOL enableReadSyscallSource = false;

// Track system calls for mitigation
BOOL enableTrackSyscalls = false;

// Track register contents for taint
BOOL enableTrackTaintedRegs = false;

// Enable memory access tracing.
BOOL enableMemoryAccessTrace = true;

// Enable memory access secrecy tracking
BOOL enableAccessSecrecyTracking = true;
std::map<ADDRINT, AccessSecrecyData*> insAddrToAccessInfoMap;
ADDRINT currentReadAccessAddress;
ADDRINT currentWriteAccessAddress;

// Track instruction info regarding register taint state
std::map<UINT64, RegisterTaintStatus> insAddrToRegTaintStatusMap;

// Output the results
std::ofstream TaintRegResults;

// Registers that are part of the tracking
std::set<REG> regs;

// Global information of stack area
UINT64 stackMinVal = 0;
UINT64 stackMaxVal = 0;

// Stack frame tracking.
// Is used as a stack.
std::vector<MemoryBlockData*> stackFrames;

UINT64 _lastStackFrameId = 100000;
std::map<ADDRINT, ADDRINT> pltToRealFctStartMap;

ADDRINT pltTargetAddress = 0;

std::map<ADDRINT, ADDRINT> blockIdToRemainingFrameLengthMap;
std::map<ADDRINT, FunctionData*> _functionStates;

std::unordered_set<ADDRINT> _forcedPublicFunctions;

UINT32 ldImgId = 0;
UINT32 libcImgId = 0;

// Mapping of addresses to instructions
std::unordered_map<ADDRINT, std::string> disassemblyMap;
std::unordered_map<ADDRINT, UINT32> disasAddrToImgIdMap;

// Set of sources for taint analysis.
std::set<ADDRINT> sources;
UINT64 keySize = 32;

// Read offset
static unsigned int stdin_read_off = 0;

// Hash function for instruction set.
struct InstructionDataHash
{
	size_t operator() (const InstructionData* a) const
	{
		return (a->instructionAddress << 32) ^ a->memoryAddress;
	}
};

// Equality function for instruction set.
struct InstructionDataComparer
{
	bool operator() (const InstructionData* a, const InstructionData* b) const
	{
		return a->instructionAddress == b->instructionAddress
			&& a->memoryAddress == b->memoryAddress;
	}
};

// Instruction set.
std::unordered_set<InstructionData*, InstructionDataHash, InstructionDataComparer> instructions;

// Dummy object for fast checking whether an instruction/memory address pair is already present in the instruction set.
InstructionData* tmpInstruction = new InstructionData(0, 0, 0, 0, 0, nullptr, AccessType::NONE, 0);

// For accessing information about the last observed instruction.
// There is one entry for each memory access call back: read 1, read 2, write, control flow
InstructionData* lastInstructions[4] = { nullptr, nullptr, nullptr, nullptr };

// Data of loaded images (e.g., binary to be analyzed, libc, libcrypto,...).
std::vector<ImageData*> images;

// Dummy "invalid" image
ImageData* _invalidImage = new ImageData(0, 0, "<INVALID>", 0, 0);

// Data from static variable detection input list.
int memoryBlockCount = 0;
std::vector<MemoryBlockData*> inputMemoryBlockData;

// Data of callstack entries
std::vector<CallstackEntry*> callstack;
std::vector<CallstackEntry*> callstackEntries;

// Data of memory blocks
std::vector<MemoryBlockData*> memoryBlocks;

// Same as memoryBlocks, but does only contain non-stack memory blocks for faster lookup.
std::vector<MemoryBlockData*> activeNonStackMemoryBlocks;

// The unique memory block ID for encountered blocks (starting with 1 so that 0 can be value for error case)
UINT64 blockId = 1;

// The data of heap reallocation taint status information
std::vector<tag_t> reallocTaintInfo;
MemoryBlockData* lastReallocMemoryBlock;

// Heap range.
ADDRINT _brkMin = 0xffffffffffffffff;
ADDRINT _brkMax = 0;

// Data of syscalls
std::vector<SyscallData*> syscallData;

// threads context counter
static size_t tctx_ct = 0;
// threads context
thread_ctx_t* threads_ctx = nullptr;

// syscall descriptors
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

// ins descriptors
ins_desc_t ins_desc[XED_ICLASS_LAST];

// Number of buffered memory trace entries.
const int _memoryTraceEntryCount = 4096;

// Memory trace entry buffer.
MemoryTraceEntry _memoryTraceEntries[_memoryTraceEntryCount];

// Current memory trace entry buffer index.
int _memoryTraceEntryIndex = 0;

// Last accessed memory address for memory trace generation.
UINT64 _lastAccessedAddress = 0;

// Memory access trace file.
std::ofstream _memoryAccessFile;


// Instructions that are part of a static instrumentation mitigation
std::unordered_map<ADDRINT, std::string> mitigationInsAddrtoDisasMap;
std::unordered_map<ADDRINT, UINT8> mitigationInsToAccessTypeMap;

// State for .plt tracking.
enum PltState
{
	// We are currently not handling a .plt call.
	PLT_STATE_INVALID,

	// We have called into a .plt gadget.
	PLT_STATE_CALL,

	// We have jumped into the lazy linking stub.
	PLT_STATE_STUB,

	// We have jumped into the lazy linking routine in ld.
	PLT_STATE_LINKING,

	// Linking is done, we will soon jump into the actual function.
	PLT_STATE_LINKING_DONE
};
PltState _pltState = PLT_STATE_INVALID;
int _ldCallDepth = 0;

// List of .plt sections.
struct PltSection
{
	ADDRINT startAddress;
	ADDRINT endAddress;

	// Stores whether this PLT section begins with a stub that points to the dynamic linker.
	bool hasStub;
};
std::vector<PltSection*> _pltSections;

// We assume that the PLT stub has a size of 16 bytes.
#define PLT_STUB_SIZE 0x10

VOID SetInsTypeAtAddr(ADDRINT addr, UINT32 type)
{
	mitigationInsToAccessTypeMap[addr] = type;
}

/* CALLBACK PROTOTYPES */

VOID InstrumentImage(IMG img, VOID* v);
static void InstrumentTrace(TRACE trace, VOID* v);

VOID AddReadSecret(ADDRINT ret, ADDRINT buf, UINT32 read_off);
BOOL AddressIsTainted(ADDRINT address);
VOID AdjustCurrentStackFrame(CONTEXT* context, ADDRINT subSize, ADDRINT ip, const ImageData* img);
VOID AdjustCurrentStackFrameRedZone(ADDRINT memoryAddress, ADDRINT ip, const ImageData* img);
VOID AdjustReallocBlockTaintStatus(ADDRINT addr);
VOID ClearAllocationRegisters(THREADID tid, BOOL isPureMalloc);
VOID ClearGlobals(ADDRINT mainStartAddress, CONTEXT* context);
VOID Declassify(ADDRINT secret, ADDRINT size);
VOID DropTaint();
VOID Classify(ADDRINT secret, ADDRINT size);
VOID Fini(INT32 code, VOID* v);
VOID GetCallstack();
VOID SetKeySize(ADDRINT keySz);
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO* exceptionInfo, PHYSICAL_CONTEXT* physicalContext, VOID* v);
VOID InsertHeapAllocAddressReturnEntry(ADDRINT allocationAddress);
VOID InsertHeapAllocSizeParameterEntry(UINT32 allocationSize);
VOID InsertHeapCallocSizeParameterEntry(ADDRINT count, ADDRINT size);
VOID InsertHeapReallocSizeAndAddressParameterEntry(ADDRINT addr, UINT32 allocationSize);
VOID InsertHeapFreeParameterEntry(ADDRINT freeAddress);
VOID InsertMemoryReadWriteEntry(UINT32 callBackIndex, ADDRINT instructionAddress, ADDRINT memoryAddress, UINT32 size, const ImageData* image, BOOL hasSegmentPrefix);
VOID RegisterIsTainted(THREADID tid, ADDRINT address);
PltSection* GetPltSectionForAddress(ADDRINT address);
bool AddressInPlt(ADDRINT address);
VOID SysBefore_CheckArgsEncrypted(ADDRINT ip, ADDRINT num, ADDRINT argCount, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5);
VOID TaintStatusRegisters(INT32 code, VOID* v);
VOID TrackStackFramesAddPop(ADDRINT addSize, ADDRINT ip, const ImageData* img);
VOID TrackStackFramesLea(CONTEXT* context, ADDRINT newAddr, ADDRINT ip, const ImageData* img);
VOID TrackStackFramesLeave(CONTEXT* context, ADDRINT ip, const ImageData* img);
VOID AllocateNewStackFrame(ADDRINT functionAddress, UINT32 functionImageId, ADDRINT functionOffset, ADDRINT rsp);
VOID HandleGenericCall(ADDRINT branchTargetAddress, CONTEXT* context, ADDRINT ip, const ImageData* img);
VOID HandleGenericJmp(ADDRINT branchTargetAddress, CONTEXT* context, ADDRINT ip, const ImageData* img);
VOID HandleGenericRet(CONTEXT* context, ADDRINT ip, const ImageData* img);
VOID HandlePltExit(ADDRINT branchTargetAddress, ADDRINT ip, const ImageData* img);
VOID UpdateBlockTaintStatus(UINT32 callBackIndex, THREADID tid);
VOID StoreMemoryTraceBefore(UINT64 address);
VOID StoreMemoryTraceAfter(UINT64 rip, UINT32 width);
VOID StoreReadAccessInfoBefore(ADDRINT ea, ADDRINT ip, UINT32 size);
VOID StoreWriteAccessInfoBefore(ADDRINT ea);
VOID StoreWriteAccessInfoAfter(ADDRINT ip, UINT32 size);

static void post_read_hook(THREADID tid, syscall_ctx_t* ctx);
static void sysenter_save(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v);
static void sysexit_save(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v);
static void thread_alloc(THREADID tid, CONTEXT* ctx, INT32 flags, VOID* v);
static inline int thread_ctx_init();


/*
 * initialization of the core tagging engine;
 * it must be called before using everything else
 *
 * @argc:	argc passed in main
 * @argv:	argv passed in main
 *
 * returns: 0 on success, 1 on error
 */
int libdft_init(const char* filename, const char* infileName, int readSyscalls, int trackSyscalls)
{
	// Open the trace file
	TraceFile.open(filename);

	// Open the ifstream
	infile.open(infileName);

	if (enableMemoryAccessTrace)
	{
		// Open memory trace output file
		_memoryAccessFile.open((std::string(filename) + ".memtrace").c_str(), std::ios::binary | std::ios::trunc);
	}

	if (enableTrackTaintedRegs)
	{
		CERR_INFO << "Registers are checked for taint status." << std::endl;

		// Add all registers for tracking
		regs.insert(REG_RAX);
		regs.insert(REG_RBX);
		regs.insert(REG_RCX);
		regs.insert(REG_RDX);
		regs.insert(REG_RDI);
		regs.insert(REG_RSI);
		regs.insert(REG_RBP);
		regs.insert(REG_RSP);
		regs.insert(REG_R8);
		regs.insert(REG_R9);
		regs.insert(REG_R10);
		regs.insert(REG_R11);
		regs.insert(REG_R12);
		regs.insert(REG_R13);
		regs.insert(REG_R14);
		regs.insert(REG_R15);
		regs.insert(REG_XMM0);
		regs.insert(REG_XMM1);
		regs.insert(REG_XMM2);
		regs.insert(REG_XMM3);
		regs.insert(REG_XMM4);
		regs.insert(REG_XMM5);
		regs.insert(REG_XMM6);
		regs.insert(REG_XMM7);
		regs.insert(REG_XMM8);
		regs.insert(REG_XMM9);
		regs.insert(REG_XMM10);
		regs.insert(REG_XMM11);
		regs.insert(REG_XMM12);
		regs.insert(REG_XMM13);
		regs.insert(REG_XMM14);
		regs.insert(REG_XMM15);
	}

	// Check if read system calls shall be used as taint sources
	if (readSyscalls != 0)
	{
		enableReadSyscallSource = true;
		CERR_INFO << "Read system calls are set as taint sources." << std::endl;
	}

	// Check if system calls shall be tracked for mitigation
	if (trackSyscalls != 0)
	{
		enableTrackSyscalls = true;
		CERR_INFO << "System calls are tracked for mitigation." << std::endl;
	}

	// Determine the stack size
	FILE* fp;
	char line[2048];
	fp = fopen("/proc/self/maps", "r");

	if (fp == nullptr)
		perror("Error opening file");

	const char* firstSplit = "-";
	UINT64 stackMin, stackMax;
	std::string::size_type addressLength;
	std::string str, stackMinStr, stackMaxStr;
	while (fgets(line, 2048, fp) != nullptr)
	{
		if (strstr(line, "[stack]") != nullptr)
		{
			str = line;
			addressLength = str.find(firstSplit);
			if (addressLength != std::string::npos)
			{
				stackMinStr = str.substr(0, addressLength);
				stackMin = getUint64FromStr(stackMinStr);
				stackMaxStr = str.substr(addressLength + 1, addressLength);
				stackMax = getUint64FromStr(stackMaxStr);
				CERR_INFO << "stackMin from /proc/self/maps: " << std::hex << stackMin << std::endl;
				CERR_INFO << "stackMax from /proc/self/maps: " << std::hex << stackMax << std::endl;

				// Get full stack size
				struct rlimit stackLimit;
				if (getrlimit(RLIMIT_STACK, &stackLimit) != 0)
				{
					char errBuffer[128];
					strerror_r(errno, errBuffer, sizeof(errBuffer));
					fprintf(stderr, "Error reading stack limit: [%d] %s\n", errno, errBuffer);
				}

				uint64_t stackMinBuffered = reinterpret_cast<uint64_t>(stackMin) - static_cast<uint64_t>(stackLimit.rlim_cur);
				uint64_t stackMaxBuffered = (reinterpret_cast<uint64_t>(stackMax) + 0x10000) & ~0x10000ull; // Round to next higher multiple of 64 kB (should be safe on x86 systems)
				CERR_INFO << "stackMinBuffered: " << std::hex << stackMinBuffered << std::endl;
				CERR_INFO << "stackMaxBuffered: " << std::hex << stackMaxBuffered << std::endl;

				stackMinVal = stackMinBuffered;
				stackMaxVal = stackMaxBuffered;

				break;
			}
		}
	}
	fclose(fp);

	// Read input: get images
	int imageCount = 0;
	infile >> imageCount;
	UINT32 imageId;
	int interesting;
	std::string sizeStr, imageName;

	for (int i = 0; i < imageCount; ++i)
	{
		infile >> imageId >> sizeStr >> interesting >> imageName;

		images.push_back(new ImageData(
			imageId, getUint64FromStr(sizeStr), imageName, 0, 0
		));
	}

	// Read input: list of static variables (= "image memory blocks"), generated with static variable detection Pintool
	infile >> memoryBlockCount;
	std::string imageOffsetStr;
	UINT64 imageBlockSize;

	for (int i = 0; i < memoryBlockCount; ++i)
	{
		infile >> imageId >> imageOffsetStr >> imageBlockSize;
		std::set<UINT32> emptySet;
		inputMemoryBlockData.push_back(new MemoryBlockData(
			imageId, getUint64FromStr(imageOffsetStr), blockId++, imageBlockSize, 0, 0, MemoryBlockType::IMAGE, 0, false, true, emptySet
		));
	}

	// Use the input for the whole analysis
	memoryBlocks = inputMemoryBlockData;
	activeNonStackMemoryBlocks = inputMemoryBlockData;

	// Initialize the callstack with a root entry
	callstack.push_back(new CallstackEntry(0, 0, 0, 0, 0, 0, 0));

	// Handle internal exceptions (for debugging)
	PIN_AddInternalExceptionHandler(HandlePinToolException, nullptr);

	// initialize symbol processing
	PIN_InitSymbols();

	// initialize thread contexts; optimized branch
	if (unlikely(thread_ctx_init()))
		// thread contexts failed
		return 1;

	/*
	* syscall hooks; store the context of every syscall
	* and invoke registered callbacks (if any)
	*/
	// Add a read hook to set the input buffer as taint source
	if (enableReadSyscallSource)
		(void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

	// register sysenter_save() to be called before every syscall
	PIN_AddSyscallEntryFunction(sysenter_save, nullptr);

	// register sysexit_save() to be called after every syscall
	PIN_AddSyscallExitFunction(sysexit_save, nullptr);

	// initialize the ins descriptors
	(void)memset(ins_desc, 0, sizeof(ins_desc));

	// Register image instrumentation
	IMG_AddInstrumentFunction(InstrumentImage, nullptr);

	// register trace_ins() to be called for every trace
	TRACE_AddInstrumentFunction(InstrumentTrace, nullptr);

	// Register Fini to be called when the application exits
	PIN_AddFiniFunction(Fini, nullptr);

	if (enableTrackTaintedRegs)
		PIN_AddFiniFunction(TaintStatusRegisters, nullptr);

	// success
	return 0;
}

/*
 * stop the execution of the application inside the
 * tag-aware VM; the execution of the application
 * is not interrupted
 *
 * NOTE: it also performs the appropriate cleanup
 */
void libdft_die()
{
	free(threads_ctx);
	PIN_Detach();
}

// Forces the stack frame of the given function to public.
VOID ForceStackFramePublic(IMG img, const char* name)
{
	RTN rtn = RTN_FindByName(img, name);
	if (RTN_Valid(rtn))
		_forcedPublicFunctions.insert(RTN_Address(rtn));
}

// [Callback] Instruments the memory allocation / deallocation functions.
VOID InstrumentImage(IMG img, VOID* v)
{
	// Retrieve image name
	std::string imageName = IMG_Name(img);

	// Retrieve image memory offsets and id
	UINT64 imageStart = IMG_LowAddress(img);
	UINT64 imageEnd = 0;
	UINT32 id = IMG_Id(img);

	CERR_INFO << "Instrumenting image #" << std::dec << id << " " << imageName << std::endl;

	// Check whether we found the dynamic linker
	if (imageName.find("ld-linux-x86-64.so") != std::string::npos || imageName.find("ld-2.31.so") != std::string::npos)
	{
		CERR_INFO << "   => Dynamic linker" << std::endl;
		ldImgId = id;
	}

	// Check whether we found libc
	if (imageName.find("libc.so") != std::string::npos)
	{
		CERR_INFO << "   => libc" << std::endl;
		libcImgId = id;

		// Remove all instrumentation to ensure that early loaded libc-instructions are correctly instrumented.
		CERR_INFO << "   Dropping all instrumentation" << std::endl;
		PIN_RemoveInstrumentation();
	}

	// Determine image bounds
	for (UINT32 i = 0; i < IMG_NumRegions(img); ++i)
	{
		if (IMG_RegionHighAddress(img, i) > imageEnd)
		{
			imageEnd = IMG_RegionHighAddress(img, i);
		}
	}
	CERR_INFO << "   Address: " << std::hex << imageStart << " ... " << imageEnd << std::endl;

	// Remember image for trace instrumentation
	for (const auto& img : images)
	{
		if (img->imageId == id)
		{
			img->imageStartAddress = imageStart;
			img->imageEndAddress = imageEnd;
		}
	}

	// Add block address information for the current image
	for (const auto& imgBlock : memoryBlocks)
	{
		if (imgBlock->imageId == id)
		{
			UINT64 blockStart = imageStart + imgBlock->offset;
			imgBlock->startAddress = blockStart;
			imgBlock->endAddress = blockStart + imgBlock->blockSize;
		}
	}

	// Find .plt section(s)
	CERR_DEBUG << "   Parsing sections" << std::endl;
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
	{
		std::string secName = SEC_Name(sec);
		bool isPlt = secName.find(".plt") == 0;

		ADDRINT secAddress = SEC_Address(sec);
		ADDRINT secSize = SEC_Size(sec);

		if (isPlt)
		{
			PltSection* pltSection = new PltSection();
			pltSection->startAddress = secAddress;
			pltSection->endAddress = secAddress + secSize;
			pltSection->hasStub = (secName == ".plt"); // .plt.got and .plt.sec don't have a stub

			_pltSections.push_back(pltSection);
		}

		CERR_DEBUG
			<< "       " << std::hex << secAddress
			<< " " << secSize
			<< " " << (isPlt ? "PLT" : "")
			<< " " << secName
			<< std::endl;
	}

	// Find the main to start taint tracking there
	RTN mainRtn = RTN_FindByName(img, "main");
	if (RTN_Valid(mainRtn))
	{
		RTN_Open(mainRtn);

		// Clear status to start tracking
		auto mainStartAddress = RTN_Address(mainRtn);
		RTN_InsertCall(mainRtn, IPOINT_BEFORE, (AFUNPTR)ClearGlobals, IARG_ADDRINT, mainStartAddress, IARG_CONST_CONTEXT, IARG_END);

		RTN_Close(mainRtn);

		CERR_INFO << "   main function at " << std::hex << mainStartAddress << " instrumented." << std::endl;
	}

	// Classify private data
	RTN classifyRtn = RTN_FindByName(img, "classify");
	if (RTN_Valid(classifyRtn))
	{
		RTN_Open(classifyRtn);

		// Instrument classify() to taint the address of the key and the key length
		RTN_InsertCall(classifyRtn, IPOINT_BEFORE, (AFUNPTR)Classify,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);

		RTN_Close(classifyRtn);
		CERR_INFO << "   classify() instrumented." << std::endl;
	}

	// Declassify function to untaint data that gets printed / written to a public buffer
	RTN declassifyRtn = RTN_FindByName(img, "declassify");
	if (RTN_Valid(declassifyRtn))
	{
		RTN_Open(declassifyRtn);

		// Instrument declassify to untaint data
		RTN_InsertCall(declassifyRtn, IPOINT_BEFORE, (AFUNPTR)Declassify,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_END);

		RTN_Close(declassifyRtn);
		CERR_INFO << "   declassify() instrumented." << std::endl;
	}

	// Function to untaint all data
	RTN dropTaintRtn = RTN_FindByName(img, "drop_taint");
	if (RTN_Valid(dropTaintRtn))
	{
		RTN_Open(dropTaintRtn);

		// Instrument
		RTN_InsertCall(dropTaintRtn, IPOINT_BEFORE, (AFUNPTR)DropTaint,
			IARG_END);

		RTN_Close(dropTaintRtn);
		CERR_INFO << "   drop_taint() instrumented." << std::endl;
	}

	// Find allocation and free functions to log allocation sizes and addresses
	// Only instrument allocation methods from libc
	if (imageName.find("libc.so") != std::string::npos)
	{
		// Instrument malloc
		RTN mallocRtn = RTN_FindByName(img, "malloc");
		if (RTN_Valid(mallocRtn))
		{
			RTN_Open(mallocRtn);

			// Trace size parameter
			RTN_InsertCall(mallocRtn, IPOINT_BEFORE, AFUNPTR(InsertHeapAllocSizeParameterEntry),
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);

			// Clear taint of size of allocation
			RTN_InsertCall(mallocRtn, IPOINT_BEFORE, AFUNPTR(ClearAllocationRegisters),
				IARG_THREAD_ID,
				IARG_BOOL, true,
				IARG_END);

			// Trace returned address
			RTN_InsertCall(mallocRtn, IPOINT_AFTER, AFUNPTR(InsertHeapAllocAddressReturnEntry),
				IARG_FUNCRET_EXITPOINT_VALUE,
				IARG_END);

			// Get the callstack
			RTN_InsertCall(mallocRtn, IPOINT_AFTER, AFUNPTR(GetCallstack), IARG_END);

			RTN_Close(mallocRtn);
			CERR_INFO << "   malloc() instrumented." << std::endl;
		}

		// Instrument calloc
		RTN callocRtn = RTN_FindByName(img, "calloc");
		if (RTN_Valid(callocRtn))
		{
			RTN_Open(callocRtn);

			// Trace size parameter
			RTN_InsertCall(callocRtn, IPOINT_BEFORE, AFUNPTR(InsertHeapCallocSizeParameterEntry),
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);

			// Clear taint of size of allocation
			RTN_InsertCall(callocRtn, IPOINT_BEFORE, AFUNPTR(ClearAllocationRegisters),
				IARG_THREAD_ID,
				IARG_BOOL, false,
				IARG_END);

			// Trace returned address
			RTN_InsertCall(callocRtn, IPOINT_AFTER, AFUNPTR(InsertHeapAllocAddressReturnEntry),
				IARG_FUNCRET_EXITPOINT_VALUE,
				IARG_END);

			// Get the callstack
			RTN_InsertCall(callocRtn, IPOINT_AFTER, AFUNPTR(GetCallstack), IARG_END);

			RTN_Close(callocRtn);
			CERR_INFO << "   calloc() instrumented." << std::endl;
		}

		// Instrument realloc
		RTN reallocRtn = RTN_FindByName(img, "realloc");
		if (RTN_Valid(reallocRtn))
		{
			RTN_Open(reallocRtn);

			// Trace size parameter and clear the taint of the heap block
			RTN_InsertCall(reallocRtn, IPOINT_BEFORE, AFUNPTR(InsertHeapReallocSizeAndAddressParameterEntry),
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);

			// Clear taint of size of allocation
			RTN_InsertCall(reallocRtn, IPOINT_BEFORE, AFUNPTR(ClearAllocationRegisters),
				IARG_THREAD_ID,
				IARG_BOOL, false,
				IARG_END);

			// Get the callstack
			RTN_InsertCall(reallocRtn, IPOINT_AFTER, AFUNPTR(GetCallstack), IARG_END);

			// Adjust the taint status and the address of the reallocated heap memory block
			RTN_InsertCall(reallocRtn, IPOINT_AFTER, AFUNPTR(AdjustReallocBlockTaintStatus),
				IARG_FUNCRET_EXITPOINT_VALUE,
				IARG_END);

			RTN_Close(reallocRtn);
			CERR_INFO << "   realloc() instrumented." << std::endl;
		}

		// Instrument free
		RTN freeRtn = RTN_FindByName(img, "free");
		if (RTN_Valid(freeRtn))
		{
			RTN_Open(freeRtn);

			// Trace address parameter and clear the taint of the heap block
			RTN_InsertCall(freeRtn, IPOINT_BEFORE, AFUNPTR(InsertHeapFreeParameterEntry),
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);

			RTN_Close(freeRtn);
			CERR_INFO << "   free() instrumented." << std::endl;
		}
	}

	// HACK for OpenSSL ECDSA: The handwritten SHA-512 assembly does weird things with the stack that break our heuristics.
	// Thus, for now, we just treat the entire function as public. This shouldn't cause any exploitable leakage.
	// (see UpdateBlockTaintStatus)
	ForceStackFramePublic(img, "sha512_block_data_order");
	ForceStackFramePublic(img, "sha512_block_data_order_avx2");
}

VOID AddReadSecret(ADDRINT ret, ADDRINT buf, UINT32 read_off)
{
	// HINT: for specific algorithms check length: e.g. only 32 byte keys for ed25519
	// TODO: adjust for algorithm to be analyzed 
	/* set the tag markings */
	if (ret == 32)
	{
		CERR_DEBUG << "reached read file 32" << std::endl;
		for (unsigned int i = 0; i < ret; i++)
		{
			sources.insert(buf + i);
			// Taint the buffer using the offset from buf start for each byte
			tag_t t = tag_alloc<tag_t>(1);
			tagmap_setb(buf + i, t);
		}
	}
}

VOID Declassify(ADDRINT secret, ADDRINT size)
{
	CERR_INFO << "[TAINT] Declassifying secret at " << std::hex << secret << ", 0x" << size << " bytes" << std::endl;

	// Clear the buffer taint tags so that public data can be written
	tagmap_clrn(secret, size);

	// Unset the 'secret' status of the block that was malloc'd for printing the buffer
	for (auto it = memoryBlocks.rbegin(); it != memoryBlocks.rend(); ++it)
	{
		if (((*it)->startAddress <= secret && secret < (*it)->endAddress) && (*it)->active)
		{
			CERR_INFO << "[TAINT]   Marking memory block #" << std::dec << (*it)->blockId << " as non-secret" << std::endl;
			(*it)->secret = false;
		}
	}
}

VOID DropTaint()
{
	CERR_INFO << "[TAINT] Dropping all taint tags" << std::endl;

	// Clear all taint tags
	tagmap_clear();
}

VOID Classify(ADDRINT secret, ADDRINT size)
{
	CERR_INFO << "[TAINT] Classifying secret at " << std::hex << secret << ", 0x" << size << " bytes" << std::endl;

	for (size_t i = 0; i < size; ++i)
	{
		sources.insert(secret + i);
		tag_t t = tag_alloc<tag_t>((UINT32)1);
		tagmap_setb(secret + i, t);
	}
}

VOID SysBefore_CheckArgsEncrypted(ADDRINT ip, ADDRINT num, ADDRINT argCount, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5)
{

	std::vector<ADDRINT> functionArgs;
	std::vector<ADDRINT> syscallArgs;
	// Arrays and these are not provided by Pin :-(
//    functionArgs.insert(functionArgs.end(), { arg0, arg1, arg2, arg3, arg4, arg5 });
//    for (const auto arg: { arg0, arg1, arg2, arg3, arg4, arg5 })
//        functionArgs.push_back(arg);

	// Get all provided args to access them
	functionArgs.push_back(arg0);
	functionArgs.push_back(arg1);
	functionArgs.push_back(arg2);
	functionArgs.push_back(arg3);
	functionArgs.push_back(arg4);
	functionArgs.push_back(arg5);

	// Set all args that are "real" args of the syscall
	for (ADDRINT i = 0; i < 6; i++)
	{
		if (i < argCount)
		{
			syscallArgs.push_back(functionArgs.at(i));
		}
		else
		{
			syscallArgs.push_back({ 0 });
		}
	}

	// Add syscall data
	auto img = GetImageByAddress(ip);
	syscallData.push_back(new SyscallData(
		ip, img->imageId, img->GetInsOffset(ip), num, argCount, syscallArgs.at(0), syscallArgs.at(1),
		syscallArgs.at(2), syscallArgs.at(3), syscallArgs.at(4), syscallArgs.at(5)
	));
}

VOID ClearAllocationRegisters(THREADID tid, BOOL isPureMalloc)
{
	// Clear the taint status of registers that contain the pointer to a heap allocation and / or the allocation size
	if (isPureMalloc)
	{
		for (size_t i = 0; i < 8; ++i)
		{
			RTAG[DFT_REG_RDI][i] = tag_traits<tag_t>::cleared_val;
		}
	}
	else
	{
		for (size_t i = 0; i < 8; ++i)
		{
			RTAG[DFT_REG_RDI][i] = tag_traits<tag_t>::cleared_val;
			RTAG[DFT_REG_RSI][i] = tag_traits<tag_t>::cleared_val;
		}
	}
}

VOID InsertHeapAllocAddressReturnEntry(ADDRINT allocationAddress)
{
	// Find the right memory block entry and add the new information
	for (auto it = activeNonStackMemoryBlocks.rbegin(); it != activeNonStackMemoryBlocks.rend(); ++it)
	{
		if ((*it)->blockId == (blockId - 1))
		{
			(*it)->startAddress = allocationAddress;
			(*it)->endAddress = allocationAddress + (*it)->blockSize;
			break;
		}
	}
}

VOID InsertHeapAllocSizeParameterEntry(UINT32 allocationSize)
{
	// Add new heap allocation block
	std::set<UINT32> emptySet;
	MemoryBlockData* memoryBlock = new MemoryBlockData(
		0, 0, blockId++, allocationSize, 0, 0, MemoryBlockType::HEAP, 0, false, true, emptySet
	);

	memoryBlocks.push_back(memoryBlock);
	activeNonStackMemoryBlocks.push_back(memoryBlock);
}

VOID InsertHeapCallocSizeParameterEntry(ADDRINT count, ADDRINT size)
{
	// Add new heap allocation block
	std::set<UINT32> emptySet;
	MemoryBlockData* memoryBlock = new MemoryBlockData(
		0, 0, blockId++, count * size, 0, 0, MemoryBlockType::HEAP, 0, false, true, emptySet
	);

	memoryBlocks.push_back(memoryBlock);
	activeNonStackMemoryBlocks.push_back(memoryBlock);
}

VOID InsertHeapReallocSizeAndAddressParameterEntry(ADDRINT addr, UINT32 allocationSize)
{
	// Find the suitable "old" allocated block and set status to inactive
	for (auto it = activeNonStackMemoryBlocks.begin(); it != activeNonStackMemoryBlocks.end(); ++it)
	{
		auto memoryBlock = *it;
		if (memoryBlock->blockType == MemoryBlockType::HEAP && memoryBlock->startAddress == addr && memoryBlock->active)
		{
			memoryBlock->active = false;
			activeNonStackMemoryBlocks.erase(it);

			// If the block is found, we store and then clear its taint status
			for (ADDRINT i = addr; i < addr + memoryBlock->blockSize; ++i)
			{
				reallocTaintInfo.push_back(tagmap_getb(i));
				tagmap_clrb(i);
			}

			break;
		}
	}

	// Add new heap allocation block
	// The address has to be adjusted according to the realloc return value
	std::set<UINT32> emptySet;
	MemoryBlockData* memoryBlock = new MemoryBlockData(
		0, 0, blockId++, allocationSize, addr, addr + allocationSize, MemoryBlockType::HEAP, 0, false, true, emptySet
	);

	memoryBlocks.push_back(memoryBlock);
	activeNonStackMemoryBlocks.push_back(memoryBlock);

	// Remember the current block in order to adjust the address after the reallocation took place
	lastReallocMemoryBlock = memoryBlock;
}

VOID AdjustReallocBlockTaintStatus(ADDRINT addr)
{
	// Adjust the start and end address of the reallocated heap memory block
	lastReallocMemoryBlock->startAddress = addr;
	lastReallocMemoryBlock->endAddress = addr + lastReallocMemoryBlock->blockSize;

	// Re-taint the data in newly allocated block 
	UINT64 oldBlockSize = reallocTaintInfo.size();
	for (size_t i = 0; i < oldBlockSize; ++i)
	{
		tagmap_setb(addr + i, reallocTaintInfo.at(i));
	}
	reallocTaintInfo.clear();
}

VOID InsertHeapFreeParameterEntry(ADDRINT freeAddress)
{
	// Find the suitable "old" allocated block and set status to inactive
	for (auto it = activeNonStackMemoryBlocks.begin(); it != activeNonStackMemoryBlocks.end(); ++it)
	{
		auto memoryBlock = *it;
		if (memoryBlock->blockType == MemoryBlockType::HEAP && memoryBlock->startAddress == freeAddress && memoryBlock->active)
		{
			memoryBlock->active = false;
			activeNonStackMemoryBlocks.erase(it);

			// If the block is found, we clear its taint status
			tagmap_clrn(memoryBlock->startAddress, memoryBlock->blockSize);

			break;
		}
	}
}

VOID InsertMemoryReadWriteEntry(UINT32 callBackIndex, ADDRINT instructionAddress, ADDRINT memoryAddress, UINT32 size, const ImageData* image, BOOL hasSegmentPrefix)
{
	MemoryBlockData* memBlk = nullptr;

	// Stack access?
	if (stackMinVal <= memoryAddress && memoryAddress < stackMaxVal)
	{
		// Find suitable stack memory block
		for (auto it = stackFrames.rbegin(); it != stackFrames.rend(); ++it)
		{
			auto currentBlock = *it;

			if (currentBlock->endAddress <= memoryAddress && memoryAddress < currentBlock->startAddress)
			{
				memBlk = currentBlock;

				UINT64 stackBaseOffset = memBlk->startAddress - memoryAddress;

				// Find function associated with this stack frame and remember the instruction
				auto funStart = memBlk->functionStartAddress;
				auto functionStateIt = _functionStates.find(funStart);
				if (functionStateIt == _functionStates.end())
				{
					CERR_WARNING
						<< "Could not find function state for stack frame of function " << std::hex << funStart
						<< " when resolving access to " << memoryAddress
						<< " (relative " << stackBaseOffset
						<< ") at " << image->imageId << " " << image->GetInsOffset(instructionAddress)
						<< std::endl;
				}

				auto functionState = functionStateIt->second;

				// Record (instruction, offset) pair for each accessed stack offset
				for (size_t i = 0; i < size; ++i)
					functionState->instructionsAndStackOffsets.insert(std::make_pair(instructionAddress, stackBaseOffset - i));

				break;
			}
		}
	}

	// Heap/image access?
	if (memBlk == nullptr && !hasSegmentPrefix)
	{
		// No stack memory block, check image/heap blocks
		for (auto it = activeNonStackMemoryBlocks.rbegin(); it != activeNonStackMemoryBlocks.rend(); ++it)
		{
			auto currentBlock = *it;

			if (currentBlock->startAddress <= memoryAddress && memoryAddress < currentBlock->endAddress)
			{
				memBlk = currentBlock;

				// Remember that this instruction accessed that block
				memBlk->instructionAddresses.insert(instructionAddress);

				break;
			}
		}
	}

	// Did we find a fitting block?
	if (memBlk == nullptr)
	{
		// Do not show errors for instructions with segment prefix (usually stack canary accesses) or for PLT/GOT accesses
		if (!hasSegmentPrefix && !AddressInPlt(instructionAddress))
		{
			// We may miss some heap allocations, as we only track malloc(), but not _int_malloc(), which is used to allocate
			// a few data structures for the allocator as well. The same is true for memory accesses prior to Pin detecting that
			// libc was loaded.
			// For these cases, we use a lower log severity to reduce noise
			const ImageData* resolvedImage = nullptr;
			if (_brkMin <= memoryAddress && memoryAddress < _brkMax)
			{
				CERR_DEBUG
					<< "Could not resolve memory access to " << std::hex << memoryAddress
					<< " at " << image->imageId << " " << image->GetInsOffset(instructionAddress)
					<< ", but address is in heap area"
					<< std::endl;
			}
			else if (libcImgId == 0)
			{
				CERR_DEBUG
					<< "Could not resolve memory access to " << std::hex << memoryAddress
					<< " at " << image->imageId << " " << image->GetInsOffset(instructionAddress)
					<< ", likely in libc prior detection by Pin"
					<< std::endl;
			}
			else if ((resolvedImage = GetImageByAddress(memoryAddress)) != nullptr)
			{
				CERR_DEBUG
					<< "Could not resolve memory access to " << std::hex << memoryAddress
					<< " at " << image->imageId << " " << image->GetInsOffset(instructionAddress)
					<< ", but address is image offset " << image->imageId << " " << (memoryAddress - image->imageStartAddress)
					<< std::endl;
			}
			else
			{
				CERR_WARNING
					<< "Could not resolve memory access to " << std::hex << memoryAddress
					<< " at " << image->imageId << " " << image->GetInsOffset(instructionAddress)
					<< std::endl;

				// Emit call stack to ease debugging
				for (auto it = callstack.begin(); it != callstack.end(); ++it)
				{
					auto callStackEntry = *it;
					CERR_DEBUG
						<< "  " << std::hex << callStackEntry->sourceImageId << " " << callStackEntry->sourceImageOffset
						<< " -> " << callStackEntry->targetImageId << " " << callStackEntry->targetImageOffset
						<< std::endl;
				}
			}
		}
	}

	// Retrieve InstructionData object for given instruction/memory address pair
	// If it does not yet exist, create a new one
	tmpInstruction->instructionAddress = instructionAddress;
	tmpInstruction->memoryAddress = memoryAddress;

	// Keep track of instruction/memory address pairs
	auto instructionsIterator = instructions.find(tmpInstruction);
	InstructionData* instructionData;
	if (instructionsIterator == instructions.end())
	{
		instructionData = new InstructionData(
			instructionAddress,
			size,
			image->imageId,
			memoryAddress,
			image->GetInsOffset(instructionAddress),
			memBlk,
			AccessType::NONE,
			memBlk == nullptr && (hasSegmentPrefix || AddressInPlt(instructionAddress))
		);
		instructions.insert(instructionData);
	}
	else
	{
		instructionData = *instructionsIterator;

		// For fast access in UpdateBlockTaintStatus
		instructionData->memBlock = memBlk;
	}

	// Remember instruction for fast access in UpdateBlockTaintStatus
	lastInstructions[callBackIndex] = instructionData;
}

VOID UpdateBlockTaintStatus(UINT32 callBackIndex, THREADID tid)
{
	// Check all bytes of the memory access for taint and update our state accordingly
	// 
	// NOTE: We do fine-grained access tracking, i.e., we check each byte of an access for taint, to reduce the final overhead.
	//       However, this has a small risk of yielding misleading results if a write access is tainted incorrectly.
	//		 Example (now fixed):
	//         `push 1` has operand size 1, but writes 8 bytes. If there is left-over taint in one of the high bytes, but a read
	//         access only accesses the low ones, the write is detected as "sometimes private" (because there is taint in one of
	//         the 8 bytes), but the read is "always public" (because the low bytes aren't tainted), leading to potential crashes.

	// Check associated memory block
	auto lastInstruction = lastInstructions[callBackIndex];
	auto block = lastInstruction->memBlock;
	if (block == nullptr || lastInstruction->instructionAddress == 0 || lastInstruction->isUnresolvableSegmentOrPltGotAccess)
	{
		if (lastInstruction == nullptr)
			return;

		// Check whether we access any tainted memory -> bad
		for (size_t i = 0; i < lastInstruction->instructionSize; ++i)
		{
			if (AddressIsTainted(lastInstruction->memoryAddress + i))
			{
				CERR_ERROR << "Could not resolve tainted access at ins "
					<< lastInstruction->imageId << " " << std::hex << lastInstruction->offset
					<< " to address " << lastInstruction->memoryAddress << std::endl;

				break;
			}
		}

		return;
	}

	if (block->blockType == MemoryBlockType::STACK)
	{
		// HACK Is this function marked as forced public?
		if (_forcedPublicFunctions.find(block->functionStartAddress) != _forcedPublicFunctions.end())
		{
			lastInstruction->accessType |= AccessType::PUBLIC;
			return;
		}

		// Find out whether this instruction touches a secret stack offset
		for (size_t i = 0; i < lastInstruction->instructionSize; ++i)
		{
			if (AddressIsTainted(lastInstruction->memoryAddress + i))
			{
				// Calculate the offsets from absolute addresses and stack frame start
				UINT64 secretOffset = (block->startAddress - lastInstruction->memoryAddress) - i;
				block->secretOffsets.insert(secretOffset);

				if (secretOffset > block->blockSize)
				{
					CERR_WARNING << "Secret offset larger than frame size at ins " << lastInstruction->imageId << " " << std::hex << lastInstruction->offset << " block " << std::dec << block->blockId << std::endl;
				}

				// Keep track of instructions that directly touch a secret offset
				lastInstruction->accessType |= AccessType::SECRET;
			}
			else
			{
				// Not a secret offset, so we add a public access to our frame tracking state for the instruction
				lastInstruction->accessType |= AccessType::PUBLIC;
			}
		}
	}
	else
	{
		// For heap and image blocks, the whole block has to be marked as secret as soon as any secret is found in it
		for (size_t i = 0; i < lastInstruction->instructionSize; ++i)
		{
			if (AddressIsTainted(lastInstruction->memoryAddress + i))
			{
				block->secret = true;
				break;
			}
		}
	}
}

VOID AdjustCurrentStackFrame(CONTEXT* context, ADDRINT subSize, ADDRINT ip, const ImageData* img)
{
	// RSP before executing this instruction
	UINT64 rspVal = PIN_GetContextReg(context, REG_RSP);

	// Find the current stack frame
	if (!stackFrames.empty())
	{
		auto currentFrame = stackFrames.back();

		ADDRINT newEndAddr = (rspVal - subSize);
		blockIdToRemainingFrameLengthMap[currentFrame->blockId] = currentFrame->startAddress - newEndAddr;

		if (currentFrame->endAddress > (rspVal - subSize))
		{
			currentFrame->endAddress = newEndAddr;
			currentFrame->blockSize = currentFrame->startAddress - currentFrame->endAddress;

			auto funStart = currentFrame->functionStartAddress;
			auto functionState = _functionStates[funStart];
			if (currentFrame->blockSize > functionState->maximumFrameSize)
			{
				functionState->maximumFrameSize = currentFrame->blockSize;
			}
		}
	}
	else
	{
		CERR_WARNING << "Stack frame sub at " << std::hex << img->imageId << " " << img->GetInsOffset(ip) << ", but there is no stack frame" << std::endl;
	}
}

VOID AdjustCurrentStackFrameRedZone(ADDRINT memoryAddress, ADDRINT ip, const ImageData* img)
{
	// Find the current stack frame
	if (!stackFrames.empty())
	{
		auto currentFrame = stackFrames.back();
		if ((currentFrame->endAddress > memoryAddress) && (memoryAddress > stackMinVal))
		{
			currentFrame->endAddress = memoryAddress;
			currentFrame->blockSize = currentFrame->startAddress - currentFrame->endAddress;

			auto funStart = currentFrame->functionStartAddress;
			auto functionState = _functionStates[funStart];
			if (currentFrame->blockSize > functionState->maximumFrameSize)
			{
				functionState->maximumFrameSize = currentFrame->blockSize;
			}
		}
	}
	else
	{
		CERR_WARNING << "Stack frame red zone adjustment at " << std::hex << img->imageId << " " << img->GetInsOffset(ip) << ", but there is no stack frame" << std::endl;
	}
}

VOID TrackStackFramesAddPop(ADDRINT addSize, ADDRINT ip, const ImageData* img)
{
	if (!stackFrames.empty())
	{
		auto currentFrame = stackFrames.back();

		blockIdToRemainingFrameLengthMap[currentFrame->blockId] -= addSize;
	}
	else
	{
		CERR_WARNING << "Stack frame add at " << std::hex << img << " " << img->GetInsOffset(ip) << ", but there is no stack frame" << std::endl;
	}
}

VOID TrackStackFramesLea(CONTEXT* context, ADDRINT newAddr, ADDRINT ip, const ImageData* img)
{
	UINT64 rspVal = PIN_GetContextReg(context, REG_RSP);
	if (rspVal < newAddr)
	{
		TrackStackFramesAddPop(newAddr - rspVal, ip, img);
	}
	else if (rspVal > newAddr)
	{
		AdjustCurrentStackFrame(context, rspVal - newAddr, ip, img);
	}
}

VOID TrackStackFramesLeave(CONTEXT* context, ADDRINT ip, const ImageData* img)
{
	// Same logic as for add/pop, but we take the offset from rbp
	UINT64 rbpVal = PIN_GetContextReg(context, REG_RBP);
	UINT64 rspVal = PIN_GetContextReg(context, REG_RSP);

	TrackStackFramesAddPop(rbpVal - rspVal + 8, ip, img);
}

VOID AllocateNewStackFrame(ADDRINT functionAddress, UINT32 functionImageId, ADDRINT functionOffset, ADDRINT rsp)
{
	int newStackFrameId = ++_lastStackFrameId;

	// The stack frame begins above the return address (RSP points to the return address)
	auto stackFrameMemoryBlock = new MemoryBlockData(
		functionImageId, functionOffset, newStackFrameId, 0, rsp, rsp, MemoryBlockType::STACK, functionAddress, false, true, std::set<UINT32>()
	);

	memoryBlocks.push_back(stackFrameMemoryBlock);
	stackFrames.push_back(stackFrameMemoryBlock);
	blockIdToRemainingFrameLengthMap[newStackFrameId] = 0;

	// Retrieve function info
	// Do we know this function already?
	FunctionData* functionState;
	const auto& search = _functionStates.find(functionAddress);
	if (search != _functionStates.end())
	{
		functionState = search->second;
	}
	else
	{
		functionState = new FunctionData();
		functionState->startAddress = functionAddress;
		functionState->maximumFrameSize = 0;
		_functionStates[functionAddress] = functionState;
	}

	// Remember stack frame for this function
	functionState->stackFrameMemoryBlocks.insert(stackFrameMemoryBlock);
}

VOID HandleGenericCall(ADDRINT branchTargetAddress, CONTEXT* context, ADDRINT ip, const ImageData* img)
{
	auto targetImg = GetImageByAddress(branchTargetAddress);
	UINT32 targetImgId = targetImg->imageId;
	UINT64 targetOffset = targetImg->GetInsOffset(branchTargetAddress);

	if (_pltState == PLT_STATE_LINKING)
	{
		++_ldCallDepth;
		return;
	}

	// Update call stack
	callstack.push_back(new CallstackEntry(
		img->imageId, img->GetInsOffset(ip), targetImgId,
		targetOffset, ip, branchTargetAddress, 0
	));

	// Do we call into a .plt entry?
	if (AddressInPlt(branchTargetAddress))
	{
		if (_pltState != PLT_STATE_INVALID)
		{
			CERR_ERROR << "[PLT] Call into .plt, but we are in state " << std::dec << _pltState << " at "
				<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
				<< std::endl;
		}

		// Check whether we already know the actual address of the function
		const auto& pltMappingIt = pltToRealFctStartMap.find(branchTargetAddress);
		if (pltMappingIt == pltToRealFctStartMap.end())
		{
			// We don't know it yet, so we need to track the dynamic linker's resolution process
			pltTargetAddress = branchTargetAddress;
		}
		else
		{
			branchTargetAddress = pltMappingIt->second;
			targetImg = GetImageByAddress(branchTargetAddress);
			targetImgId = targetImg->imageId;
			targetOffset = targetImg->GetInsOffset(branchTargetAddress);
		}

		_pltState = PLT_STATE_CALL;
		CERR_DEBUG
			<< "[PLT] Switching to PLT_STATE_CALL: "
			<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
			<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
			<< std::endl;

	}

	// Create stack frame for this function call
	// If we call into the PLT, we assign the PLT entry address is function address. We fix this later during lazy binding or
	// when jumping out of the PLT (only if the binding is already done)

	UINT64 rspVal = PIN_GetContextReg(context, REG_RSP);

	AllocateNewStackFrame(branchTargetAddress, targetImgId, targetOffset, rspVal);
}

VOID HandleGenericJmp(ADDRINT branchTargetAddress, CONTEXT* context, ADDRINT ip, const ImageData* img)
{
	auto targetImg = GetImageByAddress(branchTargetAddress);
	UINT32 targetImgId = targetImg->imageId;
	UINT64 targetOffset = targetImg->GetInsOffset(branchTargetAddress);

	// Update .plt state
	auto addressPltSection = GetPltSectionForAddress(branchTargetAddress);
	if (addressPltSection != nullptr)
	{
		if (_pltState == PLT_STATE_INVALID)
		{
			// Check whether we already know the actual address of the function
			const auto& pltMappingIt = pltToRealFctStartMap.find(branchTargetAddress);
			if (pltMappingIt == pltToRealFctStartMap.end())
			{
				// We don't know it yet, so we need to track the dynamic linker's resolution process
				pltTargetAddress = branchTargetAddress;
			}
			else
			{
				branchTargetAddress = pltMappingIt->second;
				targetImg = GetImageByAddress(branchTargetAddress);
				targetImgId = targetImg->imageId;
				targetOffset = targetImg->GetInsOffset(branchTargetAddress);
			}

			// New stack frame is allocated below

			_pltState = PLT_STATE_CALL;
			CERR_DEBUG
				<< "[PLT] Switching to PLT_STATE_CALL: "
				<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
				<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
				<< std::endl;

		}
		else if (_pltState == PLT_STATE_CALL)
		{
			// Check whether we jumped into another PLT entry, or into the binding stub
			if (addressPltSection->hasStub && (branchTargetAddress - addressPltSection->startAddress) < PLT_STUB_SIZE)
			{
				// The .plt entry isn't bound yet
				_pltState = PLT_STATE_STUB;
				CERR_DEBUG
					<< "[PLT] Switching to PLT_STATE_STUB: "
					<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
					<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
					<< std::endl;
			}

			// No stack frame handling necessary
			return;
		}
	}

	if (_pltState == PLT_STATE_STUB)
	{
		// The stub should take us into the dynamic linker
		if (targetImgId != ldImgId)
		{
			CERR_ERROR
				<< "[PLT] Jump from .plt stub does not target dynamic linker: "
				<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
				<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
				<< std::endl;

			PIN_ExitProcess(-1);
		}

		_pltState = PLT_STATE_LINKING;
		CERR_DEBUG
			<< "[PLT] Switching to PLT_STATE_LINKING: "
			<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
			<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
			<< std::endl;


		// No stack frame handling necessary
		return;
	}

	if (_pltState == PLT_STATE_LINKING)
	{
		// Ld jumped into another library, e.g., to resolve ifunc
		// No stack frame handling necessary
		return;
	}

	// End lazy linking tracking, if active
	if (_pltState == PLT_STATE_LINKING_DONE)
	{
		// Sanity check
		if (img->imageId != ldImgId)
		{
			CERR_ERROR << "[PLT] Jump from outside LD, but we are still in post-linking state: "
				<< std::hex << img->imageId << " " << img->GetInsOffset(ip)
				<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress)
				<< std::endl;

			PIN_ExitProcess(-1);
			return;
		}

		// We exit lazy linking tracking as soon as we arrive at the resolved function
		if (branchTargetAddress == pltToRealFctStartMap[pltTargetAddress])
		{
			_pltState = PLT_STATE_INVALID;
			CERR_DEBUG
				<< "[PLT] Switching to PLT_STATE_INVALID: "
				<< std::hex << img->imageId << " " << img->GetInsOffset(ip)
				<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress)
				<< std::endl;

			// Reset tracked stack frame size
			if (stackFrames.empty())
			{
				CERR_ERROR << "[PLT] Can't reset tracked stack frame size, as the stack frame list is empty: "
					<< std::hex << img->imageId << " " << img->GetInsOffset(ip)
					<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress)
					<< std::endl;

				return;
			}

			auto& currentFrame = stackFrames.back();

			// Sanity check
			if (currentFrame->functionStartAddress != branchTargetAddress)
			{
				const ImageData* frameFunctionImage = GetImageByAddress(currentFrame->functionStartAddress);

				CERR_ERROR << "[PLT] Unexpected stack frame function address when resetting stack frame size tracking: "
					<< std::hex << img->imageId << " " << img->GetInsOffset(ip)
					<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress)
					<< ", actual address " << frameFunctionImage->imageId << " " << frameFunctionImage->GetInsOffset(currentFrame->functionStartAddress)
					<< std::endl;

				return;
			}
			
			blockIdToRemainingFrameLengthMap[currentFrame->blockId] = currentFrame->blockSize;
		}
	}

	// Jumps from PLT are handled elsewhere
	// TODO We can probably merge this, if PLT entries execute both functions anyway?
	if (AddressInPlt(ip))
		return;

	if (!stackFrames.empty())
	{
		auto& currentFrame = stackFrames.back();

		// If the current stack frame is free'd entirely, we assume that we have jumped into another function (tail call)
		// Thus, we need to cleanup the current stack frame and allocate a new one.
		if (blockIdToRemainingFrameLengthMap[currentFrame->blockId] == 0)
		{
			// Cleanup current stack frame
			auto currentFrame = stackFrames.back();
			currentFrame->active = false;
			stackFrames.pop_back();

			// Allocate new stack frame for this function call
			// We don't allocate stack frames for functions in the dynamic linker
			UINT64 rspVal = PIN_GetContextReg(context, REG_RSP);

			AllocateNewStackFrame(branchTargetAddress, targetImgId, targetOffset, rspVal);

			CERR_DEBUG
				<< "Allocating new stack frame for suspected tail call: "
				<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
				<< " -> " << targetImgId << " " << targetImg->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
				<< std::endl;
		}
	}
}

VOID HandleGenericRet(CONTEXT* context, ADDRINT ip, const ImageData* img)
{
	if (_pltState == PLT_STATE_LINKING)
	{
		// Ld jumped into another library, e.g., to resolve ifunc
		--_ldCallDepth;

		// If we have reached the bottom of the LD call stack, we have completed dynamic linking
		// and now have the resolved function address in RAX (_dl_fixup)
		if (_ldCallDepth == 0)
		{
			if (img->imageId != ldImgId)
			{
				CERR_ERROR
					<< "[PLT] ldCallDepth == 0, but we are not in ld at "
					<< img->imageId << " " << std::hex << img->GetInsOffset(ip) << " (" << ip << ")"
					<< std::endl;
			}

			const ADDRINT pltAddress = pltTargetAddress;
			const ADDRINT functionAddress = PIN_GetContextReg(context, REG_RAX);
			auto functionImage = GetImageByAddress(functionAddress);
			const UINT32 functionImageId = functionImage->imageId;
			const UINT64 functionOffset = functionImage->GetInsOffset(functionAddress);

			// Map PLT address to the correct function address
			pltToRealFctStartMap[pltAddress] = functionAddress;

			// Change key of function state
			auto oldFunctionStateIt = _functionStates.find(pltAddress);
			if (oldFunctionStateIt == _functionStates.end())
			{
				CERR_ERROR << "[PLT] Could not find temporary function state entry indexed with PLT offset " << std::hex << pltAddress << std::endl;
				return;
			}

			FunctionData* functionState = oldFunctionStateIt->second;
			_functionStates.erase(oldFunctionStateIt);

			// Reset current stack frame, in case the `push` instructions in the PLT were picked up
			auto& currentStackFrame = stackFrames.back();
			currentStackFrame->endAddress = currentStackFrame->startAddress;
			currentStackFrame->blockSize = 0;

			// Update image IDs/offsets in function's stack frames
			// We also need to refresh the observed stack frame sizes, in case it was changed by the current one
			UINT64 maxFunctionStackFrameSize = 0;
			for (const auto& stackFrame : functionState->stackFrameMemoryBlocks)
			{
				stackFrame->imageId = functionImageId;
				stackFrame->offset = functionOffset;

				if (stackFrame->blockSize > maxFunctionStackFrameSize)
					maxFunctionStackFrameSize = stackFrame->blockSize;

				stackFrame->functionStartAddress = functionAddress;
			}

			functionState->maximumFrameSize = maxFunctionStackFrameSize;

			// Save updated function state
			// Check whether there is already a function state from an earlier PLT resolution process, so we don't lose information
			auto existingFunctionStateIt = _functionStates.find(functionAddress);
			if (existingFunctionStateIt != _functionStates.end())
			{
				// We need to merge the new state into the existing one
				FunctionData* existingState = existingFunctionStateIt->second;

				existingState->instructionsAndStackOffsets.insert(functionState->instructionsAndStackOffsets.begin(), functionState->instructionsAndStackOffsets.end());
				existingState->stackFrameMemoryBlocks.insert(functionState->stackFrameMemoryBlocks.begin(), functionState->stackFrameMemoryBlocks.end());

				if (existingState->maximumFrameSize < functionState->maximumFrameSize)
					existingState->maximumFrameSize = functionState->maximumFrameSize;

				delete functionState;
			}
			else
			{
				// Just store the new state
				functionState->startAddress = functionAddress;
				_functionStates[functionAddress] = functionState;
			}

			_pltState = PLT_STATE_LINKING_DONE;
			CERR_DEBUG
				<< "[PLT] Switching to PLT_STATE_LINKING_DONE: "
				<< std::hex
				<< " waiting for reaching resolved function " << functionImageId << " " << functionImage->GetInsOffset(functionAddress) << " (" << functionAddress << ")"
				<< std::endl;

		}
		return;
	}

	// Update call stack
	// Never remove the root element
	if (callstack.size() == 0)
	{
		if (libcImgId == 0)
		{
			CERR_DEBUG << "Unbalanced callstack, skipping return at "
				<< img->imageId << " " << std::hex << img->GetInsOffset(ip)
				<< ". Likely a call ld->libc was ignored"
				<< std::endl;
		}
		else
		{
			CERR_WARNING << "Unbalanced callstack, skipping return at " << img->imageId << " " << std::hex << img->GetInsOffset(ip)
				<< std::endl;
		}
		return;
	}
	callstack.pop_back();

	// Cleanup stack frame
	if (stackFrames.empty())
	{
		CERR_WARNING << "Return, but empty stack frame list in " << img->imageId << " " << std::hex << img->GetInsOffset(ip) << ", skipping" << std::endl;

		return;
	}

	auto currentFrame = stackFrames.back();
	currentFrame->active = false;
	stackFrames.pop_back();

	if (blockIdToRemainingFrameLengthMap[currentFrame->blockId] != 0)
	{
		CERR_WARNING
			<< "Remaining size " << std::hex << blockIdToRemainingFrameLengthMap[currentFrame->blockId]
			<< " of stack frame " << currentFrame->imageId << " " << currentFrame->offset
			<< " at ret " << img->imageId << " " << img->GetInsOffset(ip)
			<< std::endl;
	}
}

VOID HandlePltExit(ADDRINT branchTargetAddress, ADDRINT ip, const ImageData* img)
{
	// There are three cases:
	// 1. We have already seen a `call func@plt -> jmp func` sequence and thus know the mapping
	//    -> Nothing to do here, stack frame setup is in generic jmp handler
	// 2. Lazy binding: Linking is not done yet
	//    -> Nothing to do here, lazy linking is handled in generic jmp handler
	// 3. Eager binding: The linking is already done, but we have never observed a call
	//    -> We need to record the plt/function address mapping

	if (_pltState == PLT_STATE_INVALID)
	{
		CERR_ERROR << "[PLT] Unexpected .plt exit: "
			<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
			<< " -> " << img->imageId << " " << img->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
			<< std::endl;

		PIN_ExitProcess(-1);

		return;
	}

	// Ignore case 1
	if (pltToRealFctStartMap.find(pltTargetAddress) != pltToRealFctStartMap.end())
	{
		_pltState = PLT_STATE_INVALID;
		CERR_DEBUG
			<< "[PLT] Switching to PLT_STATE_INVALID: "
			<< std::hex << img->imageId << " " << img->GetInsOffset(ip) << " (" << ip << ")"
			<< " -> " << GetImageByAddress(branchTargetAddress)->imageId << " " << GetImageByAddress(branchTargetAddress)->GetInsOffset(branchTargetAddress) << " (" << branchTargetAddress << ")"
			<< std::endl;

		return;
	}

	// Ignore case 2
	if (_pltState == PLT_STATE_STUB || _pltState == PLT_STATE_LINKING || _pltState == PLT_STATE_LINKING_DONE)
		return;

	// We only care for jumps from .plt to normal code
	auto tgtImg = GetImageByAddress(branchTargetAddress);
	UINT32 tgtImgId = tgtImg->imageId;
	if (AddressInPlt(branchTargetAddress))
		return;

	const ADDRINT pltAddress = pltTargetAddress;
	const ADDRINT functionAddress = branchTargetAddress;
	auto functionImage = tgtImg;
	const UINT32 functionImageId = tgtImgId;
	const UINT64 functionOffset = functionImage->GetInsOffset(functionAddress);

	// Map PLT address to the correct function address
	pltToRealFctStartMap[pltAddress] = functionAddress;

	// Change key of function state
	auto oldFunctionStateIt = _functionStates.find(pltAddress);
	if (oldFunctionStateIt == _functionStates.end())
	{
		CERR_ERROR << "[PLT] Could not find temporary function state entry indexed with PLT offset " << std::hex << pltAddress << std::endl;
		return;
	}

	FunctionData* functionState = oldFunctionStateIt->second;
	_functionStates.erase(oldFunctionStateIt);

	// Update image IDs/offsets in function's stack frames
	for (auto& stackFrame : functionState->stackFrameMemoryBlocks)
	{
		stackFrame->imageId = functionImageId;
		stackFrame->offset = functionOffset;
		stackFrame->functionStartAddress = functionAddress;
	}

	// Save updated function state
	// Check whether there is already a function state from an earlier PLT resolution process, so we don't lose information
	auto existingFunctionStateIt = _functionStates.find(functionAddress);
	if (existingFunctionStateIt != _functionStates.end())
	{
		// We need to merge the new state into the existing one
		FunctionData* existingState = existingFunctionStateIt->second;

		existingState->instructionsAndStackOffsets.insert(functionState->instructionsAndStackOffsets.begin(), functionState->instructionsAndStackOffsets.end());
		existingState->stackFrameMemoryBlocks.insert(functionState->stackFrameMemoryBlocks.begin(), functionState->stackFrameMemoryBlocks.end());

		if (existingState->maximumFrameSize < functionState->maximumFrameSize)
			existingState->maximumFrameSize = functionState->maximumFrameSize;

		delete functionState;
	}
	else
	{
		// Just store the new state
		functionState->startAddress = functionAddress;
		_functionStates[functionAddress] = functionState;
	}

	// PLT call done 
	_pltState = PLT_STATE_INVALID;
	CERR_DEBUG
		<< "[PLT] Switching to PLT_STATE_INVALID: "
		<< std::hex << img->imageId << " " << img->GetInsOffset(ip)
		<< " -> " << tgtImgId << " " << tgtImg->GetInsOffset(branchTargetAddress)
		<< std::endl;

}

VOID GetCallstack()
{
	// We take all entries that belong to the allocation for which we called GetCallstack()
	// Compare to blockId - 1 as the counter has been changed directly after adding memory block entry
	UINT64 currentBlockId = blockId - 1;

	for (auto it = callstack.rbegin(); it != callstack.rend(); ++it)
	{
		CallstackEntry* entry = (*it);
		auto copy = new CallstackEntry(
			entry->sourceImageId,
			entry->sourceImageOffset,
			entry->targetImageId,
			entry->targetImageOffset,
			entry->sourceAddress,
			entry->targetAddress,
			currentBlockId
		);
		callstackEntries.push_back(copy);
	}
}

const ImageData* GetImageByAddress(UINT64 address)
{
	for (const auto& img : images)
	{
		if (img->imageStartAddress <= address && address < img->imageEndAddress)
			return img;
	}

	return _invalidImage;
}

const ImageData* GetImageById(UINT32 id)
{
	for (const auto& img : images)
	{
		if (img->imageId == id)
			return img;
	}

	return _invalidImage;
}

VOID SetKeySize(ADDRINT keySz)
{
	keySize = keySz;
}

inline BOOL AddressIsTainted(ADDRINT address)
{
	// Get the taint value at the memory address
	return !tag_is_empty(tagmap_getb(address));
}

VOID RegisterIsTainted(THREADID tid, ADDRINT address)
{
	RegisterTaintStatus& taintStatusData = insAddrToRegTaintStatusMap[address];

	// Get the taint status of all registers for the instruction at address "address"
	for (auto& reg : regs)
	{
		for (UINT32 i = 0; i < REG_Size(reg); ++i)
		{
			if (!(tag_is_empty(RTAG[REG_INDX(reg)][i])))
			{
				taintStatusData.SecretRegs.insert(reg);
				break;
			}
		}
	}
}

inline PltSection* GetPltSectionForAddress(ADDRINT address)
{
	for (const auto& sec : _pltSections)
	{
		if (sec->startAddress <= address && address < sec->endAddress)
			return sec;
	}

	return nullptr;
}

bool AddressInPlt(ADDRINT address)
{
	return GetPltSectionForAddress(address) != nullptr;
}

VOID ClearGlobals(ADDRINT mainStartAddress, CONTEXT* context)
{
	// Clear the contents
	sources.clear();
	blockIdToRemainingFrameLengthMap.clear();

	callstackEntries.clear();
	callstack.clear();
	memoryBlocks.clear(); // TODO memory leak: Free all that are not in inputMemoryBlockData
	activeNonStackMemoryBlocks.clear();
	syscallData.clear();
	mitigationInsToAccessTypeMap.clear();
	mitigationInsAddrtoDisasMap.clear();

	for (auto& functionStateIt : _functionStates)
		functionStateIt.second->stackFrameMemoryBlocks.clear();

	// Free instruction objects
	for (auto instruction : instructions)
		delete instruction;
	instructions.clear();

	// Clear instruction lists in input memory blocks
	for (auto memoryBlock : inputMemoryBlockData)
		memoryBlock->instructionAddresses.clear();

	// Re-initialize if needed
	memoryBlocks = inputMemoryBlockData;
	activeNonStackMemoryBlocks = inputMemoryBlockData;

	// Initialize the callstack with a root entry
	callstack.push_back(new CallstackEntry(
		0, 0, 0, 0, 0, 0, 0
	));

	// thread_ctx_init() would bring multiple calls of PIN_AddThreadStartFunction
	(void)memset(ins_desc, 0, sizeof(ins_desc));

	// Clear the taint tag values in BDDTag object
	ClearTags();

	CERR_INFO << "######################## Leaving prefix ########################" << std::endl;
	CERR_INFO << "   Cleared all global variables." << std::endl;

	_pltState = PLT_STATE_INVALID;
	CERR_DEBUG << "[PLT] Switching to PLT_STATE_INVALID in ClearGlobals." << std::endl;

	// Add new stack frame for main
	UINT64 rspVal = PIN_GetContextReg(context, REG_RSP);
	auto targetImg = GetImageByAddress(mainStartAddress);
	UINT32 targetImgId = targetImg->imageId;

	AllocateNewStackFrame(mainStartAddress, targetImgId, targetImg->GetInsOffset(mainStartAddress), rspVal);
}

VOID TaintStatusRegisters(INT32 code, VOID* v)
{
	TaintRegResults << "[INFO] Taint status registers results: insAddr, imgId, insOffset, regs" << std::endl;

	int ctr = 0;
	for (const auto& ins : insAddrToRegTaintStatusMap)
	{
		if (!ins.second.SecretRegs.empty())
			ctr++;
	}
	TaintRegResults << std::dec << ctr << std::endl;

	for (const auto& ins : insAddrToRegTaintStatusMap)
	{
		if (!ins.second.SecretRegs.empty())
		{
			TaintRegResults << std::hex << ins.first << "\t";
			TaintRegResults << std::dec << disasAddrToImgIdMap[ins.first] << "\t";
			TaintRegResults << std::hex << GetImageById(disasAddrToImgIdMap[ins.first])->GetInsOffset(ins.first) << "\t";
			for (const auto& reg : ins.second.SecretRegs)
			{
				TaintRegResults << REG_StringShort(REG_FullRegName(reg)) << "\t";
			}
			TaintRegResults << std::endl;
		}
	}

	TaintRegResults.close();
}

VOID StoreMemoryTrace()
{
	_memoryAccessFile.write(reinterpret_cast<char*>(&_memoryTraceEntries[0]), _memoryTraceEntryIndex * sizeof(_memoryTraceEntries[0]));

	_memoryTraceEntryIndex = 0;
}

VOID StoreMemoryTraceBefore(UINT64 address)
{
	_lastAccessedAddress = address;
}

VOID StoreMemoryTraceAfter(UINT64 rip, UINT32 width)
{
	if (_memoryTraceEntryIndex == _memoryTraceEntryCount)
		StoreMemoryTrace();

	auto image = GetImageByAddress(rip);
	UINT64 offset = image->GetInsOffset(rip);

	if (image == _invalidImage || image->imageId == ldImgId)
		return;

	bool isSecret = false;
	for (UINT32 i = 0; i < width; ++i)
	{
		if (AddressIsTainted(_lastAccessedAddress + i))
		{
			isSecret = true;
			break;
		}
	}

	auto nextMemoryTraceEntry = &_memoryTraceEntries[_memoryTraceEntryIndex];
	nextMemoryTraceEntry->_imageId = image->imageId;
	nextMemoryTraceEntry->_offset = offset;
	nextMemoryTraceEntry->_width = width;
	nextMemoryTraceEntry->_secret = isSecret ? 1 : 0;

	++_memoryTraceEntryIndex;
}

VOID StoreReadAccessInfoBefore(ADDRINT ea, ADDRINT ip, UINT32 size)
{
	currentReadAccessAddress = ea;

	bool isSecret = false;
	for (UINT32 i = 0; i < size; ++i)
	{
		if (AddressIsTainted(currentReadAccessAddress + i))
		{
			isSecret = true;
			break;
		}
	}

	AccessSecrecyData* accessSecrecy;
	const auto& search = insAddrToAccessInfoMap.find(ip);
	if (search != insAddrToAccessInfoMap.end())
	{
		accessSecrecy = search->second;
	}
	else
	{
		accessSecrecy = new AccessSecrecyData();
		accessSecrecy->ip = ip;
		accessSecrecy->width = size;
		insAddrToAccessInfoMap[ip] = accessSecrecy;
	}

	isSecret ? accessSecrecy->secretReadCount++ : accessSecrecy->publicReadCount++;
}

VOID StoreWriteAccessInfoBefore(ADDRINT ea)
{
	currentWriteAccessAddress = ea;
}

VOID StoreWriteAccessInfoAfter(ADDRINT ip, UINT32 size)
{
	bool isSecret = false;
	for (UINT32 i = 0; i < size; ++i)
	{
		if (AddressIsTainted(currentWriteAccessAddress + i))
		{
			isSecret = true;
			break;
		}
	}

	AccessSecrecyData* accessSecrecy;
	const auto& search = insAddrToAccessInfoMap.find(ip);
	if (search != insAddrToAccessInfoMap.end())
	{
		accessSecrecy = search->second;
	}
	else
	{
		accessSecrecy = new AccessSecrecyData();
		accessSecrecy->width = size;
		accessSecrecy->ip = ip;
		insAddrToAccessInfoMap[ip] = accessSecrecy;
	}

	isSecret ? accessSecrecy->secretWriteCount++ : accessSecrecy->publicWriteCount++;
}


VOID Fini(INT32 code, VOID* v)
{

	// Write pending memory access trace entries
	if (enableMemoryAccessTrace)
	{
		StoreMemoryTrace();
		_memoryAccessFile.close();
	}

	CERR_DEBUG << "pltToFunctionStart (plt -> start)" << std::endl;
	for (const auto& addr : pltToRealFctStartMap)
	{
		auto pltImg = GetImageByAddress(addr.first);
		UINT64 pltOff = pltImg->GetInsOffset(addr.first);
		auto funImg = GetImageByAddress(addr.second);
		UINT64 funOff = funImg->GetInsOffset(addr.second);
		CERR_DEBUG << "   " << std::hex << pltImg->imageId << " " << pltOff << "\t-> " << funImg->imageId << " " << funOff << std::endl;
	}

	std::stringstream ss;

	// Print the image information
	CERR_INFO << "Printing image information." << std::endl;
	ss << "[INFO] Image information: id, size, name, start, end" << std::endl;
	ss << images.size() << std::endl;
	for (const auto& img : images)
	{
		ss << img->imageId << "\t";
		ss << std::hex << img->imageSize << "\t";
		ss << img->imageName << "\t";
		ss << std::hex << img->imageStartAddress << "\t";
		ss << std::hex << img->imageEndAddress << std::endl;
	}

	TraceFile << ss.rdbuf() << std::flush;


	// Collect functions that have a non-empty stack frame
	std::vector<FunctionData*> functionStatesWithStackFrame;
	for (const auto& fct : _functionStates)
	{
		auto functionState = fct.second;
		if (!functionState->stackFrameMemoryBlocks.empty() && GetImageByAddress(functionState->startAddress)->imageId != ldImgId)
			functionStatesWithStackFrame.push_back(functionState);
	}

	// Print stack frames
	CERR_INFO << "Printing stack frame information." << std::endl;
	ss << "[INFO] Stack Block information: imgId, off, blkSz, secOffCount, offsets" << std::endl;
	ss << std::dec << functionStatesWithStackFrame.size() << std::endl;

	std::unordered_map<UINT64, std::set<UINT64>> secretStackOffsetsPerFunction;
	for (const auto functionState : functionStatesWithStackFrame)
	{
		// Merge secret offsets of all stack frames of this function
		std::set<UINT64> secOffs;
		for (const auto& stackFrame : functionState->stackFrameMemoryBlocks)
		{
			secOffs.insert(stackFrame->secretOffsets.begin(), stackFrame->secretOffsets.end());
		}

		secretStackOffsetsPerFunction[functionState->startAddress] = secOffs;

		auto functionImage = GetImageByAddress(functionState->startAddress);

		ss << std::dec << functionImage->imageId << "\t"
			<< std::hex << functionImage->GetInsOffset(functionState->startAddress) << "\t"
			<< std::hex << functionState->maximumFrameSize << "\t"
			<< std::dec << secOffs.size() << "\t";

		for (const auto& off : secOffs)
			ss << std::hex << off << "\t";

		ss << std::endl;
	}

	TraceFile << ss.rdbuf() << std::flush;


	// Collect heap objects and static variables
	std::vector<MemoryBlockData*> nonStackMemoryBlocks;
	for (auto memoryBlock : memoryBlocks)
	{
		if (memoryBlock->blockType != MemoryBlockType::STACK)
			nonStackMemoryBlocks.push_back(memoryBlock);
	}

	// Print heap objects and static variables
	CERR_INFO << "Printing heap object and static variables information." << std::endl;
	ss << "[INFO] Heap object and static variables information: imgId, off, blkId, blkSz, start, end, type, sec, act" << std::endl;
	ss << std::dec << nonStackMemoryBlocks.size() << std::endl;

	for (auto memoryBlock : nonStackMemoryBlocks)
	{
		// Memory block output
		ss << memoryBlock->imageId << "\t"
			<< std::hex << memoryBlock->offset << "\t"
			<< std::dec << memoryBlock->blockId << "\t"
			<< std::hex << memoryBlock->blockSize << "\t"
			<< std::hex << memoryBlock->startAddress << "\t"
			<< std::hex << memoryBlock->endAddress << "\t"
			<< static_cast<UINT64>(memoryBlock->blockType) << "\t"
			<< memoryBlock->secret << "\t"
			<< memoryBlock->active
			<< std::endl;
	}

	TraceFile << ss.rdbuf() << std::flush;


	// Print callstack information.
	CERR_INFO << "Printing callstack information." << std::endl;
	ss << "[INFO] Callstack entries: srcImgId, srcOffset, tgtImgId, tgtOffset, srcAddr, tgtAddr, blockId" << std::endl;
	ss << std::dec << callstackEntries.size() << std::endl;
	for (const auto& entry : callstackEntries)
	{
		ss << std::dec << entry->sourceImageId << "\t"
			<< std::hex << entry->sourceImageOffset << "\t"
			<< std::dec << entry->targetImageId << "\t"
			<< std::hex << entry->targetImageOffset << "\t"
			<< std::hex << entry->sourceAddress << "\t"
			<< std::hex << entry->targetAddress << "\t"
			<< std::dec << entry->blockId << std::endl;
	}

	TraceFile << ss.rdbuf() << std::flush;


	// Create map with fresh instruction objects
	// Each instruction only appears once.
	std::unordered_map<UINT64, InstructionData*> mergedInstructions;

	// Create lookup for instruction address/memory address pairs
	std::unordered_map<InstructionMemoryAddressPair, InstructionData*> instructionLookup;

	for (auto instructionData : instructions)
	{
		// Ignore segment and PLT/GOT accesses that could not be resolved to memory blocks
		if (instructionData->isUnresolvableSegmentOrPltGotAccess)
			continue;

		// Store in lookup
		for (UINT32 i = 0; i < instructionData->instructionSize; ++i)
			instructionLookup[InstructionMemoryAddressPair(instructionData->instructionAddress, instructionData->memoryAddress + i)] = instructionData;

		// Record new merged instruction, if no one exists yet
		auto mergedInstructionIt = mergedInstructions.find(instructionData->instructionAddress);
		if (mergedInstructionIt == mergedInstructions.end())
		{
			mergedInstructions[instructionData->instructionAddress] = new InstructionData
			(
				instructionData->instructionAddress,
				instructionData->instructionSize,
				instructionData->imageId,
				0,
				instructionData->offset,
				nullptr,
				instructionData->accessType,
				0
			);
		}
		else
		{
			// Merge access type
			auto mergedInstruction = mergedInstructionIt->second;
			mergedInstruction->accessType |= instructionData->accessType;
		}
	}

	// Update access type for all stack accesses, by comparing the stack offsets of stack accessing instructions with
	// the secret offsets
	for (const auto functionState : functionStatesWithStackFrame)
	{
		auto& secretStackOffsets = secretStackOffsetsPerFunction[functionState->startAddress];
		for (const auto& instructionAndStackOffset : functionState->instructionsAndStackOffsets)
		{
			// Find merged instruction
			auto mergedInstructionIt = mergedInstructions.find(instructionAndStackOffset.first);
			if (mergedInstructionIt != mergedInstructions.end())
			{
				// Is this an access to a secret offset?
				if (secretStackOffsets.find(instructionAndStackOffset.second) != secretStackOffsets.end())
					mergedInstructionIt->second->accessType |= AccessType::SECRET;
			}
			else
			{
				auto instructionImage = GetImageByAddress(instructionAndStackOffset.first);
				CERR_ERROR << "Can't find merged instruction when checking stack access: "
					<< std::hex << instructionImage->imageId << " " << instructionImage->GetInsOffset(instructionAndStackOffset.first)
					<< std::endl;
			}
		}
	}

	// Update access type for all heap/image accesses
	for (auto memoryBlock : nonStackMemoryBlocks)
	{
		AccessType blockAccessType = memoryBlock->secret ? AccessType::SECRET : AccessType::PUBLIC;

		for (const auto& instructionAddress : memoryBlock->instructionAddresses)
		{
			mergedInstructions[instructionAddress]->accessType |= blockAccessType;
		}
	}

	// Collect all instructions that are relevant for instrumentation, i.e. that touch secret data
	std::vector<InstructionData*> interestingInstructions;
	for (auto& mergedInstruction : mergedInstructions)
	{
		auto instruction = mergedInstruction.second;

		if ((instruction->accessType & AccessType::SECRET) == AccessType::SECRET)
		{
			interestingInstructions.push_back(instruction);
		}
		else if (instruction->accessType == AccessType::NONE)
		{
			CERR_WARNING << "Instruction with access type NONE: "
				<< std::hex << instruction->imageId << " " << instruction->offset
				<< std::endl;
		}
	}

	// Print the instruction information.
	CERR_INFO << "   Instructions to be secured: " << std::dec << interestingInstructions.size() << std::endl;

	CERR_INFO << "Printing instruction information." << std::endl;
	ss << "[INFO] Instructions: addr, imgId, offset, size, access type" << std::endl;
	ss << std::dec << interestingInstructions.size() << std::endl;

	for (const auto& inst : interestingInstructions)
	{
		ss << std::hex << inst->instructionAddress << "\t"
			<< inst->imageId << "\t"
			<< inst->offset << "\t"
			<< inst->instructionSize << "\t"
			<< (int)inst->accessType
			<< std::endl;
	}

	TraceFile << ss.rdbuf() << std::flush;

	// Output information about secrecy of memory accesses
	if (enableAccessSecrecyTracking)
	{
		CERR_INFO << "Printing access secrecy information." << std::endl;

		ss << "[INFO] Access Secrecy: ins (img, offset), width, secretReads, secretWrites, publicReads, publicWrites" << std::endl;

		// Sort instruction info by total count
		std::vector<AccessSecrecyData*> accessSecrecyData;
		for (const auto& ins : insAddrToAccessInfoMap)
		{
			ins.second->totalCount = ins.second->secretReadCount + ins.second->secretWriteCount + ins.second->publicReadCount + ins.second->publicWriteCount;
			accessSecrecyData.push_back(ins.second);
		}
		std::sort(accessSecrecyData.begin(), accessSecrecyData.end(), [=](const AccessSecrecyData* a, const AccessSecrecyData* b)
			{
				return a->totalCount < b->totalCount;
			});

		ss << std::dec << interestingInstructions.size() << std::endl;
		for (const AccessSecrecyData* ins : accessSecrecyData) // TODO iterate over interestingInstructions and search map, should be more efficient
		{
			for (const auto& out : interestingInstructions)
			{
				if (out->instructionAddress == ins->ip)
				{
					auto img = GetImageByAddress(ins->ip);
					ss << std::hex << img->imageId << "\t"
						<< img->GetInsOffset(ins->ip) << "\t" << std::dec
						<< std::setw(4) << ins->width << "\t"
						<< std::setw(4) << ins->secretReadCount << "\t"
						<< std::setw(4) << ins->secretWriteCount << "\t"
						<< std::setw(4) << ins->publicReadCount << "\t"
						<< std::setw(4) << ins->publicWriteCount << "\t"
						<< std::endl;
				}
			}
		}
		TraceFile << ss.rdbuf() << std::flush;
	}

	if (enableTrackTaintedRegs)
	{
		CERR_INFO << "Printing register taint status information." << std::endl;
		ss << "[INFO] Taint status registers results: insAddr, imgId, insOffset, regs" << std::endl;

		int ctr = 0;
		for (const auto& ins : insAddrToRegTaintStatusMap)
		{
			if (!ins.second.SecretRegs.empty())
				ctr++;
		}
		ss << std::dec << ctr << std::endl;

		for (const auto& ins : insAddrToRegTaintStatusMap)
		{
			if (!ins.second.SecretRegs.empty())
			{
				ss << std::hex << ins.first << "\t"
					<< std::dec << disasAddrToImgIdMap[ins.first] << "\t"
					<< std::hex << GetImageById(disasAddrToImgIdMap[ins.first])->GetInsOffset(ins.first) << "\t";
				for (const auto& reg : ins.second.SecretRegs)
				{
					ss << REG_StringShort(REG_FullRegName(reg)) << "\t";
				}
				ss << std::endl;
			}
		}

		TraceFile << ss.rdbuf() << std::flush;
	}


	if (enableTrackSyscalls)
	{
		// TODO: this only considers non-stack blocks; print instructions that touch secret blocks
		std::vector<SyscallData*> secretSyscallInputs;

		for (const auto& blk : memoryBlocks)
		{
			if (blk->secret)
			{
				// Check whether we input encrypted data to syscalls
				ADDRINT blockStart = blk->startAddress;
				ADDRINT blockEnd = blk->endAddress;

				for (const auto& call : syscallData)
				{
					// Iterate over the 6 syscall args
					ADDRINT arg0 = call->arg0;
					bool s0 = arg0 >= blockStart && arg0 < blockEnd;
					ADDRINT arg1 = call->arg1;
					bool s1 = arg1 >= blockStart && arg1 < blockEnd;
					ADDRINT arg2 = call->arg2;
					bool s2 = arg2 >= blockStart && arg2 < blockEnd;
					ADDRINT arg3 = call->arg3;
					bool s3 = arg3 >= blockStart && arg3 < blockEnd;
					ADDRINT arg4 = call->arg4;
					bool s4 = arg4 >= blockStart && arg4 < blockEnd;
					ADDRINT arg5 = call->arg5;
					bool s5 = arg5 >= blockStart && arg5 < blockEnd;

					if (s0 || s1 || s2 || s3 || s4 || s5)
					{
						CERR_INFO << "[!]     Found encrypted syscall data in block " << blk->blockId << "." << std::endl;
						secretSyscallInputs.push_back(call);
					}
				}
			}
		}
	}

	// Close the trace file.
	TraceFile.close();
}

// [Callback] Instruments instruction from a given sequence of basic blocks.
static void InstrumentTrace(TRACE trace, VOID* v)
{
	// Traverse basic blocks
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		auto image = GetImageByAddress(BBL_Address(bbl));
		UINT64 imageId = image->imageId;

		// Traverse instructions
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			ADDRINT instructionAddress = INS_Address(ins);
			xed_iclass_enum_t instructionType = (xed_iclass_enum_t)INS_Opcode(ins);

			// Install memory access trace handler
			if (enableMemoryAccessTrace)
			{
				if (INS_IsMemoryWrite(ins) && !INS_IsControlFlow(ins))
				{
					INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)StoreMemoryTraceBefore,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)StoreMemoryTraceAfter,
						IARG_INST_PTR,
						IARG_MEMORYWRITE_SIZE,
						IARG_END);
				}
			}

			// Trace access secrecy information for memory reads and writes
			if (enableAccessSecrecyTracking)
			{
				if (INS_IsMemoryRead(ins) && !INS_IsControlFlow(ins))
				{
					INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)StoreReadAccessInfoBefore,
						IARG_MEMORYREAD_EA,
						IARG_INST_PTR,
						IARG_MEMORYREAD_SIZE,
						IARG_END);
				}
				if (INS_IsMemoryWrite(ins) && !INS_IsControlFlow(ins))
				{
					INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)StoreWriteAccessInfoBefore,
						IARG_MEMORYWRITE_EA,
						IARG_END);
					INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)StoreWriteAccessInfoAfter,
						IARG_INST_PTR,
						IARG_MEMORYWRITE_SIZE,
						IARG_END);
				}
			}

			/*
			 * Install generic handlers for call, jmp and ret
			 * Those do the call stack and stack frame handling, and also detect PLT calls.
			*/

			if (INS_IsCall(ins) && INS_IsControlFlow(ins))
			{
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(HandleGenericCall),
					IARG_BRANCH_TARGET_ADDR,
					IARG_CONST_CONTEXT,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			if (instructionType == XED_ICLASS_JMP && INS_IsValidForIpointTakenBranch(ins))
			{
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(HandleGenericJmp),
					IARG_BRANCH_TARGET_ADDR,
					IARG_CONST_CONTEXT,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			if (INS_IsRet(ins) && INS_IsControlFlow(ins))
			{
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(HandleGenericRet),
					IARG_CONST_CONTEXT,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			// No further tracking in the dynamic linker
			if (imageId == ldImgId)
				continue;

			// Handle jumps from .plt section to normal code
			if (instructionType == XED_ICLASS_JMP && INS_IsValidForIpointTakenBranch(ins) && AddressInPlt(instructionAddress))
			{
				INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(HandlePltExit),
					IARG_BRANCH_TARGET_ADDR,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}


			/*
			 * Check if instruction interacts with the stack
			 */

			 // TODO This only detects instructions that explicitly use RBP/RSP; other pointers are not detected
			 // This should be moved into the generic write call back, where we check for stack memory anyway
			if (INS_IsStackWrite(ins) && !INS_IsCall(ins) && instructionType != XED_ICLASS_PUSH)
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AdjustCurrentStackFrameRedZone),
					IARG_MEMORYWRITE_EA,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			if (instructionType == XED_ICLASS_PUSH)
			{
				// Adjust the new end of stack frame
				ADDRINT subSize = 8;
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AdjustCurrentStackFrame),
					IARG_CONST_CONTEXT,
					IARG_ADDRINT, subSize,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			if (instructionType == XED_ICLASS_SUB && REG(INS_OperandReg(ins, 0)) == REG_RSP)
			{
				// Adjust the new end of stack frame
				if (INS_OperandIsImmediate(ins, 1))
				{
					ADDRINT subSize = INS_OperandImmediate(ins, 1);
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AdjustCurrentStackFrame),
						IARG_CONST_CONTEXT,
						IARG_ADDRINT, subSize,
						IARG_INST_PTR,
						IARG_PTR, image,
						IARG_END);
				}
				else if (INS_OperandIsReg(ins, 1))
				{
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(AdjustCurrentStackFrame),
						IARG_CONST_CONTEXT,
						IARG_REG_VALUE, INS_OperandReg(ins, 1),
						IARG_INST_PTR,
						IARG_PTR, image,
						IARG_END);
				}
				else
				{
					CERR_ERROR
						<< std::dec << imageId << " " << std::hex << image->GetInsOffset(instructionAddress)
						<< " sub rsp, but unsupported operand type"
						<< std::endl;
				}
			}

			if (instructionType == XED_ICLASS_POP)
			{
				ADDRINT addSize = 8;
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TrackStackFramesAddPop),
					IARG_ADDRINT, addSize,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			if (instructionType == XED_ICLASS_ADD && REG(INS_OperandReg(ins, 0)) == REG_RSP)
			{
				if (INS_OperandIsImmediate(ins, 1))
				{
					ADDRINT addSize = INS_OperandImmediate(ins, 1);
					INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TrackStackFramesAddPop),
						IARG_ADDRINT, addSize,
						IARG_INST_PTR,
						IARG_PTR, image,
						IARG_END);
				}
				else
				{
					CERR_ERROR
						<< std::dec << imageId << " " << std::hex << image->GetInsOffset(instructionAddress)
						<< " add rsp, but unsupported operand type"
						<< std::endl;
				}
			}

			if (instructionType == XED_ICLASS_LEAVE)
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TrackStackFramesLeave),
					IARG_CONST_CONTEXT,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			if (instructionType == XED_ICLASS_LEA && REG(INS_OperandReg(ins, 0)) == REG_RSP)
			{
				INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(TrackStackFramesLea),
					IARG_CONST_CONTEXT,
					IARG_EXPLICIT_MEMORY_EA,
					IARG_INST_PTR,
					IARG_PTR, image,
					IARG_END);
			}

			// Trace instructions with memory read
			// Use the *PredicatedCall instrumentation, so we only log memory accesses which are actually executed (e.g. cmov)
			if (!INS_IsControlFlow(ins) && INS_IsMemoryRead(ins) && INS_IsStandardMemop(ins))
			{
				// Add read to set of reads for block
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
					IARG_UINT32, MemoryAccessCallBackIndex::READ1,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA,
					IARG_MEMORYREAD_SIZE,
					IARG_PTR, image,
					IARG_BOOL, INS_SegmentPrefix(ins),
					IARG_END);

				// Check taint status of the address read and mark block
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(UpdateBlockTaintStatus),
					IARG_UINT32, MemoryAccessCallBackIndex::READ1,
					IARG_THREAD_ID,
					IARG_CALL_ORDER, CALL_ORDER_LAST,
					IARG_END);
			}

			// Trace instructions with a second memory read operand
			if (!INS_IsControlFlow(ins) && INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins))
			{
				// Add read to set of reads for block
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
					IARG_UINT32, MemoryAccessCallBackIndex::READ2,
					IARG_INST_PTR,
					IARG_MEMORYREAD2_EA,
					IARG_MEMORYREAD_SIZE,
					IARG_PTR, image,
					IARG_BOOL, INS_SegmentPrefix(ins),
					IARG_END);

				// Check taint status of the address read and mark block
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(UpdateBlockTaintStatus),
					IARG_UINT32, MemoryAccessCallBackIndex::READ2,
					IARG_THREAD_ID,
					IARG_CALL_ORDER, CALL_ORDER_LAST,
					IARG_END);
			}

			// Trace instructions with memory write
			if (!INS_IsControlFlow(ins) && INS_IsMemoryWrite(ins) && INS_IsStandardMemop(ins))
			{
				// Add write to set of writes for block
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
					IARG_UINT32, MemoryAccessCallBackIndex::WRITE,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYWRITE_SIZE,
					IARG_PTR, image,
					IARG_BOOL, INS_SegmentPrefix(ins),
					IARG_END);

				// Check taint status of the address written and mark block
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(UpdateBlockTaintStatus),
					IARG_UINT32, MemoryAccessCallBackIndex::WRITE,
					IARG_THREAD_ID,
					IARG_CALL_ORDER, CALL_ORDER_LAST,
					IARG_END);
			}

			// For control flow instructions, there is no taint status update after their execution
			if (INS_IsControlFlow(ins) && INS_IsMemoryRead(ins) && !INS_IsCall(ins) && !INS_IsRet(ins))
			{
				// Add read to set of reads for block
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
					IARG_UINT32, MemoryAccessCallBackIndex::CONTROL_FLOW,
					IARG_INST_PTR,
					IARG_MEMORYREAD_EA,
					IARG_MEMORYREAD_SIZE,
					IARG_PTR, image,
					IARG_BOOL, INS_SegmentPrefix(ins),
					IARG_END);
			}

			if (INS_IsControlFlow(ins) && INS_HasMemoryRead2(ins) && !INS_IsCall(ins) && !INS_IsRet(ins))
			{
				// Add read to set of reads for block
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
					IARG_UINT32, MemoryAccessCallBackIndex::CONTROL_FLOW,
					IARG_INST_PTR,
					IARG_MEMORYREAD2_EA,
					IARG_MEMORYREAD_SIZE,
					IARG_PTR, image,
					IARG_BOOL, INS_SegmentPrefix(ins),
					IARG_END);
			}

			if (INS_IsControlFlow(ins) && INS_IsMemoryWrite(ins) && !INS_IsCall(ins) && !INS_IsRet(ins))
			{
				// Add write to set of writes for block
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(InsertMemoryReadWriteEntry),
					IARG_UINT32, MemoryAccessCallBackIndex::CONTROL_FLOW,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_EA,
					IARG_MEMORYWRITE_SIZE,
					IARG_PTR, image,
					IARG_BOOL, INS_SegmentPrefix(ins),
					IARG_END);
			}

			/*
			 * Track register taint information for every instruction
			 */
			if (enableTrackTaintedRegs)
			{
				// Check taint status each time the instruction is executed
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RegisterIsTainted,
					IARG_THREAD_ID,
					IARG_INST_PTR,
					IARG_END);
			}

			xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

			/*
			 * invoke the pre-ins instrumentation callback;
			 * optimized branch
			 */
			if (unlikely(ins_desc[ins_indx].pre != nullptr))
				ins_desc[ins_indx].pre(ins);

			// Do the taint analysis part.
			ins_inspect(ins);

			/*
			 * invoke the post-ins instrumentation callback;
			 * optimized branch
			 */
			if (unlikely(ins_desc[ins_indx].post != nullptr))
				ins_desc[ins_indx].post(ins);
		}
	}
}


/*
 * add a new pre-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the pre-ins handler
 *
 * returns:     0 on success, 1 on error
 */
int ins_set_pre(ins_desc_t* desc, void (*pre)(INS))
{
	// sanity checks
	if (unlikely((desc == nullptr) | (pre == nullptr)))
		// return with failure
		return 1;

	// update the pre-ins callback
	desc->pre = pre;

	// success
	return 0;
}

/*
 * add a new post-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the post-ins handler
 *
 * returns:     0 on success, 1 on error
 */
int ins_set_post(ins_desc_t* desc, void (*post)(INS))
{
	// sanity checks
	if (unlikely((desc == nullptr) | (post == nullptr)))
		/* return with failure */
		return 1;

	// update the post-ins callback
	desc->post = post;

	// success
	return 0;
}

/*
 * remove the pre-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 * returns:     0 on success, 1 on error
 */
int ins_clr_pre(ins_desc_t* desc)
{
	// sanity check
	if (unlikely(desc == nullptr))
		/* return with failure */
		return 1;

	// clear the pre-ins callback
	desc->pre = nullptr;

	// return with success
	return 0;
}

/*
 * remove the post-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 * returns:     0 on success, 1 on error
 */
int ins_clr_post(ins_desc_t* desc)
{
	/* sanity check */
	if (unlikely(desc == nullptr))
		// return with failure
		return 1;

	// clear the post-ins callback
	desc->post = nullptr;

	// return with success
	return 0;
}

/*
 * thread start callback (analysis function)
 *
 * allocate space for the syscall context and VCPUs (i.e., thread context)
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @flags:	OS specific flags for the new thread
 * @v:		callback value
 */
static void thread_alloc(THREADID tid, CONTEXT* ctx, INT32 flags, VOID* v)
{
	// store the old threads context
	thread_ctx_t* tctx_prev = threads_ctx;

	/*
	 * we need more thread contexts; optimized branch (not so frequent);
	 *
	 * NOTE: in case the tid is greater than tctx_ct + THREAD_CTX_BLK we
	 * need to loop in order to allocate enough thread contexts
	 */
	while (unlikely(tid >= tctx_ct))
	{
		// reallocate space; optimized branch
		if (unlikely((threads_ctx = (thread_ctx_t*)realloc(
			threads_ctx, (tctx_ct + THREAD_CTX_BLK) *
			sizeof(thread_ctx_t))) == nullptr))
		{
			// failed; this is fatal we need to terminate

			// cleanup
			free(tctx_prev);

			// error message
			fprintf(stderr, "%s:%u", __func__, __LINE__);

			// die
			libdft_die();
		}

		// success; patch the counter
		tctx_ct += THREAD_CTX_BLK;
	}
}

static void post_read_hook(THREADID tid, syscall_ctx_t* ctx)
{
	/* read() was not successful; optimized branch */
	const size_t ret = ctx->ret;
	if (unlikely(ret <= 0))
		return;

	const int fd = ctx->arg[SYSCALL_ARG0];
	const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
	//    size_t count = ctx->arg[SYSCALL_ARG2];

	CERR_INFO << "[TAINT] Secret from file address found: " << std::hex << buf << std::endl;
	CERR_INFO << "[TAINT] Secret from file size: " << std::dec << ret << std::endl;

	/* taint-source */
	unsigned int read_off = 0;
	if (fd == STDIN_FILENO)
	{
		read_off = stdin_read_off;
		stdin_read_off += ret;
	}

	AddReadSecret(ret, buf, read_off);

	tagmap_setb_reg(tid, DFT_REG_RAX, 0, 1);
}

/*
 * syscall enter notification (analysis function)
 *
 * save the system call context and invoke any pre-syscall callback
 * functions that have been registered
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void sysenter_save(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v)
{
	// get the syscall number
	size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);

	if (enableTrackSyscalls) {
		// Save the syscall arguments in order to check whether we pipe encrypted data into calls
		SysBefore_CheckArgsEncrypted(PIN_GetContextReg(ctx, REG_INST_PTR),
			PIN_GetSyscallNumber(ctx, std),
			(ADDRINT)syscall_desc[syscall_nr].nargs,
			PIN_GetSyscallArgument(ctx, std, 0),
			PIN_GetSyscallArgument(ctx, std, 1),
			PIN_GetSyscallArgument(ctx, std, 2),
			PIN_GetSyscallArgument(ctx, std, 3),
			PIN_GetSyscallArgument(ctx, std, 4),
			PIN_GetSyscallArgument(ctx, std, 5));
	}

	// unknown syscall; optimized branch
	if (unlikely(syscall_nr >= SYSCALL_MAX)) {
		fprintf(stderr, "%s:%u: unknown syscall(num=%lu)\n", __func__, __LINE__, syscall_nr);
		// syscall number is set to -1; hint for the sysexit_save()
		threads_ctx[tid].syscall_ctx.nr = -1;
		// no context save and no pre-syscall callback invocation
		return;
	}

	// pass the system call number to sysexit_save()
	threads_ctx[tid].syscall_ctx.nr = syscall_nr;

	/*
	 * check if we need to save the arguments for that syscall
	 *
	 * we save only when we have a callback registered or the syscall
	 * returns a value in the arguments
	 */
	if (syscall_desc[syscall_nr].save_args | syscall_desc[syscall_nr].retval_args)
	{
		/*
		 * dump only the appropriate number of arguments
		 * or yet another lame way to avoid a loop (vpk)
		 */
		switch (syscall_desc[syscall_nr].nargs)
		{
			/* 6 */
			case SYSCALL_ARG5 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG5] =
					PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG5);
				/* 5 */
			case SYSCALL_ARG4 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG4] =
					PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG4);
				/* 4 */
			case SYSCALL_ARG3 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG3] =
					PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG3);
				/* 3 */
			case SYSCALL_ARG2 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG2] =
					PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG2);
				/* 2 */
			case SYSCALL_ARG1 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG1] =
					PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG1);
				/* 1 */
			case SYSCALL_ARG0 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG0] =
					PIN_GetSyscallArgument(ctx, std, SYSCALL_ARG0);
			default:
				break;
		}

		/*
		 * dump the architectural state of the processor;
		 * saved as "auxiliary" data
		 */
		threads_ctx[tid].syscall_ctx.aux = ctx;

		// call the pre-syscall callback (if any); optimized branch
		// This cannot be used for checking whether the syscall arguments are tainted
		// We would need to register every possible syscall
		if (unlikely(syscall_desc[syscall_nr].pre != nullptr))
			syscall_desc[syscall_nr].pre(tid, &threads_ctx[tid].syscall_ctx);
	}
}

/*
 * syscall exit notification (analysis function)
 *
 * save the system call context and invoke any post-syscall callback
 * functions that have been registered
 *
 * NOTE: it performs tag cleanup for the syscalls that have side effects in
 * their arguments
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
static void sysexit_save(THREADID tid, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v)
{
	// iterator
	size_t i;

	// get the syscall number
	int syscall_nr = threads_ctx[tid].syscall_ctx.nr;

	// Track heap size
	if (unlikely(syscall_nr == 12)) // brk()
	{
		ADDRINT brk = PIN_GetSyscallReturn(ctx, std);
		if (brk < _brkMin)
			_brkMin = brk;
		if (brk > _brkMax)
			_brkMax = brk;
	}

	// unknown syscall; optimized branch
	if (unlikely(syscall_nr < 0))
	{
		fprintf(stderr, "%s:%u: unknown syscall(num=%d)\n", __func__, __LINE__, syscall_nr);
		// no context save and no pre-syscall callback invocation
		return;
	}

	/*
	 * return value of a syscall is store in EAX, usually it is not a pointer
	 * So need to clean the tag of EAX, if it is, the post function should
	 * retag EAX
	 */

	 /*
	  * check if we need to save the arguments for that syscall
	  *
	  * we save only when we have a callback registered or the syscall
	  * returns a value in the arguments
	  */
	if (syscall_desc[syscall_nr].save_args | syscall_desc[syscall_nr].retval_args)
	{
		// dump only the appropriate number of arguments
		threads_ctx[tid].syscall_ctx.ret = PIN_GetSyscallReturn(ctx, std);

		/*
		 * dump the architectural state of the processor;
		 * saved as "auxiliary" data
		 */
		threads_ctx[tid].syscall_ctx.aux = ctx;

		/* thread_ctx[tid].syscall_ctx.errno =
		   PIN_GetSyscallErrno(ctx, std); */

		   // call the post-syscall callback (if any)
		if (syscall_desc[syscall_nr].post != nullptr)
		{
			syscall_desc[syscall_nr].post(tid, &threads_ctx[tid].syscall_ctx);
		}
		else
		{
			// default post-syscall handling

			/*
			 * the syscall failed; typically 0 and positive
			 * return values indicate success
			 */
			if (threads_ctx[tid].syscall_ctx.ret < 0)
				// no need to do anything
				return;

			// traverse the arguments map
			for (i = 0; i < syscall_desc[syscall_nr].nargs; i++)
				// analyze each argument
				if (unlikely(syscall_desc[syscall_nr].map_args[i] > 0))
					// sanity check -- probably not needed
					if (likely((void*)threads_ctx[tid].syscall_ctx.arg[i] != nullptr))
						/*
						 * argument i is changed by the system call;
						 * the length of the change is given by
						 * map_args[i]
						 */
						tagmap_clrn(threads_ctx[tid].syscall_ctx.arg[i], syscall_desc[syscall_nr].map_args[i]);
		}
	}
}


/*
 * initialize thread contexts
 *
 * allocate space for the thread contexts and
 * register a thread start callback
 *
 * returns: 0 on success, 1 on error
 */
static inline int thread_ctx_init()
{
	/* allocate space for the thread contexts; optimized branch
	 *
	 * NOTE: allocation is performed in blocks of THREAD_CTX_BLK
	 */
	threads_ctx = new thread_ctx_t[THREAD_CTX_BLK]();

	if (unlikely(threads_ctx == nullptr))
	{
		fprintf(stderr, "%s:%u", __func__, __LINE__);
		// failed
		libdft_die();
		return 1;
	}

	// initialize the context counter
	tctx_ct = THREAD_CTX_BLK;

	/*
	 * thread start hook;
	 * keep track of the threads and allocate space for the per-thread
	 * logistics (i.e., syscall context, VCPU, etc)
	 */
	PIN_AddThreadStartFunction(thread_alloc, nullptr);

	// success
	return 0;
}

// Handles an internal exception of this trace tool.
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO* exceptionInfo, PHYSICAL_CONTEXT* physicalContext, VOID* v)
{
	// Output exception data
	CERR_ERROR << "Internal exception: " << PIN_ExceptionToString(exceptionInfo) << std::endl;
	return EHR_UNHANDLED;
}