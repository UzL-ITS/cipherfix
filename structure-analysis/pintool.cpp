/* INCLUDES */

#include <pin.H>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <unordered_map>
#include <unordered_set>


/* UTILITY TYPES */

class BasicBlockData
{
public:
	UINT64 BaseAddress;
	UINT64 Size;
	BOOL HasFallThrough;

	BasicBlockData(UINT64 baseAddress, UINT64 size, BOOL hasFallThrough)
		: BaseAddress(baseAddress), Size(size), HasFallThrough(hasFallThrough)
	{	}
};

enum struct StatusFlags
{
	None = 0,
	C = 1 << 0,
	P = 1 << 1,
	A = 1 << 2,
	Z = 1 << 3,
	S = 1 << 4,
	O = 1 << 5
};
inline StatusFlags operator|(StatusFlags a, StatusFlags b)
{
	return static_cast<StatusFlags>(static_cast<int>(a) | static_cast<int>(b));
}
inline StatusFlags operator&(StatusFlags a, StatusFlags b)
{
	return static_cast<StatusFlags>(static_cast<int>(a) & static_cast<int>(b));
}
inline void operator|=(StatusFlags& a, StatusFlags b)
{
	a = a | b;
}

enum struct Registers : uint64_t {
	None = 0ull,
	RAX = 1ull << 0,
	RBX = 1ull << 1,
	RCX = 1ull << 2,
	RDX = 1ull << 3,
	RDI = 1ull << 4,
	RSI = 1ull << 5,
	RBP = 1ull << 6,
	RSP = 1ull << 7,
	R8 = 1ull << 8,
	R9 = 1ull << 9,
	R10 = 1ull << 10,
	R11 = 1ull << 11,
	R12 = 1ull << 12,
	R13 = 1ull << 13,
	R14 = 1ull << 14,
	R15 = 1ull << 15,
	YMM0 = 1ull << 16,
	YMM1 = 1ull << 17,
	YMM2 = 1ull << 18,
	YMM3 = 1ull << 19,
	YMM4 = 1ull << 20,
	YMM5 = 1ull << 21,
	YMM6 = 1ull << 22,
	YMM7 = 1ull << 23,
	YMM8 = 1ull << 24,
	YMM9 = 1ull << 25,
	YMM10 = 1ull << 26,
	YMM11 = 1ull << 27,
	YMM12 = 1ull << 28,
	YMM13 = 1ull << 29,
	YMM14 = 1ull << 30,
	YMM15 = 1ull << 31,
};
inline Registers operator|(Registers a, Registers b)
{
	return static_cast<Registers>(static_cast<UINT64>(a) | static_cast<UINT64>(b));
}
inline Registers operator&(Registers a, Registers b)
{
	return static_cast<Registers>(static_cast<UINT64>(a) & static_cast<UINT64>(b));
}
inline void operator|=(Registers& a, Registers b)
{
	a = a | b;
}

class InstructionData
{
public:
	Registers ReadRegisters = Registers::None;
	Registers WriteRegisters = Registers::None;
	Registers KeepRegisters = Registers::None;

	StatusFlags ReadFlags = StatusFlags::None;
	StatusFlags PotentialWriteFlags = StatusFlags::None;
	StatusFlags WriteFlags = StatusFlags::None;
	StatusFlags KeepFlags = StatusFlags::None;

	InstructionData() {}
};

class RegisterState
{
public:
	Registers Register;
	std::string Name;

	// Actually holds InstructionData* pointers.
	// TODO This should be std::tr1::unordered_set, but for some reason std::set is faster?
	std::set<uintptr_t> InstructionsExecutedSinceLastWrite;

	RegisterState(Registers reg, std::string name)
		: Register(reg), Name(name)
	{}
};

class FlagState
{
public:
	StatusFlags Flag;
	std::string Name;

	// Actually holds InstructionData* pointers.
	// TODO This should be std::tr1::unordered_set, but for some reason std::set is faster?
	std::set<uintptr_t> InstructionsExecutedSinceLastWrite;

	InstructionData* LastWritingInstruction = 0;

	FlagState(StatusFlags flag, std::string name)
		: Flag(flag), Name(name)
	{}
};

// Hash function for registers.
struct RegHash
{
	size_t operator() (const REG r) const
	{
		return static_cast<size_t>(r);
	}
};


/* GLOBAL VARIABLES */

// The output file command line option.
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "out", "specify output file path");

// All identified basic blocks.
std::vector<BasicBlockData> _basicBlocks;

// Register usage counts.
std::tr1::unordered_map<REG, int, RegHash> _registerCounts;

// Mapping of Pin registers to the Registers enum.
std::map<REG, Registers> _registerMapping;

// Instruction info.
std::tr1::unordered_map<UINT64, InstructionData*> _instructionData;

// Output file stream.
std::ofstream _outputFile;

// Number of the most recently entered system call.
ADDRINT _syscallNumber;

// Current state of register tracking.
std::vector<RegisterState*> _registerTrackingStates;

// Current state of flag tracking.
std::vector<FlagState*> _flagTrackingStates;

// Instruction addresses of relevant system calls.
std::set<UINT64> _syscalls;

// Some magic formatting strings.
std::string _colorRed = "\033[1;31m";
std::string _colorGreen = "\033[1;32m";
std::string _colorDefault = "\033[0m";


/* CALLBACK PROTOTYPES */

VOID InstrumentTrace(TRACE trace, VOID* v);
VOID InstrumentImage(IMG img, VOID* v);
VOID HandleSyscallEntry(THREADID tid, CONTEXT* context, SYSCALL_STANDARD std, VOID* v);
VOID HandleSyscallExit(THREADID tid, CONTEXT* context, SYSCALL_STANDARD std, VOID* v);
VOID OutputResults(INT32 exitCode, VOID* v);
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO* exceptionInfo, PHYSICAL_CONTEXT* physicalContext, VOID* v);


/* FUNCTIONS */

void tolower(std::string& str)
{
	std::transform(str.begin(), str.end(), str.begin(), [](unsigned char c) -> unsigned char { return std::tolower(c); });
}

// The main procedure of the tool.
int main(int argc, char* argv[])
{
	// Initialize PIN library
	if (PIN_Init(argc, argv))
	{
		// Print help message if -h(elp) is specified in the command line or the command line is invalid 
		std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
		return -1;
	}

	// Open output file stream
	_outputFile.open(KnobOutputFile.Value().c_str());

	// Initialize flag tracking
	_flagTrackingStates.push_back(new FlagState(StatusFlags::C, "C"));
	_flagTrackingStates.push_back(new FlagState(StatusFlags::P, "P"));
	_flagTrackingStates.push_back(new FlagState(StatusFlags::A, "A"));
	_flagTrackingStates.push_back(new FlagState(StatusFlags::Z, "Z"));
	_flagTrackingStates.push_back(new FlagState(StatusFlags::S, "S"));
	_flagTrackingStates.push_back(new FlagState(StatusFlags::O, "O"));

	// Initialize register tracking
	_registerMapping[REG_RAX] = Registers::RAX;
	_registerMapping[REG_RBX] = Registers::RBX;
	_registerMapping[REG_RCX] = Registers::RCX;
	_registerMapping[REG_RDX] = Registers::RDX;
	_registerMapping[REG_RDI] = Registers::RDI;
	_registerMapping[REG_RSI] = Registers::RSI;
	_registerMapping[REG_RBP] = Registers::RBP;
	_registerMapping[REG_RSP] = Registers::RSP;
	_registerMapping[REG_R8] = Registers::R8;
	_registerMapping[REG_R9] = Registers::R9;
	_registerMapping[REG_R10] = Registers::R10;
	_registerMapping[REG_R11] = Registers::R11;
	_registerMapping[REG_R12] = Registers::R12;
	_registerMapping[REG_R13] = Registers::R13;
	_registerMapping[REG_R14] = Registers::R14;
	_registerMapping[REG_R15] = Registers::R15;
	_registerMapping[REG_YMM0] = Registers::YMM0;
	_registerMapping[REG_YMM1] = Registers::YMM1;
	_registerMapping[REG_YMM2] = Registers::YMM2;
	_registerMapping[REG_YMM3] = Registers::YMM3;
	_registerMapping[REG_YMM4] = Registers::YMM4;
	_registerMapping[REG_YMM5] = Registers::YMM5;
	_registerMapping[REG_YMM6] = Registers::YMM6;
	_registerMapping[REG_YMM7] = Registers::YMM7;
	_registerMapping[REG_YMM8] = Registers::YMM8;
	_registerMapping[REG_YMM9] = Registers::YMM9;
	_registerMapping[REG_YMM10] = Registers::YMM10;
	_registerMapping[REG_YMM11] = Registers::YMM11;
	_registerMapping[REG_YMM12] = Registers::YMM12;
	_registerMapping[REG_YMM13] = Registers::YMM13;
	_registerMapping[REG_YMM14] = Registers::YMM14;
	_registerMapping[REG_YMM15] = Registers::YMM15;
	for (auto& regMapping : _registerMapping)
		_registerTrackingStates.push_back(new RegisterState(regMapping.second, REG_StringShort(regMapping.first)));

	// Instrument instructions and routines
	IMG_AddInstrumentFunction(InstrumentImage, 0);
	TRACE_AddInstrumentFunction(InstrumentTrace, 0);

	// Register syscall instrumentation callbacks
	PIN_AddSyscallEntryFunction(HandleSyscallEntry, NULL);
	PIN_AddSyscallExitFunction(HandleSyscallExit, NULL);

	// Handle internal exceptions (for debugging)
	PIN_AddInternalExceptionHandler(HandlePinToolException, NULL);

	// Output results at program end
	PIN_AddFiniFunction(OutputResults, NULL);

	// Load symbols to access function name information
	PIN_InitSymbols();

	// Start the target program
	PIN_StartProgram();
	return 0;
}


/* CALLBACKS */

// [Callback] Keeps track of used registers and flags.
VOID HandleInstructionExecuted(InstructionData* instructionData, UINT64 address)
{
	// Handle register accesses
	for (auto& regState : _registerTrackingStates)
	{
		// Does the instruction read this register?
		if (static_cast<UINT64>(instructionData->ReadRegisters & regState->Register))
		{
			// Update all instructions which were executed after the last write
			for (auto executedInstruction : regState->InstructionsExecutedSinceLastWrite)
				reinterpret_cast<InstructionData*>(executedInstruction)->KeepRegisters |= regState->Register;

			regState->InstructionsExecutedSinceLastWrite.clear();
		}

		// Does the instruction write this register?
		if (static_cast<UINT64>(instructionData->WriteRegisters & regState->Register))
		{
			// Reset access tracking
			regState->InstructionsExecutedSinceLastWrite.clear();
		}
		else
		{
			// Remember instruction
			regState->InstructionsExecutedSinceLastWrite.insert(reinterpret_cast<uintptr_t>(instructionData));
		}
	}

	// Handle flag accesses
	for (auto& flagState : _flagTrackingStates)
	{
		// Does the instruction read this flag?
		if (static_cast<int>(instructionData->ReadFlags & flagState->Flag))
		{
			// The flag was actually used, so store this in the writing instruction
			if (flagState->LastWritingInstruction != nullptr)
				flagState->LastWritingInstruction->WriteFlags |= flagState->Flag;

			// Update all instructions which were executed after the last write
			for (auto executedInstruction : flagState->InstructionsExecutedSinceLastWrite)
				reinterpret_cast<InstructionData*>(executedInstruction)->KeepFlags |= flagState->Flag;

			flagState->InstructionsExecutedSinceLastWrite.clear();
		}

		// Does the instruction write this flag?
		if (static_cast<int>(instructionData->PotentialWriteFlags & flagState->Flag))
		{
			// Reset access tracking
			flagState->InstructionsExecutedSinceLastWrite.clear();

			// Remember instruction address
			flagState->LastWritingInstruction = instructionData;
		}
		else
		{
			// Remember instruction
			flagState->InstructionsExecutedSinceLastWrite.insert(reinterpret_cast<uintptr_t>(instructionData));
		}
	}
}

// [Callback] Instruments basic blocks and instructions.
VOID InstrumentTrace(TRACE trace, VOID* v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		//std::cerr << "Instrumenting BBL " << std::setw(16) << std::setfill('0') << std::hex << BBL_Address(bbl) << std::endl;

		// Remember basic block
		_basicBlocks.push_back(BasicBlockData(BBL_Address(bbl), BBL_Size(bbl), BBL_HasFallThrough(bbl)));

		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			// Retrieve instruction data object
			InstructionData* instructionData;
			if (_instructionData.find(INS_Address(ins)) != _instructionData.end())
				instructionData = _instructionData[INS_Address(ins)];
			else
				_instructionData[INS_Address(ins)] = instructionData = new InstructionData();

			// Instrument instruction
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)HandleInstructionExecuted,
				IARG_PTR, instructionData,
				IARG_ADDRINT, INS_Address(ins),
				IARG_BOOL, INS_IsRet(ins),
				IARG_END);

			// Analyze read registers
			// Ignore some common idioms
			if (!(INS_Opcode(ins) == XED_ICLASS_XOR && INS_OperandCount(ins) == 3 && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) && INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1) && INS_OperandReg(ins, 2) == REG_RFLAGS) // xor reg, reg
				&& !(INS_Opcode(ins) == XED_ICLASS_PXOR && INS_OperandCount(ins) == 2 && INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) && INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) // pxor xmm, xmm
				)
			{
				// Analyze read registers
				for (UINT32 i = 0; i < INS_MaxNumRRegs(ins); ++i)
				{
					REG reg = INS_RegR(ins, i);
					if (REG_valid(reg))
					{
						REG fullReg = REG_FullRegName(reg);

						// Get matching register enum
						auto regMappingIt = _registerMapping.find(fullReg);
						if (regMappingIt == _registerMapping.end())
							continue;

						instructionData->ReadRegisters |= regMappingIt->second;
					}
				}
			}

			// Analyze write registers
			for (UINT32 i = 0; i < INS_MaxNumWRegs(ins); ++i)
			{
				REG reg = INS_RegW(ins, i);
				if (REG_valid(reg))
				{
					REG fullReg = REG_FullRegName(reg);

					// Get matching register enum
					auto regMappingIt = _registerMapping.find(fullReg);
					if (regMappingIt == _registerMapping.end())
						continue;

					instructionData->WriteRegisters |= regMappingIt->second;

					// If this is a partial register that doesn't zero-extend to the full register, record a read as well
					if (REG_is_gr8(reg) || REG_is_gr16(reg))
					{
						instructionData->ReadRegisters |= regMappingIt->second;
					}

					++_registerCounts[fullReg];
				}
			}

			// We have to manually apply the read registers for syscall instructions, as those are only part of the ABI
			if (INS_IsSyscall(ins))
			{
				if (INS_SyscallStd(ins) == SYSCALL_STANDARD::SYSCALL_STANDARD_IA32E_LINUX)
				{
					instructionData->ReadRegisters |= Registers::RDI;
					instructionData->ReadRegisters |= Registers::RSI;
					instructionData->ReadRegisters |= Registers::RDX;
					instructionData->ReadRegisters |= Registers::R10;
					instructionData->ReadRegisters |= Registers::R8;
					instructionData->ReadRegisters |= Registers::R9;
					instructionData->WriteRegisters |= Registers::RAX;
				}
			}

			// Analyze flags
			auto decodedInstruction = INS_XedDec(ins);
			auto flagInfo = xed_decoded_inst_get_rflags_info(decodedInstruction);
			if (flagInfo)
			{
				auto readFlags = xed_simple_flag_get_read_flag_set(flagInfo);
				StatusFlags instructionReadFlagData = StatusFlags::None;
				if (readFlags->s.cf)
					instructionReadFlagData |= StatusFlags::C;
				if (readFlags->s.pf)
					instructionReadFlagData |= StatusFlags::P;
				if (readFlags->s.af)
					instructionReadFlagData |= StatusFlags::A;
				if (readFlags->s.zf)
					instructionReadFlagData |= StatusFlags::Z;
				if (readFlags->s.sf)
					instructionReadFlagData |= StatusFlags::S;
				if (readFlags->s.of)
					instructionReadFlagData |= StatusFlags::O;
				instructionData->ReadFlags = instructionReadFlagData;

				auto writeFlags = xed_simple_flag_get_written_flag_set(flagInfo);
				StatusFlags instructionWriteFlagData = StatusFlags::None;
				if (writeFlags->s.cf)
					instructionWriteFlagData |= StatusFlags::C;
				if (writeFlags->s.pf)
					instructionWriteFlagData |= StatusFlags::P;
				if (writeFlags->s.af)
					instructionWriteFlagData |= StatusFlags::A;
				if (writeFlags->s.zf)
					instructionWriteFlagData |= StatusFlags::Z;
				if (writeFlags->s.sf)
					instructionWriteFlagData |= StatusFlags::S;
				if (writeFlags->s.of)
					instructionWriteFlagData |= StatusFlags::O;
				instructionData->PotentialWriteFlags = instructionWriteFlagData;
			}
		}
	}
}

// [Callback] Stores image info.
VOID InstrumentImage(IMG img, VOID* v)
{
	_outputFile << "I"
		<< " " << std::setw(16) << std::setfill('0') << std::hex << IMG_LowAddress(img)
		<< " " << std::setw(16) << std::setfill('0') << std::hex << IMG_HighAddress(img)
		<< " " << IMG_Name(img)
		<< std::endl;
}

// [Callback] Handles entry of a system call.
VOID HandleSyscallEntry(THREADID tid, CONTEXT* context, SYSCALL_STANDARD std, VOID* v)
{
	// Check system call type
	_syscallNumber = PIN_GetSyscallNumber(context, std);
	switch (_syscallNumber)
	{
		case 9: // mmap
		{
			_syscalls.insert(PIN_GetContextReg(context, REG_RIP));

			std::cerr
				<< _colorDefault << std::hex << PIN_GetContextReg(context, REG_RIP) << ": "
				<< _colorGreen << "mmap"
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 0)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 1)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 2)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 3)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 4)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 5)
				<< _colorDefault;

			break;
		}

		case 11: // munmap
		{
			_syscalls.insert(PIN_GetContextReg(context, REG_RIP));

			std::cerr
				<< _colorDefault << std::hex << PIN_GetContextReg(context, REG_RIP) << ": "
				<< _colorGreen << "munmap"
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 0)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 1)
				<< _colorDefault;

			break;
		}

		case 25: // mremap
		{
			_syscalls.insert(PIN_GetContextReg(context, REG_RIP));

			std::cerr
				<< _colorDefault << std::hex << PIN_GetContextReg(context, REG_RIP) << ": "
				<< _colorGreen << "mremap"
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 0)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 1)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 2)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 3)
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 4)
				<< _colorDefault;

			break;
		}

		case 12: // brk
		{
			_syscalls.insert(PIN_GetContextReg(context, REG_RIP));

			std::cerr
				<< _colorDefault << std::hex << PIN_GetContextReg(context, REG_RIP) << ": "
				<< _colorGreen << "brk"
				<< _colorDefault << " "
				<< _colorRed << std::hex << PIN_GetSyscallArgument(context, std, 0)
				<< _colorDefault;


			break;
		}
	}
}

// [Callback] Handles exit of a system call.
VOID HandleSyscallExit(THREADID tid, CONTEXT* context, SYSCALL_STANDARD std, VOID* v)
{
	// Print return value of last system call
	switch (_syscallNumber)
	{
		case 9: //mmap
		case 11: //munmap
		case 12: // brk
		case 25: // mremap
		{
			std::cerr
				<< "  ->  "
				<< _colorRed << std::hex << PIN_GetSyscallReturn(context, std)
				<< _colorDefault
				<< std::endl;

			break;
		}
	}
}

// [Callback] Outputs analysis results.
VOID OutputResults(INT32 exitCode, VOID* v)
{
	// Note: This output may be skipped due to the child closing the I/O handles
	std::cerr << "Analysis done, writing results" << std::endl;

	// Sort basic blocks by address: Pin may instrument a basic block multiple times. We only output the _longest_ version of each encountered block that does overlap the next block
	std::sort(_basicBlocks.begin(), _basicBlocks.end(), [](BasicBlockData a, BasicBlockData b)
		{
			if (a.BaseAddress == b.BaseAddress)
				return a.Size < b.Size;
			return a.BaseAddress < b.BaseAddress;
		});

	// First, find longest version of each block
	std::vector<BasicBlockData> uniqueBasicBlocks;
	for (size_t i = 0; i < _basicBlocks.size(); ++i)
	{
		UINT64 startAddress = _basicBlocks[i].BaseAddress;
		UINT64 size = _basicBlocks[i].Size;
		BOOL hasFallThrough = _basicBlocks[i].HasFallThrough;

		// Iterate through subsequent blocks that have the same start address
		for (; i < _basicBlocks.size() - 1; ++i)
		{
			if (_basicBlocks[i + 1].BaseAddress == startAddress)
			{
				size = _basicBlocks[i + 1].Size;
				hasFallThrough |= _basicBlocks[i + 1].HasFallThrough;
			}
			else
			{
				break;
			}
		}

		uniqueBasicBlocks.push_back(BasicBlockData(startAddress, size, hasFallThrough));
	}

	for (size_t i = 0; i < uniqueBasicBlocks.size(); ++i)
	{
		UINT64 startAddress = uniqueBasicBlocks[i].BaseAddress;
		UINT64 endAddress = startAddress + uniqueBasicBlocks[i].Size;

		// Check whether the next basic block overlaps with the current one
		// -> start address of the next one is the end address of the current one
		if (i < uniqueBasicBlocks.size() - 1)
		{
			UINT64 nextBlockStartAddress = uniqueBasicBlocks[i + 1].BaseAddress;
			if (nextBlockStartAddress < endAddress)
				endAddress = nextBlockStartAddress;
		}

		if (startAddress < endAddress)
		{
			_outputFile << "B"
				<< " " << std::setw(16) << std::setfill('0') << std::hex << startAddress
				<< " " << std::setw(16) << std::setfill('0') << std::hex << endAddress
				<< " " << (uniqueBasicBlocks[i].HasFallThrough > 0 ? 1 : 0)
				<< std::endl;
		}
	}

	_outputFile << "#N                ";
	for (auto& flag : _flagTrackingStates)
	{
		_outputFile << " " << flag->Name << "  ";
	}
	for (auto& reg : _registerTrackingStates)
	{
		_outputFile << " " << reg->Name;
	}
	_outputFile << std::endl;

	for (auto& instructionData : _instructionData)
	{
		// Instruction address
		_outputFile << "N"
			<< " " << std::setw(16) << std::setfill('0') << std::hex << instructionData.first;

		// Flags
		for (auto& flag : _flagTrackingStates)
		{
			_outputFile << " ";
			_outputFile << (static_cast<int>(instructionData.second->ReadFlags & flag->Flag) ? "r" : "-");
			_outputFile << (static_cast<int>(instructionData.second->WriteFlags & flag->Flag) ? "w" : "-");
			_outputFile << (static_cast<int>(instructionData.second->KeepFlags & flag->Flag) ? "k" : "-");
		}

		// Registers
		for (auto& reg : _registerTrackingStates)
		{
			_outputFile << " ";
			_outputFile << (static_cast<UINT64>(instructionData.second->ReadRegisters & reg->Register) ? "r" : "-");
			_outputFile << (static_cast<UINT64>(instructionData.second->WriteRegisters & reg->Register) ? "w" : "-");
			_outputFile << (static_cast<UINT64>(instructionData.second->KeepRegisters & reg->Register) ? "k" : "-");
		}

		_outputFile << std::endl;
	}

	for (auto& regData : _registerCounts)
	{
		_outputFile << "R"
			<< " " << REG_StringShort(regData.first)
			<< " " << std::dec << regData.second
			<< std::endl;
	}

	for (auto& syscallAddress : _syscalls)
	{
		_outputFile << "S"
			<< " " << std::setw(16) << std::setfill('0') << std::hex << syscallAddress
			<< std::endl;
	}

	_outputFile.close();
}

// [Callback] Handles an internal exception of this trace tool.
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO* exceptionInfo, PHYSICAL_CONTEXT* physicalContext, VOID* v)
{
	// Output exception data
	std::cerr << "Internal exception: " << PIN_ExceptionToString(exceptionInfo) << std::endl;
	return EHR_UNHANDLED;
}