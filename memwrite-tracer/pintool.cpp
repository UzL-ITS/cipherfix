/* INCLUDES */

#include <pin.H>
#include <iostream>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <cctype>
#include <fstream>
#include <cstdlib>
#include <string>


/* UTILITY TYPES */

class ImageData
{
public:
	int Id;
	UINT64 Low;
	UINT64 High;
	bool Ignore;

	ImageData(int id, UINT64 low, UINT64 high, bool ignore)
		: Id(id), Low(low), High(high), Ignore(ignore) {}
};

class InterestingOffset
{
public:
	int ImageId;
	UINT64 Offset1;
	UINT64 Offset2;

	InterestingOffset(int imageId, UINT64 offset1, UINT64 offset2)
		: ImageId(imageId), Offset1(offset1), Offset2(offset2) {}
};


/* GLOBAL VARIABLES */

// The output file command line option.
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "out", "specify output file path");

// Interesting offset ranges.
KNOB<std::string> KnobInterestingOffsets(KNOB_MODE_WRITEONCE, "pintool", "offsets", "", "specify interesting offsets, e.g. <image1>.<offset1a>.<offset1a>;<image2>.<offset2a>.<offset2b>");

// Output file stream.
std::ofstream _outputFile;

// Stores the effective memory operand address of the current instruction.
UINT64 _currentMemoryOperandAddress;

// Image data.
std::vector<ImageData*> _images;

// Interesting offsets.
std::vector<InterestingOffset*> _interestingOffsets;

// Controls whether memory accesses are currently skipped (ignore sections).
bool _skipping = false;


/* CALLBACK PROTOTYPES */

VOID InstrumentTrace(TRACE trace, VOID* v);
VOID InstrumentImage(IMG img, VOID* v);
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO* exceptionInfo, PHYSICAL_CONTEXT* physicalContext, VOID* v);


/* FUNCTIONS */

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

	// Extract interesting offset ranges
	std::istringstream knobInterestingOffsetsValue(KnobInterestingOffsets.Value());
	std::string currentOffset;
	while (std::getline(knobInterestingOffsetsValue, currentOffset, ';'))
	{
		std::istringstream currentOffsetParts(currentOffset);
		std::string offsetImage;
		std::string offsetOffset1;
		std::string offsetOffset2;

		if(!std::getline(currentOffsetParts, offsetImage, '.') || !std::getline(currentOffsetParts, offsetOffset1, '.') || !std::getline(currentOffsetParts, offsetOffset2, '.'))
		{
			std::cerr << "Invalid offset list format" << std::endl;
			return -1;
		}

		auto interestingOffset = new InterestingOffset(atoi(offsetImage.c_str()), strtoull(offsetOffset1.c_str(), nullptr, 16), strtoull(offsetOffset2.c_str(), nullptr, 16));
		std::cerr << "Interesting offset " << std::dec << interestingOffset->ImageId << " " << std::hex << interestingOffset->Offset1 << " " << interestingOffset->Offset2 << std::endl;
		_interestingOffsets.push_back(interestingOffset);
	}

	// Instrument instructions and routines
	IMG_AddInstrumentFunction(InstrumentImage, 0);
	TRACE_AddInstrumentFunction(InstrumentTrace, 0);

	// Handle internal exceptions (for debugging)
	PIN_AddInternalExceptionHandler(HandlePinToolException, NULL);

	// Load symbols to access function name information
	PIN_InitSymbols();

	// Start the target program
	PIN_StartProgram();
	return 0;
}


/* CALLBACKS */

// [Callback] Stores the memory operand address of the current instruction.
VOID StoreInstructionMemoryOperandAddress(UINT64 effectiveAddress)
{
	_currentMemoryOperandAddress = effectiveAddress;
}

// [Callback] Prints executed instructions.
VOID HandleInstructionExecuted(CONTEXT* context, UINT64 rip, UINT32 width)
{
	if (_skipping)
		return;

	// Resolve image and check whether instruction should be ignored
	ImageData* image = nullptr;
	for (auto& imageData : _images)
	{
		if (imageData->Low <= rip && rip < imageData->High)
		{
			image = imageData;
			if (imageData->Ignore)
				return;

			break;
		}
	}

	// Skip unresolvable offsets
	if (image == nullptr)
		return;
	UINT64 imageOffset = rip - image->Low;

	// Check whether offset is interesting
	bool isInteresting = false;
	for(auto interestingOffset : _interestingOffsets)
	{
		if(interestingOffset->ImageId == image->Id && interestingOffset->Offset1 <= imageOffset && imageOffset < interestingOffset->Offset2)
		{
			isInteresting = true;
			break;
		}
	}

	if(!isInteresting)
	{
		_outputFile << "I"
			<< " " << std::hex << image->Id
			<< " " << std::hex << imageOffset
			<< " ?"
			<< std::endl;
		return;
	}

	UINT64 blockAddress = _currentMemoryOperandAddress & ~0xf;
	UINT64 lowerBits = _currentMemoryOperandAddress & 0xf;
	_outputFile << "I"
		<< " " << std::hex << image->Id
		<< " " << std::hex << imageOffset
		<< " " << std::hex << _currentMemoryOperandAddress
		<< " " << std::hex << blockAddress
		<< " " << std::hex << width
		<< " ";

	// Retrieve and dump written data
	UINT8* bytes = (UINT8*)(blockAddress);
	for (int i = 0; i < 16; ++i)
		_outputFile << std::setw(2) << std::hex << (int)bytes[i];

	// Does the access span two blocks?
	if (lowerBits + width > 0x10)
	{
		blockAddress += 0x10;
		_outputFile	<< " ";

		// Retrieve and dump written data
		bytes = (UINT8*)(blockAddress);
		for (int i = 0; i < 16; ++i)
			_outputFile << std::setw(2) << std::hex << (int)bytes[i];
	}

	_outputFile << std::endl;
}

// [Callback] Records the beginning of an ignore section.
VOID MarkIgnoreSectionBegin()
{
	_skipping = true;
}

// [Callback] Marks the begin of a contiguous instruction sequence.
VOID MarkSequenceSectionBegin()
{
	_outputFile << "Sb" << std::endl;
}

// [Callback] End marker.
VOID MarkSectionEnd()
{
	if (_skipping)
		_skipping = false;
	else
	{
		_outputFile << "Se" << std::endl;
	}
}

// [Callback] Instruments basic blocks and instructions.
VOID InstrumentTrace(TRACE trace, VOID* v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			// Skip call/ret instructions, as those do only write well-known addresses
			if (INS_IsControlFlow(ins))
				continue;

			// Instrument instruction if it performs a memory write
			if (INS_IsMemoryWrite(ins))
			{
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)StoreInstructionMemoryOperandAddress,
					IARG_MEMORYWRITE_EA,
					IARG_END);
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, (AFUNPTR)HandleInstructionExecuted,
					IARG_CONTEXT,
					IARG_INST_PTR,
					IARG_MEMORYWRITE_SIZE,
					IARG_END);
			}

			// Markers for instruction sequences
			if (INS_IsMovFullRegRegSame(ins) && INS_RegR(ins, 0) == REG_R11 && INS_RegW(ins, 0) == REG_R11)
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MarkIgnoreSectionBegin,
					IARG_END);
			}
			if (INS_IsMovFullRegRegSame(ins) && INS_RegR(ins, 0) == REG_R12 && INS_RegW(ins, 0) == REG_R12)
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MarkSequenceSectionBegin,
					IARG_END);
			}
			else if (INS_IsMovFullRegRegSame(ins) && INS_RegR(ins, 0) == REG_R13 && INS_RegW(ins, 0) == REG_R13)
			{
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MarkSectionEnd,
					IARG_END);
			}
		}
	}
}

// [Callback] Records image info.
VOID InstrumentImage(IMG img, VOID* v)
{
	std::string imageName = IMG_Name(img);
	bool ignore = imageName.find("/ld-") != imageName.npos;

	_images.push_back(new ImageData(IMG_Id(img), IMG_LowAddress(img), IMG_HighAddress(img), ignore));

	_outputFile << "L"
		<< " " << IMG_Id(img)
		<< " " << std::setw(16) << std::setfill('0') << std::hex << IMG_LowAddress(img)
		<< " " << std::setw(16) << std::setfill('0') << std::hex << IMG_HighAddress(img)
		<< " " << imageName
		<< std::endl;
}

// [Callback] Handles an internal exception of this trace tool.
EXCEPT_HANDLING_RESULT HandlePinToolException(THREADID tid, EXCEPTION_INFO* exceptionInfo, PHYSICAL_CONTEXT* physicalContext, VOID* v)
{
	// Output exception data
	std::cerr << "Internal exception: " << PIN_ExceptionToString(exceptionInfo) << std::endl;
	return EHR_UNHANDLED;
}
