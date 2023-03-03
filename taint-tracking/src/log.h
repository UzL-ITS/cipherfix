#ifndef __LOG_H__
#define __LOG_H__

#include <string>
#include <iostream>
#include "Utilities.h"

// Format strings for stderr.
extern const std::string _stderrPrefixDebug;
extern const std::string _stderrPrefixWarning;
extern const std::string _stderrPrefixError;
extern const std::string _stderrPrefixInfo;

enum LogLevel {
    LOG_LEVEL_DEBUG = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,
    LOG_LEVEL_INFO = 4,
};

extern LogLevel _logLevel;

#define CERR_DEBUG if(_logLevel > LOG_LEVEL_DEBUG) {} else std::cerr << _stderrPrefixDebug
#define CERR_WARNING if(_logLevel > LOG_LEVEL_WARNING) {} else std::cerr << _stderrPrefixWarning
#define CERR_ERROR if(_logLevel > LOG_LEVEL_ERROR) {} else std::cerr << _stderrPrefixError
#define CERR_INFO if(_logLevel > LOG_LEVEL_INFO) {} else std::cerr << _stderrPrefixInfo

// Utility macro for logging unknown opcodes in tainting logic.
#define LOG_UNHANDLED_OPCODE(ins) do {																	\
		xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);								\
		LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) + ")\n");			\
																										\
		auto insImage = GetImageByAddress(INS_Address(ins));											\
		CERR_ERROR << "[TAINT] Unhandled opcode "														\
		<< "'" << INS_Disassemble(ins) << "'"															\
		<< " at " << std::hex << insImage->imageId << " " << insImage->GetInsOffset(INS_Address(ins))	\
		<< " detected in '" << __func__ << "'"															\
		<< std::endl;																					\
	}																									\
	while(0)

#endif