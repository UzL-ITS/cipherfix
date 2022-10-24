#ifndef __LOG_H__
#define __LOG_H__

#include <string>

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

#endif