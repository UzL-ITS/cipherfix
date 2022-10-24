#include "log.h"

// Format strings for stderr.
extern const std::string _stderrPrefixDebug = "[\033[36mDEBUG\033[0m] ";
extern const std::string _stderrPrefixWarning = "[\033[43;30mWARN\033[0m] ";
extern const std::string _stderrPrefixError = "[\033[41;97mERROR\033[0m] ";
extern const std::string _stderrPrefixInfo = "[INFO] ";

// Default log level.
LogLevel _logLevel = LogLevel::LOG_LEVEL_WARNING;

