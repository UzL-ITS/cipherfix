/* INCLUDES */

#include "pin.H"
#include "../src/branch_pred.h"
#include "../src/libdft_api.h"
#include "../src/Utilities.h"

#include <iostream>


/* GLOBAL VARIABLES */

// The output file command line option.
KNOB <std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "taint.out", "specify trace file name");

// The input file command line option.
KNOB <std::string> KnobInputFile(KNOB_MODE_WRITEONCE, "pintool", "in", "", "specify input file name");

// The read system calls as taint source command line option.
KNOB <int> KnobReadSource(KNOB_MODE_WRITEONCE, "pintool", "r", "0", "take read system calls as taint source");

// The system calls tracking command line option.
KNOB <int> KnobTrackSyscalls(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "track system calls (for mitigation)");

/* CALLBACK PROTOTYPES */

/* FUNCTIONS */

// The main procedure of the tool
int main(int argc, char* argv[]) {

    // Initialize PIN library
    if(PIN_Init(argc, argv)) {
        // Print help message if -h(elp) is specified in the command line or the command line is invalid
        std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
        return -1;
    }

    const char *traceFile = KnobOutputFile.Value().c_str();
    const char *infile = KnobInputFile.Value().c_str();
    int readSyscalls = KnobReadSource.Value();
    int trackSyscalls = KnobTrackSyscalls.Value();

    // Initialize the core tagging engine
    if (unlikely(libdft_init(traceFile, infile, readSyscalls, trackSyscalls) != 0))
        // Failed
        goto err;

    // Start the target program
    PIN_StartProgram();
    // Typically not reached; make the compiler happy
    return EXIT_SUCCESS;

    err: // Error handling
    // Detach from the process
    libdft_die();
    // Return
    return EXIT_FAILURE;
}

/* CALLBACKS */

