CC=clang
CXX=clang++

LIBDFT_SRC			= src
LIBDFT_TOOL			= tools


.PHONY: all
all: dftsrc tool

.PHONY: dftsrc mytool
dftsrc: $(LIBDFT_SRC)
	cd $< && CPPFLAGS=$(CPPFLAGS) DFTFLAGS=$(LIBDFT_TAG_FLAGS) $(MAKE) -j

tool: $(LIBDFT_TOOL)
	cd $< && TARGET=intel64 CPPFLAGS=$(CPPFLAGS) DFTFLAGS=$(LIBDFT_TAG_FLAGS) $(MAKE) -j

.PHONY: clean
clean:
	cd $(LIBDFT_SRC) && $(MAKE) clean
	cd $(LIBDFT_TOOL) && $(MAKE) clean 
