using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using ElfTools;
using ElfTools.Chunks;
using ElfTools.Enums;
using ElfTools.Instrumentation;
using ElfTools.Utilities;
using Iced.Intel;

// ReSharper disable HeuristicUnreachableCode
#pragma warning disable 162

namespace StaticInstrumentation;

public static class Program
{
    private static string _inputDirectory;
    private static string _outputDirectory;

    private static AnalysisResult _analysisResult;
    private static BbToolResult _bbToolResult;
    private static readonly InstructionTranslator _instructionTranslator = new();
    private static readonly StackFrameInitializer _stackFrameInitializer = new();

    private static StreamWriter _mappingFileWriter;
    private static StreamWriter _ignoreFileWriter;

    private static HashSet<(int imageId, uint offset)> _pendingInstructions;
    private static Dictionary<(int imageId, uint offset), bool> _pendingHeapAllocationCalls;

    private static bool _debug;

    public const long ManagementObjectAddress = 0x700000000000;
    public const int ManagementObjectInt3HtListOffset = 0;
    public const int ManagementObjectInt3HtListCount = 16;
    public const int ManagementObjectHeaderAddrListOffset = ManagementObjectInt3HtListOffset + 8 * ManagementObjectInt3HtListCount;
    public const int ManagementObjectHeaderAddrListCount = 16;
    public const int ManagementObjectAllocTrackerOffset = ManagementObjectHeaderAddrListOffset + 8 * ManagementObjectHeaderAddrListCount;
    public const int ManagementObjectAllocTrackerSize = 8;

    public static void Main(string[] args)
    {
        if(args.Length < 2)
        {
            Console.WriteLine("Usage: <input directory> <mode> [<flags>]");
            Console.WriteLine("  Supported modes: base, fast, enhanced");
            return;
        }

        _inputDirectory = args[0];

        string mode = args[1];
        switch(mode)
        {
            case "base":
                MaskUtils.UseSecrecyBuffer = true;
                MaskUtils.AvoidSmallWrites = false;
                break;
            case "fast":
                MaskUtils.UseSecrecyBuffer = false;
                MaskUtils.AvoidSmallWrites = false;
                break;
            case "enhanced":
                MaskUtils.UseSecrecyBuffer = true;
                MaskUtils.AvoidSmallWrites = true;
                break;
            default:
                Console.WriteLine("Unsupported mode.");
                return;
        }

        string outDirSuffix = mode;
        if(args.Length > 2)
        {
            string[] argFlags = args[2].Split('-');

            MaskUtils.DebugForceZeroMask = argFlags.Contains("zeromask");
            MaskUtils.DebugForceConstantMask = !MaskUtils.DebugForceZeroMask && argFlags.Contains("constmask");
            AssemblerExtensions.DebugInsertMarkersForMaskingCode = argFlags.Contains("debugtracemarker");
            AssemblerExtensions.DebugInsertMarkersForMemtraceEvaluation = argFlags.Contains("evalmarker");
            _debug = argFlags.Contains("dumpinstr");

            outDirSuffix += $"-{args[2]}";
        }

        // Ensure output directory exists
        _outputDirectory = Path.Join(_inputDirectory, $"instr-{outDirSuffix}");
        if(!Directory.Exists(_outputDirectory))
            Directory.CreateDirectory(_outputDirectory);

        // Open mapping file
        _mappingFileWriter = new StreamWriter(File.Open(Path.Join(_outputDirectory, "map.txt"), FileMode.Create));
        _ignoreFileWriter = new StreamWriter(File.Open(Path.Join(_outputDirectory, "ignore.txt"), FileMode.Create));

        // Load analysis result
        _analysisResult = AnalysisResult.FromFile(Path.Join(_inputDirectory, "taint.out"));
        _pendingInstructions = _analysisResult.Instructions
            .Where(i => i.Value.HandlesSecretData)
            .Select(i => i.Key)
            .ToHashSet();

        // Load image and basic block data
        _bbToolResult = BbToolResult.FromFile(Path.Join(_inputDirectory, "structure.out"));

        // Find images to be instrumented
        List<(int imageId, string oldImageName, string oldImagePath, string newImageName, string newImagePath)> instrumentImages = new();
        foreach(var image in _bbToolResult.Images)
        {
            Console.WriteLine($"Checking image {image.Value.Name}...");

            // Skip images that should not be instrumented
            if(image.Value.Name.Contains("ld-linux-x86-64"))
            {
                Console.WriteLine("  Dynamic linker, skipping...");
                continue;
            }

            if(image.Value.Name.Contains("[vdso]"))
            {
                Console.WriteLine("  vDSO, skipping...");
                continue;
            }

            if(!File.Exists(image.Value.Path))
            {
                Console.WriteLine("  Could not locate file, skipping...");
                continue;
            }

            string oldName = image.Value.Name;
            string newName = oldName + ".instr";
            string newPath = Path.Join(_outputDirectory, newName);
            instrumentImages.Add((image.Value.Id, oldName, image.Value.Path, newName, newPath));
        }

        // The user needs to specify malloc() functions for all heap allocation call stacks
        var callStacksWithoutMalloc = _analysisResult.HeapMemoryBlocks
            .Where(b => b.Value.CallStack.Count > 0
                        && b.Value.CallStack
                            .All(c => !_bbToolResult.Mallocs.Contains((c.TargetImageId, (uint)c.TargetImageOffset))
                                      && !_bbToolResult.Reallocs.Contains((c.TargetImageId, (uint)c.TargetImageOffset))))
            .Select(b => b.Value.CallStack)
            .ToList();
        if(callStacksWithoutMalloc.Count > 0)
        {
            Console.WriteLine("Insufficient *alloc() information. Please specify a *alloc() function for each occuring call stack: \n  M* <address>");

            // Retrieve symbol tables of relevant ELF files, so we can show function names alongside the offsets, if possible
            Dictionary<int, List<SymbolTableParser>> symbolTablesPerImage = new();
            foreach(var image in instrumentImages)
            {
                var elf = ElfReader.Load(image.oldImagePath);

                var imageSymbolTables = new List<SymbolTableParser>();
                for(int s = 0; s < elf.SectionHeaderTable.SectionHeaders.Count; ++s)
                {
                    var sectionHeader = elf.SectionHeaderTable.SectionHeaders[s];

                    if(sectionHeader.Type is SectionType.SymbolTable or SectionType.DynamicSymbols)
                        imageSymbolTables.Add(new SymbolTableParser(elf, s));
                }

                symbolTablesPerImage.Add(image.imageId, imageSymbolTables);
            }

            // Show candidates
            HashSet<(int imageId, uint offset)> candidates = new();
            foreach(var block in _analysisResult.HeapMemoryBlocks)
            {
                if(block.Value.CallStack.Count == 0)
                    continue;

                // Always insert the bottom level call
                candidates.Add((block.Value.CallStack[0].TargetImageId, (uint)block.Value.CallStack[0].TargetImageOffset));

                // If there is a 2nd level, insert that as well
                if(block.Value.CallStack.Count > 1)
                    candidates.Add((block.Value.CallStack[1].TargetImageId, (uint)block.Value.CallStack[1].TargetImageOffset));
            }

            Console.WriteLine("Missing call stacks:");
            foreach(var callStack in callStacksWithoutMalloc)
            {
                for(var i = callStack.Count - 1; i >= 0; --i)
                {
                    var call = callStack[i];
                    var sourceImage = _bbToolResult.Images[call.SourceImageId];
                    var targetImage = _bbToolResult.Images[call.TargetImageId];

                    string targetImageSymbolName = "?";
                    if(symbolTablesPerImage.TryGetValue(targetImage.Id, out var targetImageSymbolTables))
                    {
                        // Look for symbol in the image's symbol tables
                        foreach(var symbolTable in targetImageSymbolTables)
                        {
                            var symbolName = symbolTable.QuerySymbol((ulong)call.TargetImageOffset);
                            if(symbolName != null)
                            {
                                targetImageSymbolName = symbolName;
                                break;
                            }
                        }
                    }

                    string candidateSuffix = candidates.Contains((call.TargetImageId, (uint)call.TargetImageOffset))
                        ? $" [M* {targetImage.BaseAddress + (uint)call.TargetImageOffset:x16}]"
                        : "";
                    Console.WriteLine($"  {sourceImage.Name}+{call.SourceImageOffset:x8} -> {targetImage.Name}+{call.TargetImageOffset:x8}{candidateSuffix} <{targetImageSymbolName}>");
                }

                Console.WriteLine(" --------------------------------");
            }

            Console.WriteLine("Candidates:");
            foreach(var candidate in candidates)
            {
                var image = _bbToolResult.Images[candidate.imageId];

                string symbolName = "?";
                if(symbolTablesPerImage.TryGetValue(image.Id, out var imageSymbolTables))
                {
                    // Look for symbol in the image's symbol tables
                    foreach(var symbolTable in imageSymbolTables)
                    {
                        var symbol = symbolTable.QuerySymbol(candidate.offset);
                        if(symbol != null)
                        {
                            symbolName = symbol;
                            break;
                        }
                    }
                }

                Console.WriteLine($"  {image.Name}+{candidate.offset:x8} <{symbolName}>: M* {image.BaseAddress + candidate.offset:x16}");
            }

            Console.WriteLine("Replace '*' by 'm' for malloc() and 'r' for realloc()");

            return;
        }

        // At the moment, the size of the heap call stack tracking bitfield is fixed
        int maxCallStackDepth = _analysisResult.HeapMemoryBlocks.Max(b => b.Value.CallStack.Count);
        if(maxCallStackDepth >= 64)
        {
            Console.WriteLine($"Error: Unsupported call stack depth of {maxCallStackDepth}");
            return;
        }

        // Collect all call instructions that are part of a heap allocation call stack
        _pendingHeapAllocationCalls = new Dictionary<(int imageId, uint offset), bool>();
        foreach(var heapMemoryBlock in _analysisResult.HeapMemoryBlocks)
        {
            for(var i = heapMemoryBlock.Value.CallStack.Count - 1; i >= 0; --i)
            {
                var callStackEntry = heapMemoryBlock.Value.CallStack[i];

                var sourceKey = (callStackEntry.SourceImageId, (uint)callStackEntry.SourceImageOffset);
                var targetKey = (callStackEntry.TargetImageId, (uint)callStackEntry.TargetImageOffset);

                if(_pendingHeapAllocationCalls.TryGetValue(sourceKey, out bool isSecret))
                {
                    // If the call is ever part of a call stack leading to an allocation of a secret block, mark it as such
                    if(!isSecret && heapMemoryBlock.Value.Secret)
                        _pendingHeapAllocationCalls[sourceKey] = true;
                }
                else
                {
                    _pendingHeapAllocationCalls.Add(sourceKey, heapMemoryBlock.Value.Secret);
                }

                // Do not instrument calls below the *alloc() call
                if(_bbToolResult.Mallocs.Contains(targetKey) || _bbToolResult.Reallocs.Contains(targetKey))
                    break;
            }
        }

        // Add dummy instructions to analysis result for stack frame handling
        foreach(var stackFrame in _analysisResult.StackFrames)
        {
            if(_analysisResult.Instructions.ContainsKey(stackFrame.Key))
                continue;

            _analysisResult.Instructions.Add(stackFrame.Key, new AnalysisResult.InstructionData
            {
                ImageId = stackFrame.Value.ImageId,
                ImageOffset = stackFrame.Value.ImageOffset,
                HandlesSecretData = false,
                AccessesOnlySecretBlocks = false,
                ReadRegisters = new HashSet<Register>(),
                WriteRegisters = new HashSet<Register>(),
                KeepRegisters = new HashSet<Register>(),
                ReadFlags = new HashSet<RflagsBits>(),
                WriteFlags = new HashSet<RflagsBits>(),
                KeepFlags = new HashSet<RflagsBits>()
            });
        }

        // Add dummy instructions to analysis result for call stack tracking
        foreach(var call in _pendingHeapAllocationCalls)
        {
            if(_analysisResult.Instructions.ContainsKey(call.Key))
                continue;

            _analysisResult.Instructions.Add(call.Key, new AnalysisResult.InstructionData
            {
                ImageId = call.Key.imageId,
                ImageOffset = call.Key.offset,
                HandlesSecretData = false,
                AccessesOnlySecretBlocks = false,
                ReadRegisters = new HashSet<Register>(),
                WriteRegisters = new HashSet<Register>(),
                KeepRegisters = new HashSet<Register>(),
                ReadFlags = new HashSet<RflagsBits>(),
                WriteFlags = new HashSet<RflagsBits>(),
                KeepFlags = new HashSet<RflagsBits>()
            });
        }

        // Backfill register/flag access data into analysis result
        foreach(var instruction in _analysisResult.Instructions)
        {
            // Sanity check
            if(!_bbToolResult.BasicBlocks.Any(bb => bb.ImageId == instruction.Key.imageId && bb.Offset <= instruction.Key.offset && instruction.Key.offset < bb.Offset + bb.Size))
            {
                Console.WriteLine($"Warning: Could not find basic block of instruction {instruction.Key.imageId}+{instruction.Value.ImageOffset:x}");
                continue;
            }

            if(!_bbToolResult.Instructions.TryGetValue(instruction.Key, out var bbResult))
            {
                Console.WriteLine($"Warning: Could not find BB tool results for instruction {instruction.Key.imageId}+{instruction.Value.ImageOffset:x}");
                continue;
            }

            foreach(var register in bbResult.Registers)
            {
                if((register.accessInfo & BbToolResult.AccessInfo.Read) != 0)
                    instruction.Value.ReadRegisters.Add(register.register);
                if((register.accessInfo & BbToolResult.AccessInfo.Write) != 0)
                    instruction.Value.WriteRegisters.Add(register.register);
                if((register.accessInfo & BbToolResult.AccessInfo.Keep) != 0)
                    instruction.Value.KeepRegisters.Add(register.register);
            }

            foreach(var flag in bbResult.Flags)
            {
                if((flag.accessInfo & BbToolResult.AccessInfo.Read) != 0)
                    instruction.Value.ReadFlags.Add(flag.flag);
                if((flag.accessInfo & BbToolResult.AccessInfo.Write) != 0)
                    instruction.Value.WriteFlags.Add(flag.flag);
                if((flag.accessInfo & BbToolResult.AccessInfo.Keep) != 0)
                    instruction.Value.KeepFlags.Add(flag.flag);
            }
        }

        var basicBlocksByImage = _bbToolResult.BasicBlocks.GroupBy(b => b.ImageId).ToDictionary(b => b.Key, b => b.ToList());

        // Instrument all associated images
        bool first = true;
        foreach(var image in instrumentImages)
        {
            Console.WriteLine($"Instrumenting image {image.oldImageName} as {image.newImageName}...");
            _mappingFileWriter.WriteLine($"image {image.imageId} {image.oldImageName}");
            _ignoreFileWriter.WriteLine($"image {image.imageId} {image.oldImageName}");

            InstrumentImage(image.imageId, first, basicBlocksByImage[image.imageId], instrumentImages);

            if(first)
                first = false;
        }

        _mappingFileWriter.Dispose();
        _ignoreFileWriter.Dispose();

        Console.WriteLine("Instrumentation completed.");
    }

    private static void InstrumentImage(int imageId, bool isMainImage, List<BbToolResult.BasicBlockData> basicBlocks, List<(int imageId, string oldImageName, string oldImagePath, string newImageName, string newImagePath)> instrumentImages)
    {
        // Load ELF file
        var elf = ElfReader.Load(_bbToolResult.Images[imageId].Path);
        var elfStream = new ElfChunkStream(elf);
        var sectionNameStringTableChunkIndex = elf.GetChunkAtFileOffset(elf.SectionHeaderTable.SectionHeaders[elf.Header.SectionHeaderStringTableIndex].FileOffset);
        if(sectionNameStringTableChunkIndex == null)
            throw new Exception("Could not find section name string table.");
        var sectionNameStringTableChunk = (StringTableChunk)elf.Chunks[sectionNameStringTableChunkIndex.Value.chunkIndex];

        // Collect some offsets
        ulong instrTextSectionAddress = (elf.ProgramHeaderTable!.ProgramHeaders.Max(s => s.VirtualMemoryAddress + s.MemorySize) + 4096) & ~0xFFFul;

        // Ignore .plt sections
        List<(ulong baseOffset, ulong endOffset)> ignoredSections = elf.SectionHeaderTable.SectionHeaders
            .Where(sh =>
            {
                string sectionName = sectionNameStringTableChunk.GetString(sh.NameStringTableOffset);

                return sectionName.StartsWith(".plt");
            })
            .Select(sh => (sh.FileOffset, sh.FileOffset + sh.Size))
            .ToList();

        // Load instrumentation code builder
        var instrumentSectionBuilder = new InstrTextSectionBuilder($"../header/instrument_header_{(MaskUtils.UseSecrecyBuffer ? "base" : "fast")}.o")
        {
            BaseAddress = instrTextSectionAddress
        };

        // If we are looking at the entrypoint image: Find and instrument call to __libc_start_main in _start
        // At the same time, we track the value of register RDI, which eventually contains a pointer to main()
        // The BBs in _start are never instrumented, as there are no secrets yet, so we can safely patch instructions
        ulong mainAddress = 0;
        if(isMainImage)
        {
            ulong entryPointAddress = elf.Header.EntryPoint;
            ulong libcStartMainPointerAddress = 0;
            int startInstructionsCount = 0;

            elfStream.Seek(elf.GetFileOffsetForAddress(entryPointAddress), SeekOrigin.Begin);

            var elfCodeReader = new StreamCodeReader(elfStream);
            var decoder = Decoder.Create(64, elfCodeReader);
            decoder.IP = entryPointAddress;

            const int maxInstructionsUntilFail = 30;
            ulong libcStartMainPointerCallInstructionAddress = 0;
            decoder.Decode(out var currentInstruction);

            while(startInstructionsCount < maxInstructionsUntilFail)
            {
                // Right now we only detect `lea rdi, [rip+...]`
                if(currentInstruction.Code == Code.Lea_r64_m
                   && currentInstruction.Op0Kind == OpKind.Register && currentInstruction.Op0Register == Register.RDI
                   && currentInstruction.IsIPRelativeMemoryOperand)
                {
                    // Evaluate effective address
                    mainAddress = currentInstruction.IPRelativeMemoryAddress;
                }

                decoder.Decode(out var nextInstruction);
                if(nextInstruction.IsInvalid)
                    throw new Exception("Encountered invalid instruction when looking for call to __libc_start_main");

                if(nextInstruction.Code == Code.Hlt)
                {
                    if(currentInstruction.FlowControl == FlowControl.IndirectCall)
                    {
                        // We found our call
                        libcStartMainPointerAddress = currentInstruction.MemoryDisplacement64;
                        libcStartMainPointerCallInstructionAddress = currentInstruction.IP;
                        break;
                    }

                    throw new Exception("Could not find call to __libc_start_main");
                }

                // Not found, next
                currentInstruction = nextInstruction;
                ++startInstructionsCount;
            }

            if(startInstructionsCount == maxInstructionsUntilFail)
                throw new Exception("Could not find call to __libc_start_main");

            // Replace 'call [rel __libc_start_main]' by 'jmp instrument_entrypoint' in _start
            byte[] patchedCall = { 0x90, 0xe9, 0x00, 0x00, 0x00, 0x00 };
            BitConverter.GetBytes((int)(instrTextSectionAddress - (libcStartMainPointerCallInstructionAddress + 6))).CopyTo(patchedCall, 2);
            elf.PatchRawBytesAtAddress((int)libcStartMainPointerCallInstructionAddress, patchedCall);

            instrumentSectionBuilder.LibcStartMainPointerAddress = libcStartMainPointerAddress;
        }

        // Group adjacent basic blocks into chunks (i.e., basic blocks with fallthrough)
        basicBlocks.Sort((bb1, bb2) => (int)bb1.Offset - (int)bb2.Offset);
        List<List<BbToolResult.BasicBlockData>> groupedBasicBlocks = new();
        uint lastBbEndOffset = 0;
        List<BbToolResult.BasicBlockData> currentGroup = null;
        foreach(var bb in basicBlocks)
        {
            // Drop basic blocks from ignored sections
            if(ignoredSections.Any(s => s.baseOffset <= bb.Offset && bb.Offset < s.endOffset))
                continue;

            if(bb.Offset != lastBbEndOffset)
            {
                currentGroup = new List<BbToolResult.BasicBlockData>();
                groupedBasicBlocks.Add(currentGroup);
            }

            currentGroup!.Add(bb);
            lastBbEndOffset = bb.Offset + bb.Size;
        }

        // BB instrumentation, first pass:
        // Analyze blocks and look for suitable jump points to instrumentation code
        List<BasicBlockInstrumentationData> instrumentedBasicBlocks = new();
        int CurrentBasicBlockId() => instrumentedBasicBlocks.Count;
        foreach(var bbs in groupedBasicBlocks.OrderBy(bbs => bbs.First().Offset))
        {
            // Compute group boundaries
            uint firstBbOffset = bbs.First().Offset;
            long groupSize = bbs.Sum(bb => bb.Size);

            // Do we need to instrument this group?
            if(_analysisResult.Instructions.All(i => i.Value.ImageId != imageId || i.Value.ImageOffset < firstBbOffset || firstBbOffset + groupSize <= i.Value.ImageOffset)
               && _analysisResult.StackFrames.All(s => s.Value.ImageId != imageId || s.Value.ImageOffset < firstBbOffset || firstBbOffset + groupSize <= s.Value.ImageOffset || s.Value.Size == 0)
               && _bbToolResult.Syscalls.All(s => s.ImageId != imageId || s.Offset < firstBbOffset || firstBbOffset + groupSize <= s.Offset)
               && _pendingHeapAllocationCalls.All(h => h.Key.imageId != imageId || h.Key.offset < firstBbOffset || firstBbOffset + groupSize <= h.Key.offset))
                continue;
            if(firstBbOffset == elf.Header.EntryPoint) // Never instrument _start
                continue;

            // Read bytes belonging to this BB group
            var bbsBytes = new byte[groupSize];
            elfStream.Seek(firstBbOffset, SeekOrigin.Begin);
            elfStream.Read(bbsBytes, 0, bbsBytes.Length);

            var bbsInstructionDecoder = Decoder.Create(64, bbsBytes, firstBbOffset);

            // Look for jump points
            var bbsInstrumentationData = bbs.Select(bb => new BasicBlockInstrumentationData { BasicBlockData = bb }).ToList();
            for(int i = 0; i < bbsInstrumentationData.Count; ++i)
            {
                var bb = bbsInstrumentationData[i];
                bb.Bytes = bbsBytes.AsMemory((int)(bb.BasicBlockData.Offset - firstBbOffset), (int)bb.BasicBlockData.Size);
                bb.IsLastInGroup = (i == bbsInstrumentationData.Count - 1);

                // Is the current block large enough to hold a 5-byte jump?
                if(bb.BasicBlockData.Size >= 5)
                {
                    bb.Jumps.Insert(0, (0, true, CurrentBasicBlockId(), 0));
                }
                else if(bb.BasicBlockData.Size >= 2)
                {
                    // We could place a 2-byte jump

                    // Check whether there is still space in one of the earlier blocks
                    long shortJmpOffset = bb.BasicBlockData.Offset + 2;
                    long minReachableOffset = shortJmpOffset - 128;
                    bool jmpPosFound = false;
                    for(int j = 0; j < i; ++j)
                    {
                        var otherBb = bbsInstrumentationData[j];

                        // Can this block even be reached from our current block?
                        if(otherBb.BasicBlockData.Offset + otherBb.BasicBlockData.Size - 5 < minReachableOffset)
                            continue;

                        // Does this block have enough space for a 5-byte jump?
                        int usedBytes = otherBb.GetJumpBytesLength();
                        if(otherBb.BasicBlockData.Size - usedBytes < 5)
                            continue;

                        // Find minimal offset for 5-byte jump
                        int secondJmpBbOffset = (int)Math.Max(usedBytes, minReachableOffset - otherBb.BasicBlockData.Offset);
                        otherBb.Jumps.Add((secondJmpBbOffset, true, CurrentBasicBlockId(), 0));
                        bb.Jumps.Insert(0, (0, false, -1, checked((sbyte)(otherBb.BasicBlockData.Offset + secondJmpBbOffset - shortJmpOffset))));

                        jmpPosFound = true;
                        break;
                    }

                    // If we didn't find a suitable position, start looking in the following blocks
                    if(!jmpPosFound)
                    {
                        long maxReachableOffset = shortJmpOffset + 127;
                        for(int j = i + 1; j < bbsInstrumentationData.Count; ++j)
                        {
                            var otherBb = bbsInstrumentationData[j];

                            // Ensure that this block does still have size for its own 5-byte jump
                            int usedBytes = otherBb.GetJumpBytesLength();
                            if(otherBb.BasicBlockData.Size < 5 + usedBytes + 5)
                                continue;

                            // Check whether target offset is still in reach
                            int secondJmpBbOffset = 5 + usedBytes;
                            if(otherBb.BasicBlockData.Offset + secondJmpBbOffset > maxReachableOffset)
                                break;

                            // We can safely insert a 5-byte jump here
                            otherBb.Jumps.Add((secondJmpBbOffset, true, CurrentBasicBlockId(), 0));
                            bb.Jumps.Insert(0, (0, false, -1, checked((sbyte)(otherBb.BasicBlockData.Offset + secondJmpBbOffset - shortJmpOffset))));
                        }
                    }
                }

                // Scan instructions
                while(bbsInstructionDecoder.IP < bb.BasicBlockData.Offset + bb.BasicBlockData.Size)
                {
                    var instruction = bbsInstructionDecoder.Decode();
                    bb.Instructions.Add(new InstructionInstrumentationData
                    {
                        Instruction = instruction,
                        OldAddress = (long)instruction.IP,
                        NewAddress = (long)instruction.IP
                    });
                }

                // This basic block is ready to get instrumented
                instrumentedBasicBlocks.Add(bb);
            }
        }

        // BB instrumentation, second pass:
        // Actual instrumentation. Copy old instructions and modify/replace them by new ones
        // Keep track of old and new offsets
        Dictionary<long, InstructionInstrumentationData> movedInstructionLookup = new();
        List<(ulong, ulong)> int3Addresses = new();
        long currentInstrumentationSectionOffset = (long)instrumentSectionBuilder.GetBasicBlockInstrumentationAreaBaseAddress();
        foreach(var bb in instrumentedBasicBlocks)
        {
            // Generate int3 instruction in original basic block if we couldn't find enough space for a jump
            if(bb.Jumps.Count == 0 && bb.Bytes.Span[0] != 0xc3)
            {
                bb.Int3 = true;
                int3Addresses.Add((bb.BasicBlockData.Offset, (ulong)currentInstrumentationSectionOffset));
            }

            bb.NewAddress = currentInstrumentationSectionOffset;

            // Instruction array iterator
            for(int i = 0; i < bb.Instructions.Count; ++i)
            {
                var currentInstruction = bb.Instructions[i];

                // Precomputation: Find out whether this is a malloc() or realloc() call
                bool isMallocCall = false;
                bool isReallocCall = false;
                if(currentInstruction.Instruction.Mnemonic == Mnemonic.Call)
                {
                    // Iterate through all call stacks and look for this instruction
                    foreach(var call in _analysisResult.HeapMemoryBlocks.SelectMany(hmb => hmb.Value.CallStack))
                    {
                        if(call.SourceImageId == imageId && call.SourceImageOffset == currentInstruction.OldAddress)
                        {
                            if(_bbToolResult.Mallocs.Contains((call.TargetImageId, (uint)call.TargetImageOffset)))
                            {
                                isMallocCall = true;
                                break;
                            }

                            if(_bbToolResult.Reallocs.Contains((call.TargetImageId, (uint)call.TargetImageOffset)))
                            {
                                isReallocCall = true;
                                break;
                            }
                        }
                    }
                }

                // Does this instruction need instrumentation?
                if(_analysisResult.StackFrames.TryGetValue((imageId, (uint)currentInstruction.OldAddress), out var stackFrameData))
                {
                    if(_debug)
                        Console.WriteLine($"  Initializing stack frame at #{currentInstruction.OldAddress:x} of size {stackFrameData.Size:x}");

                    // Generate initializer instructions
                    _analysisResult.Instructions.TryGetValue((imageId, (uint)currentInstruction.OldAddress), out var instructionAnalysisData);
                    var initializerInstructions = _stackFrameInitializer.InitializeStackFrame(currentInstruction.Instruction, instructionAnalysisData, stackFrameData);

                    // Create instruction data objects, and adjust IP for relative operands
                    Dictionary<ulong, ulong> adjustedIpMapping = new(); // For resolving local labels
                    List<InstructionInstrumentationData> instructionInstrumentationDataList = new();
                    foreach(var initializerInstruction in initializerInstructions)
                    {
                        InstructionInstrumentationData initInstructionInstrumentationData = new InstructionInstrumentationData
                        {
                            Instruction = initializerInstruction with { IP = (ulong)currentInstrumentationSectionOffset },
                            NewAddress = currentInstrumentationSectionOffset,
                            OldAddress = currentInstruction.OldAddress,
                            OldIpRelativeOperandAddress = null
                        };
                        adjustedIpMapping.Add(initializerInstruction.IP, (ulong)currentInstrumentationSectionOffset);

                        // Handle RIP-relative instructions
                        if(initInstructionInstrumentationData.Instruction.IsIPRelativeMemoryOperand)
                        {
                            initInstructionInstrumentationData.OldIpRelativeOperandAddress = (long)initInstructionInstrumentationData.Instruction.MemoryDisplacement64;

                            // We will later back-fill this with a value computed from IpRelativeOperandAddress
                            // This is safe, as RIP-relative memory operands always have the same size.
                            initInstructionInstrumentationData.Instruction = initInstructionInstrumentationData.Instruction.WithAdjustedIpDisplacement(0);
                        }
                        else if(initInstructionInstrumentationData.Instruction.IsCallNear
                                || initInstructionInstrumentationData.Instruction.IsJccShort
                                || initInstructionInstrumentationData.Instruction.IsJccNear
                                || initInstructionInstrumentationData.Instruction.IsJmpShort
                                || initInstructionInstrumentationData.Instruction.IsJmpNear)
                        {
                            // Handle local jumps generated during instrumentation
                            initInstructionInstrumentationData.OldIpRelativeOperandAddress = (long)initializerInstruction.MemoryDisplacement64; // Remember actual target, will remap it in the second pass
                            initInstructionInstrumentationData.Instruction = initInstructionInstrumentationData.Instruction.WithAdjustedBranchDisplacement(initInstructionInstrumentationData.Instruction.IP);
                        }

                        bb.Instructions.Insert(i++, initInstructionInstrumentationData);
                        instructionInstrumentationDataList.Add(initInstructionInstrumentationData);
                        _ignoreFileWriter.WriteLine($"{currentInstrumentationSectionOffset:x}");
                        currentInstrumentationSectionOffset += initInstructionInstrumentationData.Instruction.Length;
                    }

                    // Do second pass over new instructions to compute 32-bit displacements for all RIP-relative instructions
                    // We cannot do that in the first loop, as there may be new local labels *after* a jump instruction.
                    foreach(var instructionInstrumentationData in instructionInstrumentationDataList)
                    {
                        if(instructionInstrumentationData.Instruction.IsCallNear
                           || instructionInstrumentationData.Instruction.IsJccShort
                           || instructionInstrumentationData.Instruction.IsJccNear
                           || instructionInstrumentationData.Instruction.IsJmpShort
                           || instructionInstrumentationData.Instruction.IsJmpNear)
                        {
                            instructionInstrumentationData.Instruction = instructionInstrumentationData.Instruction.WithAdjustedBranchDisplacement(adjustedIpMapping[(ulong)instructionInstrumentationData.OldIpRelativeOperandAddress]);
                            instructionInstrumentationData.OldIpRelativeOperandAddress = null;
                        }
                    }

                    // If we inserted any instruction, mark that as the new location
                    if(instructionInstrumentationDataList.Count > 0)
                        movedInstructionLookup.Add(currentInstruction.OldAddress, instructionInstrumentationDataList[0]);

                    // Process this instruction again (we've only inserted additional ones)
                    _analysisResult.StackFrames.Remove((imageId, (uint)currentInstruction.OldAddress));
                    --i;
                }
                else if(_pendingInstructions.Contains((imageId, (uint)currentInstruction.OldAddress))
                        && currentInstruction.Instruction.Mnemonic is not (Mnemonic.Call or Mnemonic.Ret or Mnemonic.Jmp))
                {
                    if(_debug)
                        Console.WriteLine($"  Instrumenting #{currentInstruction.OldAddress:x}: {currentInstruction.Instruction}");

                    _pendingInstructions.Remove((imageId, (uint)currentInstruction.OldAddress));

                    // Generate instrumentation code (with old IP)
                    _analysisResult.Instructions.TryGetValue((imageId, (uint)currentInstruction.OldAddress), out var instructionAnalysisData);
                    var instrumentationInstructions = _instructionTranslator.InstrumentMemoryAccessInstruction(currentInstruction.Instruction, instructionAnalysisData, out bool isWrite);
                    if(_debug)
                        Console.WriteLine($"    -> {currentInstrumentationSectionOffset:x} ({(isWrite ? "write" : "read")})");

                    // Create instruction data objects, and adjust IP for relative operands
                    bb.Instructions.RemoveAt(i);
                    bool first = true;
                    Dictionary<ulong, ulong> adjustedIpMapping = new(); // For resolving local labels
                    List<InstructionInstrumentationData> instructionInstrumentationDataList = new();
                    foreach(var instrumentationInstruction in instrumentationInstructions)
                    {
                        InstructionInstrumentationData instructionInstrumentationData = new InstructionInstrumentationData
                        {
                            Instruction = instrumentationInstruction with { IP = (ulong)currentInstrumentationSectionOffset },
                            NewAddress = currentInstrumentationSectionOffset,
                            OldAddress = currentInstruction.OldAddress,
                            OldIpRelativeOperandAddress = null
                        };
                        adjustedIpMapping.Add(instrumentationInstruction.IP, (ulong)currentInstrumentationSectionOffset);

                        // Handle RIP-relative instructions
                        if(instructionInstrumentationData.Instruction.IsIPRelativeMemoryOperand)
                        {
                            instructionInstrumentationData.OldIpRelativeOperandAddress = (long)instructionInstrumentationData.Instruction.MemoryDisplacement64;

                            // We will later back-fill this with a value computed from IpRelativeOperandAddress
                            // This is safe, as RIP-relative memory operands always have the same size.
                            instructionInstrumentationData.Instruction = instructionInstrumentationData.Instruction.WithAdjustedIpDisplacement(0);
                        }
                        else if(instructionInstrumentationData.Instruction.IsCallNear
                                || instructionInstrumentationData.Instruction.IsJccShort
                                || instructionInstrumentationData.Instruction.IsJccNear
                                || instructionInstrumentationData.Instruction.IsJmpShort
                                || instructionInstrumentationData.Instruction.IsJmpNear)
                        {
                            // Since we don't instrument jumps, this instruction can have been generated only during instrumentation.
                            // Thus, we can safely assume that it does not jump further than a few bytes. Since we may jump to an address
                            // that we haven't already seen (adjustedIpMapping), we just insert a dummy and then do a second pass.
                            instructionInstrumentationData.OldIpRelativeOperandAddress = (long)instrumentationInstruction.MemoryDisplacement64; // Remember actual target, will remap it in the second pass
                            instructionInstrumentationData.Instruction = instructionInstrumentationData.Instruction.WithAdjustedBranchDisplacement(instructionInstrumentationData.Instruction.IP);
                        }

                        if(first)
                        {
                            movedInstructionLookup.TryAdd(instructionInstrumentationData.OldAddress, instructionInstrumentationData);
                            first = false;
                        }
                        else
                        {
                            ++i;
                        }

                        bb.Instructions.Insert(i, instructionInstrumentationData);
                        instructionInstrumentationDataList.Add(instructionInstrumentationData);
                        if(!isWrite) // Sometimes reads use pushf/popf, which confuse the evaluation tool, so just ignore everything that belongs to a read
                            _ignoreFileWriter.WriteLine($"{currentInstrumentationSectionOffset:x}");
                        currentInstrumentationSectionOffset += instructionInstrumentationData.Instruction.Length;
                    }

                    // Do second pass over new instructions to compute 32-bit displacements for all RIP-relative instructions
                    // We cannot do that in the first loop, as there may be new local labels *after* a jump instruction.
                    foreach(var instructionInstrumentationData in instructionInstrumentationDataList)
                    {
                        if(instructionInstrumentationData.Instruction.IsCallNear
                           || instructionInstrumentationData.Instruction.IsJccShort
                           || instructionInstrumentationData.Instruction.IsJccNear
                           || instructionInstrumentationData.Instruction.IsJmpShort
                           || instructionInstrumentationData.Instruction.IsJmpNear)
                        {
                            instructionInstrumentationData.Instruction = instructionInstrumentationData.Instruction.WithAdjustedBranchDisplacement(adjustedIpMapping[(ulong)instructionInstrumentationData.OldIpRelativeOperandAddress]);
                            instructionInstrumentationData.OldIpRelativeOperandAddress = null;
                        }
                    }
                }
                else if(currentInstruction.Instruction.Mnemonic == Mnemonic.Syscall
                        && _bbToolResult.Syscalls.Any(s => s.ImageId == imageId && s.Offset == (uint)currentInstruction.OldAddress!))
                {
                    if(_debug)
                        Console.WriteLine($"  Instrumenting system call at #{currentInstruction.OldAddress:x}");

                    // Replace system call instruction by call to predefined instrumentation

                    ulong systemCallHandlerAddress = instrumentSectionBuilder.GetAddressOfSymbol("handle_system_call");
                    var callInstruction = Instruction.CreateBranch(Code.Call_rel32_64, systemCallHandlerAddress);
                    callInstruction.Length = 1 + 4;
                    callInstruction.IP = (ulong)currentInstrumentationSectionOffset;

                    var instructionInstrumentationData = new InstructionInstrumentationData
                    {
                        Instruction = callInstruction,
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    bb.Instructions[i] = instructionInstrumentationData;

                    currentInstrumentationSectionOffset += callInstruction.Length;
                    movedInstructionLookup.TryAdd(instructionInstrumentationData.OldAddress, instructionInstrumentationData);
                }
                else if(currentInstruction.Instruction.Mnemonic == Mnemonic.Call
                        && _pendingHeapAllocationCalls.TryGetValue((imageId, (uint)currentInstruction.OldAddress), out bool isPartOfSecretAllocation))
                {
                    if(_debug)
                        Console.WriteLine($"  Instrumenting heap allocation call stack entry at #{currentInstruction.OldAddress:x}");

                    // Insert allocation tracker update before and after call

                    // TODO For simplicity, we just rely on the calling convention here. This may break randomly
                    //      It would be much cleaner to not use registers at all, but directly access a variable in thread-local storage.

                    _analysisResult.Instructions.TryGetValue((imageId, (uint)currentInstruction.OldAddress), out var instructionAnalysisData);

                    // We may need to save RAX, if this is an indirect call (`call rax` or `call [rax+0x10]`), or if RAX is used
                    InstructionInstrumentationData beforeSaveRaxInstruction = null;
                    Register raxSaveReg = Register.None;
                    if((instructionAnalysisData.ReadRegisters.Contains(Register.RAX) || instructionAnalysisData.KeepRegisters.Contains(Register.RAX)) && !isMallocCall && !isReallocCall)
                    {
                        // Pick suitable register for saving RAX
                        var availableRegisters = ToyRegisterAllocator.GeneralPurposeRegisters
                            .Where(r => !instructionAnalysisData.KeepRegisters.Contains(r) && !instructionAnalysisData.ReadRegisters.Contains(r))
                            .ToList();
                        if(!availableRegisters.Any())
                            throw new Exception($"Can not identify general purpose register for temporarily saving RAX at {currentInstruction.OldAddress:x}");
                        raxSaveReg = availableRegisters.First();

                        beforeSaveRaxInstruction = new InstructionInstrumentationData
                        {
                            Instruction = Instruction.Create(Code.Mov_rm64_r64, raxSaveReg, Register.RAX)
                                with
                                {
                                    Length = 3,
                                    IP = (ulong)currentInstrumentationSectionOffset
                                },
                            OldAddress = currentInstruction.OldAddress,
                            NewAddress = currentInstrumentationSectionOffset,
                            OldIpRelativeOperandAddress = null
                        };
                        currentInstrumentationSectionOffset += 3;
                    }

                    // mov rax, [alloc_tracker]
                    var beforeGetTrackerInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Mov_RAX_moffs64, Register.RAX, new MemoryOperand(ManagementObjectAddress + ManagementObjectAllocTrackerOffset, 8))
                            with
                            {
                                Length = 10,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    currentInstrumentationSectionOffset += 10;

                    // lea rax, [2*rax+b]
                    //   where b = 0 for non-secret / b = 1 for secret
                    var beforeShiftIncTrackerInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Lea_r64_m, Register.RAX, new MemoryOperand(Register.None, Register.RAX, 2, isPartOfSecretAllocation ? 1 : 0, 4))
                            with
                            {
                                Length = 8,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    currentInstrumentationSectionOffset += 8;

                    var beforeSetTrackerInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Mov_moffs64_RAX, new MemoryOperand(ManagementObjectAddress + ManagementObjectAllocTrackerOffset, 8), Register.RAX)
                            with
                            {
                                Length = 10,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    currentInstrumentationSectionOffset += 10;

                    InstructionInstrumentationData beforeRestoreRaxInstruction = null;
                    InstructionInstrumentationData callInstructionData;
                    InstructionInstrumentationData call2InstructionData = null;

                    // If this is a call to *alloc, replace it by a call to the appropriate handler function.
                    // Else, leave it as is
                    if(isMallocCall || isReallocCall)
                    {
                        string allocName = isMallocCall ? "malloc" : "realloc";

                        if(_debug)
                            Console.WriteLine($"  Instrumenting {allocName}() call at #{currentInstruction.OldAddress:x}");

                        // Replace *alloc() call instruction by call to predefined instrumentation

                        // Store address of *alloc() in rax
                        // Overwriting this register is more or less safe (ABI)
                        var addressStoreInstruction = Instruction.Create(Code.Lea_r64_m, Register.RAX, new MemoryOperand(Register.RIP, (long)currentInstruction.Instruction.NearBranchTarget));
                        addressStoreInstruction.Length = 7;
                        addressStoreInstruction.IP = (ulong)currentInstrumentationSectionOffset;

                        callInstructionData = new InstructionInstrumentationData
                        {
                            Instruction = addressStoreInstruction,
                            OldAddress = currentInstruction.OldAddress,
                            NewAddress = currentInstrumentationSectionOffset,
                            OldIpRelativeOperandAddress = null
                        };
                        currentInstrumentationSectionOffset += addressStoreInstruction.Length;

                        // Insert call to instrumentation
                        ulong allocHandlerAddress = instrumentSectionBuilder.GetAddressOfSymbol($"handle_{allocName}");
                        var callInstruction = Instruction.CreateBranch(Code.Call_rel32_64, allocHandlerAddress);
                        callInstruction.Length = 1 + 4;
                        callInstruction.IP = (ulong)currentInstrumentationSectionOffset;

                        call2InstructionData = new InstructionInstrumentationData
                        {
                            Instruction = callInstruction,
                            OldAddress = currentInstruction.OldAddress,
                            NewAddress = currentInstrumentationSectionOffset,
                            OldIpRelativeOperandAddress = null
                        };
                        currentInstrumentationSectionOffset += callInstruction.Length;
                    }
                    else
                    {
                        if(beforeSaveRaxInstruction != null)
                        {
                            beforeRestoreRaxInstruction = new InstructionInstrumentationData
                            {
                                Instruction = Instruction.Create(Code.Mov_rm64_r64, Register.RAX, raxSaveReg)
                                    with
                                    {
                                        Length = 3,
                                        IP = (ulong)currentInstrumentationSectionOffset
                                    },
                                OldAddress = currentInstruction.OldAddress,
                                NewAddress = currentInstrumentationSectionOffset,
                                OldIpRelativeOperandAddress = null
                            };
                            currentInstrumentationSectionOffset += 3;
                        }

                        var callInstruction = currentInstruction.Instruction.WithAdjustedBranchDisplacement(0);
                        callInstruction.Length = callInstruction.GetActualLength((ulong)currentInstrumentationSectionOffset);
                        callInstruction.IP = (ulong)currentInstrumentationSectionOffset;
                        callInstructionData = new InstructionInstrumentationData
                        {
                            Instruction = callInstruction,
                            OldAddress = currentInstruction.OldAddress,
                            NewAddress = currentInstrumentationSectionOffset,
                            OldIpRelativeOperandAddress = (long)currentInstruction.Instruction.NearBranchTarget
                        };
                        currentInstrumentationSectionOffset += callInstruction.Length;
                    }

                    var afterGetTrackerAddressInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Mov_r64_imm64, Register.RDI, ManagementObjectAddress + ManagementObjectAllocTrackerOffset)
                            with
                            {
                                Length = 10,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null,
                    };
                    currentInstrumentationSectionOffset += 10;

                    var afterGetTrackerInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Mov_r64_rm64, Register.RSI, new MemoryOperand(Register.RDI))
                            with
                            {
                                Length = 3,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    currentInstrumentationSectionOffset += 3;

                    var afterShiftTrackerInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Shr_rm64_1, Register.RSI, 1)
                            with
                            {
                                Length = 3,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    currentInstrumentationSectionOffset += 3;

                    var afterSetTrackerInstruction = new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Mov_rm64_r64, new MemoryOperand(Register.RDI), Register.RSI)
                            with
                            {
                                Length = 3,
                                IP = (ulong)currentInstrumentationSectionOffset
                            },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    };
                    currentInstrumentationSectionOffset += 3;

                    // Store new instructions
                    bb.Instructions.RemoveAt(i);
                    --i;
                    if(beforeSaveRaxInstruction != null)
                        bb.Instructions.Insert(++i, beforeSaveRaxInstruction);
                    bb.Instructions.Insert(++i, beforeGetTrackerInstruction);
                    bb.Instructions.Insert(++i, beforeShiftIncTrackerInstruction);
                    bb.Instructions.Insert(++i, beforeSetTrackerInstruction);
                    if(beforeRestoreRaxInstruction != null)
                        bb.Instructions.Insert(++i, beforeRestoreRaxInstruction);
                    bb.Instructions.Insert(++i, callInstructionData);
                    if(call2InstructionData != null)
                        bb.Instructions.Insert(++i, call2InstructionData);
                    bb.Instructions.Insert(++i, afterGetTrackerAddressInstruction);
                    bb.Instructions.Insert(++i, afterGetTrackerInstruction);
                    bb.Instructions.Insert(++i, afterShiftTrackerInstruction);
                    bb.Instructions.Insert(++i, afterSetTrackerInstruction);

                    _ignoreFileWriter.WriteLine($"{beforeSetTrackerInstruction.NewAddress:x}");
                    _ignoreFileWriter.WriteLine($"{afterSetTrackerInstruction.NewAddress:x}");

                    movedInstructionLookup.TryAdd(currentInstruction.OldAddress, beforeSaveRaxInstruction ?? beforeGetTrackerInstruction);

                    _pendingHeapAllocationCalls.Remove((imageId, (uint)currentInstruction.OldAddress));
                }
                else if(currentInstruction.Instruction.Mnemonic == Mnemonic.Nop)
                {
                    // Reproduce former alignment of subsequent instruction
                    long nextInstructionAddress = currentInstruction.OldAddress + currentInstruction.Instruction.Length;
                    int alignment = 1 << (int)System.Runtime.Intrinsics.X86.Bmi1.TrailingZeroCount((uint)nextInstructionAddress);
                    if(alignment > 16)
                        alignment = 16;

                    bb.Instructions.RemoveAt(i);
                    int count = 0;
                    while(currentInstrumentationSectionOffset % alignment != 0)
                    {
                        var newNopInstruction = new InstructionInstrumentationData
                        {
                            Instruction = Instruction.Create(Code.Nopd) with { Length = 1, IP = (ulong)currentInstrumentationSectionOffset },
                            OldAddress = currentInstruction.OldAddress,
                            NewAddress = currentInstrumentationSectionOffset,
                            OldIpRelativeOperandAddress = null
                        };
                        bb.Instructions.Insert(i + count, newNopInstruction);

                        if(count == 0)
                            movedInstructionLookup.TryAdd(newNopInstruction.OldAddress, newNopInstruction);

                        ++count;
                        ++currentInstrumentationSectionOffset;
                    }

                    i += count - 1; // i will be incremented by the for loop itself again
                }
                else if(currentInstruction.Instruction.Mnemonic == Mnemonic.Jrcxz)
                {
                    if(_debug)
                        Console.WriteLine($"  Instrumenting jrcxz at #{currentInstruction.OldAddress:x}");

                    //   jrcxz label
                    // -->
                    //   jrcxz trampoline
                    //   jmp continue
                    // trampoline:
                    //   jmp label
                    // continue:

                    bb.Instructions.RemoveAt(i);

                    bb.Instructions.Insert(i, new InstructionInstrumentationData
                    {
                        Instruction = Instruction.CreateBranch(Code.Jrcxz_rel8_64, (ulong)currentInstrumentationSectionOffset) with { Length = 2, IP = (ulong)currentInstrumentationSectionOffset },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = currentInstrumentationSectionOffset + 7
                    });
                    currentInstrumentationSectionOffset += 2;
                    movedInstructionLookup.TryAdd(bb.Instructions[i].OldAddress, bb.Instructions[i]);

                    bb.Instructions.Insert(i + 1, new InstructionInstrumentationData
                    {
                        Instruction = Instruction.CreateBranch(Code.Jmp_rel32_64, (ulong)currentInstrumentationSectionOffset)with { Length = 5, IP = (ulong)currentInstrumentationSectionOffset },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = currentInstrumentationSectionOffset + 10
                    });
                    currentInstrumentationSectionOffset += 5;

                    bb.Instructions.Insert(i + 2, new InstructionInstrumentationData
                    {
                        Instruction = Instruction.CreateBranch(Code.Jmp_rel32_64, (ulong)currentInstrumentationSectionOffset)with { Length = 5, IP = (ulong)currentInstrumentationSectionOffset },
                        OldAddress = currentInstruction.OldAddress,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = (long)currentInstruction.Instruction.NearBranchTarget
                    });
                    currentInstrumentationSectionOffset += 5;

                    i += 2;
                }
                else
                {
                    // We don't instrument this instruction, just move it to the instrumentation section
                    currentInstruction.NewAddress = currentInstrumentationSectionOffset;
                    currentInstruction.Instruction = currentInstruction.Instruction with { IP = (ulong)currentInstruction.NewAddress };

                    // Ensure that all RIP-relative instructions use a 32-bit displacement, for simplicity
                    // We will later back-fill them with values computed from IpRelativeOperandAddress
                    if(currentInstruction.Instruction.IsIPRelativeMemoryOperand)
                    {
                        currentInstruction.OldIpRelativeOperandAddress = (long)currentInstruction.Instruction.MemoryDisplacement64;
                        currentInstruction.Instruction = currentInstruction.Instruction.WithAdjustedIpDisplacement(0);
                    }
                    else if(currentInstruction.Instruction.IsCallNear
                            || currentInstruction.Instruction.IsJccShort
                            || currentInstruction.Instruction.IsJccNear
                            || currentInstruction.Instruction.IsJmpShort
                            || currentInstruction.Instruction.IsJmpNear)
                    {
                        currentInstruction.OldIpRelativeOperandAddress = (long)currentInstruction.Instruction.NearBranchTarget;
                        currentInstruction.Instruction = currentInstruction.Instruction.WithAdjustedBranchDisplacement(0);
                    }

                    movedInstructionLookup.TryAdd(currentInstruction.OldAddress, currentInstruction);

                    var ins = currentInstruction.Instruction;
                    int length = ins.GetActualLength((ulong)currentInstrumentationSectionOffset);
                    ins.Length = length;
                    ins.IP = (ulong)currentInstruction.NewAddress; // For some reason, changing Length also modifies IP
                    currentInstruction.Instruction = ins;

                    currentInstrumentationSectionOffset += currentInstruction.Instruction.Length;
                }
            }

            // Create mappings for memory access instructions
            foreach(var currentInstruction in bb.Instructions)
            {
                // Record all new memory accesses in MAP file for verification
                if(currentInstruction.Instruction.IsMemoryAccess())
                    _mappingFileWriter.WriteLine($"{currentInstruction.OldAddress:x} {currentInstruction.NewAddress:x}");
            }

            // Insert jump back to original location, if this is the last block of a chunk
            if(bb.IsLastInGroup && (bb.Instructions.LastOrDefault()?.Instruction.Mnemonic is not Mnemonic.Ret and not Mnemonic.Jmp))
            {
                var jumpInstruction = Instruction.CreateBranch(Code.Jmp_rel32_64, bb.BasicBlockData.Offset + bb.BasicBlockData.Size);
                jumpInstruction.Length = 1 + 4;
                jumpInstruction.IP = (ulong)currentInstrumentationSectionOffset;

                bb.Instructions.Add(new InstructionInstrumentationData
                {
                    Instruction = jumpInstruction,
                    OldAddress = 0,
                    NewAddress = currentInstrumentationSectionOffset,
                    OldIpRelativeOperandAddress = null
                });

                currentInstrumentationSectionOffset += jumpInstruction.Length;
            }

            // Align the next basic block chunk
            if(bb.IsLastInGroup)
            {
                while(currentInstrumentationSectionOffset % 16 != 0)
                {
                    bb.Instructions.Add(new InstructionInstrumentationData
                    {
                        Instruction = Instruction.Create(Code.Nopd) with { Length = 1, IP = (ulong)currentInstrumentationSectionOffset }, // In this order!
                        OldAddress = 0,
                        NewAddress = currentInstrumentationSectionOffset,
                        OldIpRelativeOperandAddress = null
                    });

                    ++currentInstrumentationSectionOffset;
                }
            }
        }

        // BB instrumentation, third pass:
        // Fix displacements of RIP-relative operands
        foreach(var bb in instrumentedBasicBlocks)
        {
            foreach(var currentInstruction in bb.Instructions)
            {
                // Find new location of target
                if(currentInstruction.OldIpRelativeOperandAddress == null)
                    continue;
                long oldOperandAddress = currentInstruction.OldIpRelativeOperandAddress.Value;
                long newOperandAddress = oldOperandAddress;

                if(currentInstruction.Instruction.IsIPRelativeMemoryOperand)
                {
                    currentInstruction.Instruction = currentInstruction.Instruction.WithAdjustedIpDisplacement((ulong)newOperandAddress);
                }
                else if(currentInstruction.Instruction.IsCallNear
                        || currentInstruction.Instruction.IsJccShort
                        || currentInstruction.Instruction.IsJccNear
                        || currentInstruction.Instruction.IsJmpShort
                        || currentInstruction.Instruction.IsJmpNear
                        || currentInstruction.Instruction.Code == Code.Jrcxz_rel8_64)
                {
                    // Redirect branches directly to the instrumented code
                    if(movedInstructionLookup.TryGetValue(oldOperandAddress, out var movedInstruction))
                        newOperandAddress = movedInstruction.NewAddress;

                    currentInstruction.Instruction = currentInstruction.Instruction.WithAdjustedBranchDisplacement((ulong)newOperandAddress);
                }
            }
        }

        if(_debug)
        {
            foreach(var bb in instrumentedBasicBlocks)
            {
                Console.WriteLine($"  {_bbToolResult.Images[imageId].Name}+{bb.BasicBlockData.Offset:x4}, length: {bb.BasicBlockData.Size}{(bb.BasicBlockData.HasFallThrough ? ", fallthrough" : "")}");

                Console.WriteLine("    Orig:");
                if(bb.Jumps.Count == 0)
                {
                    Console.WriteLine($"      {bb.BasicBlockData.Offset:x4}: int3");
                }
                else
                {
                    foreach(var jmp in bb.Jumps)
                        Console.WriteLine($"      {(bb.BasicBlockData.Offset + jmp.bbOffset):x4}: " + (jmp.isNearJump ? "jmp5" : $"jmp2 {jmp.shortOffset:x}"));

                    Console.WriteLine($"    Inst:");
                    foreach(var instruction in bb.Instructions)
                        Console.WriteLine($"      {instruction.NewAddress:x4} / {instruction.Instruction.IP:x4}: {instruction.Instruction}");
                }
            }
        }

        // Shared libraries: Insert constructor call for initialization of instrumentation section
        if(!isMainImage)
        {
            // To avoid extending the constructor section (which may shift subsequent sections, causing a lot of problems), we simply
            // replace the first constructor by instrumentation, which will in turn call the given constructor.

            // Determine instrumentation initializer address
            byte[] initializerAddressBytes = new byte[8];
            ulong initializerAddress = instrumentSectionBuilder.GetAddressOfSymbol("library_init");
            BinaryPrimitives.WriteUInt64LittleEndian(initializerAddressBytes, initializerAddress);

            // DT_INIT takes precedent before DT_INIT_ARRAY
            var initEntry = elf.DynamicTable.Entries.FirstOrDefault(e => e.Type == DynamicEntryType.DT_INIT);
            if(initEntry != null)
            {
                // Read old constructor address
                instrumentSectionBuilder.FirstConstructorAddress = initEntry.Value;

                // Replace by pointer to new initalization code
                initEntry.Value = initializerAddress;
            }
            else
            {
                // Find .init_array section
                var initArraySectionIndex = elf.SectionHeaderTable.SectionHeaders.FindIndex(h => h.Type == SectionType.InitArray);
                if(initArraySectionIndex < 0)
                    throw new Exception("Could not find .init_array section.");
                var initArraySectionHeader = elf.SectionHeaderTable.SectionHeaders[initArraySectionIndex];

                // Read pointer to first constructor
                byte[] oldConstructorAddressBytes = new byte[8];
                elf.GetRawBytesAtOffset((int)initArraySectionHeader.FileOffset, oldConstructorAddressBytes);
                instrumentSectionBuilder.FirstConstructorAddress = BinaryPrimitives.ReadUInt64LittleEndian(oldConstructorAddressBytes);

                // Replace by pointer to new initalization code
                elf.PatchRawBytesAtOffset((int)initArraySectionHeader.FileOffset, initializerAddressBytes);

                // Patch entry for the given pointer in relocation table, if it is in there
                elf.PatchValueInRelocationTable(initArraySectionHeader.VirtualAddress, (long)instrumentSectionBuilder.FirstConstructorAddress, (long)initializerAddress);
            }
        }

        // Produce list of segments which need a backing mask buffer
        instrumentSectionBuilder.SegmentAddresses = elf.ProgramHeaderTable.ProgramHeaders
            .Where(ph => ph.Type == SegmentType.Load)
            .Select(ph => (ph.VirtualMemoryAddress, (int)ph.MemorySize, (ph.Flags & SegmentFlags.Writable) == 0))
            .ToList();

        // Produce list of data blocks which contain private data and need a non-zero mask
        instrumentSectionBuilder.PrivateDataBlockAddresses = new List<(ulong baseAddress, int length)>();
        foreach(var imageMemoryBlock in _analysisResult.ImageMemoryBlocks.Where(m => m.Value.ImageId == imageId))
        {
            // HACK In case the image addresses are not based on 0, but e.g. on 0x400000, we just assume that the first LOAD segment points to its base address
            ulong baseAddress = elf.ProgramHeaderTable.ProgramHeaders.First().VirtualMemoryAddress + (ulong)imageMemoryBlock.Value.Offset;
            
            instrumentSectionBuilder.PrivateDataBlockAddresses.Add((baseAddress, imageMemoryBlock.Value.Size));
        }

        // Try to locate existing symbol table so we can generate meaningful symbols for the instrumented BBs
        int symbolTableSectionIndex = elf.SectionHeaderTable.SectionHeaders.FindIndex(h => h.Type == SectionType.SymbolTable);

        // Assemble instructions and generate BB instrumentation section
        var bbInstrumentationCodeAssembler = new Assembler(64);
        List<(ulong address, string name)> instrumentationSymbols = new();
        var symbolTableParser = new SymbolTableParser(elf, symbolTableSectionIndex);
        foreach(var bb in instrumentedBasicBlocks)
        {
            // Skip empty basic blocks (may occur if there is a single aligned nop)
            if(bb.Instructions.Count == 0)
            {
                Console.WriteLine($"  Skipping empty instrumented basic block #{bb.BasicBlockData.Offset:x}");
                continue;
            }

            long firstInstructionAddress = bb.Instructions.First().NewAddress;
            long firstInstructionOriginalAddress = bb.BasicBlockData.Offset;

            // If there is a symbol for the original address, include it in the new symbol to ease debugging
            var oldSymbol = symbolTableParser.QuerySymbol((ulong)firstInstructionOriginalAddress);
            if(oldSymbol != null)
                instrumentationSymbols.Add(((ulong)firstInstructionAddress, $"{oldSymbol}.instr.bb_{firstInstructionOriginalAddress:x}"));
            else
                instrumentationSymbols.Add(((ulong)firstInstructionAddress, $"instr.bb_{firstInstructionOriginalAddress:x}"));

            foreach(var instruction in bb.Instructions)
            {
                bbInstrumentationCodeAssembler.AddInstruction(instruction.Instruction);
            }
        }

        using var bbInstrumentationCodeStream = new MemoryStream();
        bbInstrumentationCodeAssembler.Assemble(
            new StreamCodeWriter(bbInstrumentationCodeStream),
            instrumentSectionBuilder.GetBasicBlockInstrumentationAreaBaseAddress(),
            BlockEncoderOptions.DontFixBranches);

        // Store final instrumentation code
        instrumentSectionBuilder.BasicBlockInstrumentationArea = bbInstrumentationCodeStream.ToArray();
        instrumentSectionBuilder.Int3Addresses = int3Addresses;

        // Create instrument sections
        var instrumentSection = instrumentSectionBuilder.Build(out var genericInstrumentationSymbols);
        int instrumentSectionIndex = elf.AllocateProgBitsSection(".instr.text", instrTextSectionAddress, instrumentSection.Length, 4096, false, true, instrumentSection);

        // For verification: Ignore all memory writes within the instrumentation header
        for(ulong o = instrumentSectionBuilder.BaseAddress; o < instrumentSectionBuilder.HeaderEndAddress; ++o)
        {
            _ignoreFileWriter.WriteLine($"{o:x}");
        }

        // Patch .text section with jumps/int3 to instrumentation code
        using var textSectionPatchesStream = new MemoryStream();
        using var textSectionPatchesWriter = new BinaryWriter(textSectionPatchesStream);
        foreach(var bb in instrumentedBasicBlocks)
        {
            textSectionPatchesStream.Position = 0;

            long bbBaseOffset = bb.BasicBlockData.Offset;

            if(bb.Int3)
            {
                // Insert int3
                textSectionPatchesWriter.Write((byte)0xcc);
            }
            else
            {
                // Insert jumps
                foreach(var jump in bb.Jumps)
                {
                    if(jump.isNearJump)
                    {
                        // Near JMP to instrumentation code

                        long targetBbOffset = instrumentedBasicBlocks[jump.nearJumpBbId].NewAddress.Value;
                        int displacement = checked((int)(targetBbOffset - (bbBaseOffset + textSectionPatchesStream.Position + 5)));

                        textSectionPatchesWriter.Write((byte)0xe9);
                        textSectionPatchesWriter.Write(displacement);
                    }
                    else
                    {
                        // Short JMP to a neighboring BB

                        textSectionPatchesWriter.Write((byte)0xeb);
                        textSectionPatchesWriter.Write(jump.shortOffset);
                    }
                }
            }

            // Patch original basic block
            elf.PatchRawBytesAtOffset((int)bbBaseOffset, textSectionPatchesStream.ToArray().AsSpan(0, (int)textSectionPatchesStream.Position));
        }

        // Insert symbols for instrumentation code
        {
            instrumentationSymbols.AddRange(genericInstrumentationSymbols);
            instrumentationSymbols.Sort((s1, s2) => (int)(s1.address - s2.address));

            // Allocate space in string and symbol table
            if(symbolTableSectionIndex < 0)
            {
                if(_debug)
                    Console.WriteLine("  Could not find symbol table section, allocating new one");

                // Create new symbol and string tables
                elf.CreateSymbolTable(".symtab", ".strtab", instrumentSectionIndex, instrumentationSymbols);
            }
            else
            {
                if(_debug)
                    Console.WriteLine("  Extending existing symbol table");

                var symbolTableHeader = elf.SectionHeaderTable.SectionHeaders[symbolTableSectionIndex];
                int stringTableSectionIndex = (int)symbolTableHeader.Link;
                var stringTableHeader = elf.SectionHeaderTable.SectionHeaders[stringTableSectionIndex];

                // Insert symbol strings
                elf.AllocateFileMemory((int)stringTableHeader.FileOffset + (int)stringTableHeader.Size, instrumentationSymbols.Sum(s => s.name.Length + 1));
                var stringTableOffsets = elf.ExtendStringTable(stringTableSectionIndex, instrumentationSymbols.Select(s => s.name).ToArray(), null);

                // Insert symbols
                List<(ulong offset, uint stringTableIndex)> newSymbols = new();
                for(int i = 0; i < instrumentationSymbols.Count; ++i)
                    newSymbols.Add((instrumentationSymbols[i].address, (uint)stringTableOffsets[i]));
                elf.AllocateFileMemory((int)symbolTableHeader.FileOffset + (int)symbolTableHeader.Size, instrumentationSymbols.Count * (int)symbolTableHeader.EntrySize);
                elf.ExtendSymbolTable(symbolTableSectionIndex, instrumentSectionIndex, newSymbols, null);
            }
        }

        // Find .dynstr table
        ulong dynamicStringTableAddress = elf.DynamicTable.Entries.First(e => e.Type == DynamicEntryType.DT_STRTAB).Value;
        int dynamicStringTableSectionIndex = elf.SectionHeaderTable.SectionHeaders.FindIndex(h => h.VirtualAddress == dynamicStringTableAddress);
        var dynamicStringTableHeader = elf.SectionHeaderTable.SectionHeaders[dynamicStringTableSectionIndex];
        var dynamicStringTableChunkIndex = elf.GetChunkAtFileOffset(dynamicStringTableHeader.FileOffset);
        if(dynamicStringTableChunkIndex == null)
            throw new Exception("Could not find dynamic string table.");
        var dynamicStringTableChunk = (StringTableChunk)elf.Chunks[dynamicStringTableChunkIndex.Value.chunkIndex];

        // Insert name strings of image and dependencies
        var newImageNames = instrumentImages.Select(i => "./" + i.newImageName).ToArray();
        elf.AllocateFileMemory((int)dynamicStringTableHeader.FileOffset + (int)dynamicStringTableHeader.Size, newImageNames.Sum(i => i.Length + 1));
        var newImageNamesStringTableOffsets = elf.ExtendStringTable(dynamicStringTableSectionIndex, newImageNames, null);

        // Update DT_NEEDED entries for renamed dependencies
        foreach(var neededEntry in elf.DynamicTable.Entries.Where(e => e.Type == DynamicEntryType.DT_NEEDED))
        {
            string oldEntry = dynamicStringTableChunk.GetString((uint)neededEntry.Value);

            int imageNumber;
            (int imageId, string oldImageName, string oldImagePath, string newImageName, string newImagePath)? imageInfo = null;
            for(imageNumber = 0; imageNumber < instrumentImages.Count; imageNumber++)
            {
                var image = instrumentImages[imageNumber];
                if(image.oldImageName == oldEntry)
                {
                    imageInfo = image;
                    break;
                }
            }

            if(imageInfo == null)
                continue;

            // Record new name string
            neededEntry.Value = (ulong)newImageNamesStringTableOffsets[imageNumber];
        }

        // We keep the SONAME entry at its old value, as at least libc.so.6 seems to be hardcoded in LD

        // Update image names in VERNEED
        if(elf.SectionHeaderTable.SectionHeaders.Where(h => h.Type == SectionType.GnuVersionNeeds).TryFirstOrDefault(out var verneedSectionHeader))
        {
            Debug.Assert(verneedSectionHeader.Link == dynamicStringTableSectionIndex);

            var verneedChunkIndex = elf.GetChunkAtFileOffset(verneedSectionHeader.FileOffset);
            if(verneedChunkIndex == null)
                throw new Exception("Could not find VERNEED chunk.");
            var verneedChunk = (VerneedChunk)elf.Chunks[verneedChunkIndex.Value.chunkIndex];
            int verneedCount = (int)elf.DynamicTable.Entries.First(e => e.Type == DynamicEntryType.DT_VERNEEDNUM).Value;

            int offset = 0;
            var verneedChunkSpan = verneedChunk.Data.AsSpan();
            for(int i = 0; i < verneedCount; ++i)
            {
                // Parse entry
                //uint auxCount = BitConverter.ToUInt16(verneedChunkSpan[(offset + 2)..]);
                uint file = BitConverter.ToUInt32(verneedChunkSpan[(offset + 4)..]);
                //uint aux = BitConverter.ToUInt32(verneedChunkSpan[(offset + 8)..]);
                uint next = BitConverter.ToUInt32(verneedChunkSpan[(offset + 12)..]);

                // Check whether "file" points to an old image name
                string name = dynamicStringTableChunk.GetString(file);
                for(int j = 0; j < instrumentImages.Count; ++j)
                {
                    var imageInfo = instrumentImages[j];
                    if(imageInfo.oldImageName == name)
                    {
                        uint newFile = (uint)newImageNamesStringTableOffsets[j];
                        BinaryPrimitives.WriteUInt32LittleEndian(verneedChunkSpan[(offset + 4)..], newFile);

                        break;
                    }
                }

                offset += (int)next;
            }
        }

        // Update image names in VERDEF
        if(elf.SectionHeaderTable.SectionHeaders.Where(h => h.Type == SectionType.GnuVersionDefinition).TryFirstOrDefault(out var verdefSectionHeader))
        {
            Debug.Assert(verdefSectionHeader.Link == dynamicStringTableSectionIndex);

            var verdefChunkIndex = elf.GetChunkAtFileOffset(verdefSectionHeader.FileOffset);
            if(verdefChunkIndex == null)
                throw new Exception("Could not find VERDEF chunk.");
            var verdefChunk = (VerdefChunk)elf.Chunks[verdefChunkIndex.Value.chunkIndex];
            int verdefCount = (int)elf.DynamicTable.Entries.First(e => e.Type == DynamicEntryType.DT_VERDEFNUM).Value;

            int offset = 0;
            var verdefChunkSpan = verdefChunk.Data.AsSpan();
            for(int i = 0; i < verdefCount; ++i)
            {
                // Parse entry
                uint auxCount = BitConverter.ToUInt16(verdefChunkSpan[(offset + 6)..]);
                uint aux = BitConverter.ToUInt32(verdefChunkSpan[(offset + 12)..]);
                uint next = BitConverter.ToUInt32(verdefChunkSpan[(offset + 16)..]);

                int auxOffset = offset + (int)aux;
                for(int a = 0; a < auxCount; ++a)
                {
                    uint nameIndex = BitConverter.ToUInt32(verdefChunkSpan[auxOffset..]);
                    uint auxNext = BitConverter.ToUInt32(verdefChunkSpan[(auxOffset + 4)..]);

                    // Check whether "nameIndex" points to an old image name
                    string name = dynamicStringTableChunk.GetString(nameIndex);
                    for(int j = 0; j < instrumentImages.Count; ++j)
                    {
                        var imageInfo = instrumentImages[j];
                        if(imageInfo.oldImageName == name)
                        {
                            uint newNameIndex = (uint)newImageNamesStringTableOffsets[j];
                            BinaryPrimitives.WriteUInt32LittleEndian(verdefChunkSpan[auxOffset..], newNameIndex);
                            BinaryPrimitives.WriteUInt32LittleEndian(verdefChunkSpan[(offset + 8)..], ElfHash(imageInfo.newImageName));

                            break;
                        }
                    }

                    auxOffset += (int)auxNext;
                }

                offset += (int)next;
            }
        }
        
        // Patch offset of .instr.text section in the program header table, in case the section was moved (LOAD entries aren't patched automatically)
        // Same for the address in the section header.
        var instrTextSectionProgramHeader = elf.ProgramHeaderTable.ProgramHeaders.First(h => h.VirtualMemoryAddress == instrTextSectionAddress);
        instrTextSectionProgramHeader.FileOffset = elf.SectionHeaderTable.SectionHeaders[instrumentSectionIndex].FileOffset;
        elf.SectionHeaderTable.SectionHeaders[instrumentSectionIndex].VirtualAddress = instrTextSectionProgramHeader.VirtualMemoryAddress;

        // Store instrumented program
        ElfWriter.Store(elf, instrumentImages.First(i => i.imageId == imageId).newImagePath);
    }

    private static uint ElfHash(string value)
    {
        uint h = 0;
        uint g = 0;
        foreach(char c in value)
        {
            h = (h << 4) + c;
            g = h & 0xf0000000;
            if(g != 0)
            {
                h ^= (g >> 24);
            }

            h &= ~g;
        }

        return h;
    }
}

/// <summary>
/// Contains information on how a given basic block is instrumented.
/// </summary>
class BasicBlockInstrumentationData
{
    public BbToolResult.BasicBlockData BasicBlockData { get; init; }

    public Memory<byte> Bytes { get; set; }

    // TODO: comment
    public long? NewAddress { get; set; }

    /// <summary>
    /// Tells whether this basic block is the last block of its group.
    /// This is used to place a jump instruction back to the original location.
    /// </summary>
    public bool IsLastInGroup { get; set; }

    /// <summary>
    /// Records short 8-bit and near 32-bit jumps to instrumentation code, as encoded in the basic block at the original offset.
    /// </summary>
    public List<(int bbOffset, bool isNearJump, int nearJumpBbId, sbyte shortOffset)> Jumps { get; } = new();

    /// <summary>
    /// States whether an int3 instruction is generated at the beginning of the original basic block.
    /// </summary>
    public bool Int3 { get; set; }

    /// <summary>
    /// Instructions of the instrumented basic block.
    /// </summary>
    public List<InstructionInstrumentationData> Instructions { get; } = new();

    public int GetJumpBytesLength() => Jumps.Sum(j => j.isNearJump ? 5 : 2);
}

class InstructionInstrumentationData
{
    public Instruction Instruction { get; set; }

    /// <summary>
    /// Offset of the associated instruction in the original, non-instrumented section.
    /// Used for generating a mapping between old and new instructions.
    /// </summary>
    public long OldAddress { get; init; }

    /// <summary>
    /// Offset of this instruction in the instrumented section.
    /// </summary>
    public long NewAddress { get; set; }

    /// <summary>
    /// Address of the IP-relative operand, or null if there is none.
    /// </summary>
    public long? OldIpRelativeOperandAddress { get; set; }
}