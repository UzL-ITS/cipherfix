using System.Globalization;
using System.Text.RegularExpressions;

namespace MemtraceComparer;

public static class Program
{
    private static readonly Dictionary<(int imageId, uint offset), HashSet<uint>> _oldToNewInstructionMapping = new();
    private static readonly HashSet<(int imageId, uint offset)> _ignoredInstructions = new();
    private static readonly List<(int id, string name)> _images = new();

    private static readonly Dictionary<ulong, Dictionary<(ulong high, ulong low), int>> _blockAddressToBlockValueCountMapping = new();
    private static readonly HashSet<ulong> _interestingBlockAddresses = new();

    public static void Main(string[] args)
    {
        if(args.Length < 4)
        {
            Console.WriteLine("Usage: <taint memtrace> <instr memtrace> <mapping> <ignore>");
            return;
        }

        string memtracePath = args[0];
        string memtraceInstrPath = args[1];
        string mappingPath = args[2];
        string ignorePath = args[3];

        // Read mapping
        var imageRegex = new Regex("^image ([0-9]+) (.*)$", RegexOptions.Compiled);
        Match match;
        int currentImageId = 0;
        foreach(var line in File.ReadLines(mappingPath))
        {
            if((match = imageRegex.Match(line)).Success)
            {
                int id = int.Parse(match.Groups[1].Value);
                string name = match.Groups[2].Value;

                currentImageId = id;
                _images.Add((id, name));
            }
            else
            {
                var split = line.Split(" ");
                uint oldOffset = uint.Parse(split[0], NumberStyles.HexNumber);
                uint newOffset = uint.Parse(split[1], NumberStyles.HexNumber);

                int imageId = currentImageId;

                if(!_oldToNewInstructionMapping.TryGetValue((imageId, oldOffset), out var newInstructionList))
                {
                    newInstructionList = new HashSet<uint>();
                    _oldToNewInstructionMapping.Add((imageId, oldOffset), newInstructionList);
                }

                newInstructionList.Add(newOffset);
            }
        }

        // Read ignored instructions
        foreach(var line in File.ReadLines(ignorePath))
        {
            if((match = imageRegex.Match(line)).Success)
            {
                int id = int.Parse(match.Groups[1].Value);
                //string name = match.Groups[2].Value;

                currentImageId = id;
            }
            else
            {
                uint newOffset = uint.Parse(line, NumberStyles.HexNumber);

                _ignoredInstructions.Add((currentImageId, newOffset));
            }
        }

        // Align traces
        using var memTraceReader = new BinaryReader(File.OpenRead(memtracePath));
        using var memTraceInstrReader = new StreamReader(memtraceInstrPath);

        string? currentInstrLine = memTraceInstrReader.ReadLine();
        int oldLineNumber = 1;
        int instrLineNumber = 1;
        int instrSequenceNumber = 1;
        bool filesMatch = true;
        try
        {
            while(memTraceReader.BaseStream.Position < memTraceReader.BaseStream.Length)
            {
                // Parse original memtrace
                uint oldOffset = checked((uint)memTraceReader.ReadUInt64());
                int oldImageId = memTraceReader.ReadInt32();
                int oldWidth = memTraceReader.ReadUInt16();
                bool oldSecret = memTraceReader.ReadUInt16() != 0;

                // There should be another instr memtrace line
                if(currentInstrLine == null)
                {
                    Console.WriteLine($"Unexpected instr memtrace end at #{oldLineNumber}/{instrLineNumber}/{instrSequenceNumber} image {oldImageId} offset {oldOffset:x}");
                    filesMatch = false;
                    break;
                }

                // Process lines from instrumented memtrace
                bool foundEquivalent = false;
                int instrImageId = 0;
                uint instrInstructionOffset = 0;
                bool inSequence = false;
                while(currentInstrLine != null)
                {
                    string[] instrSplit = currentInstrLine.Split(" ");
                    if(instrSplit.Length == 0)
                        continue;
                    if(instrSplit[0] == "Sb")
                    {
                        inSequence = true;
                    }
                    else if(instrSplit[0] == "Se")
                    {
                        if(!inSequence)
                        {
                            Console.WriteLine($"Unexpected sequence end for #{oldLineNumber}/{instrLineNumber}/{instrSequenceNumber} image {oldImageId} offset {oldOffset:x}");
                            return;
                        }

                        inSequence = false;
                        currentInstrLine = memTraceInstrReader.ReadLine();
                        ++instrLineNumber;
                        ++instrSequenceNumber;
                        break;
                    }
                    else if(instrSplit[0] == "I")
                    {
                        instrImageId = int.Parse(instrSplit[1], NumberStyles.HexNumber);
                        instrInstructionOffset = uint.Parse(instrSplit[2], NumberStyles.HexNumber);

                        // Only handle non-ignored instructions
                        if(!_ignoredInstructions.Contains((instrImageId, instrInstructionOffset)))
                        {
                            if(oldImageId != instrImageId)
                                break;

                            if(instrSplit[3] == "?")
                            {
                                foundEquivalent = true;
                            }
                            else
                            {
                                //ulong instrInstructionAddress = ulong.Parse(instrSplit[1], NumberStyles.HexNumber);
                                //ulong instrMemAddress = ulong.Parse(instrSplit[3], NumberStyles.HexNumber);
                                ulong instrBlockAddress = ulong.Parse(instrSplit[4], NumberStyles.HexNumber);
                                //int instrWidth = ushort.Parse(instrSplit[5], NumberStyles.HexNumber);

                                (ulong high, ulong low) instrBlock0 = (ulong.Parse(instrSplit[6][..16], NumberStyles.HexNumber), ulong.Parse(instrSplit[6][16..], NumberStyles.HexNumber));

                                (ulong high, ulong low)? instrBlock1 = null;
                                if(instrSplit.Length > 7)
                                    instrBlock1 = (ulong.Parse(instrSplit[7][..16], NumberStyles.HexNumber), ulong.Parse(instrSplit[7][16..], NumberStyles.HexNumber));

                                // Check whether instructions are equivalent
                                bool equivalent = (oldOffset == instrInstructionOffset);
                                if(!equivalent && _oldToNewInstructionMapping.TryGetValue((oldImageId, oldOffset), out var equivalentInstrInstructions))
                                    equivalent = equivalentInstrInstructions.Contains(instrInstructionOffset);

                                if(!equivalent)
                                    break;

                                foundEquivalent = true;

                                // Track block values
                                if(!_blockAddressToBlockValueCountMapping.TryGetValue(instrBlockAddress, out var blockValueCounts))
                                {
                                    blockValueCounts = new();
                                    _blockAddressToBlockValueCountMapping.Add(instrBlockAddress, blockValueCounts);
                                }

                                // Update count for first block
                                if(blockValueCounts.TryGetValue((instrBlock0.high, instrBlock0.low), out int oldCount0))
                                {
                                    if(oldSecret)
                                        blockValueCounts[(instrBlock0.high, instrBlock0.low)] = oldCount0 + 1;
                                }
                                else
                                {
                                    blockValueCounts.Add((instrBlock0.high, instrBlock0.low), 0);
                                }

                                // Update count for second block
                                if(instrBlock1 != null)
                                {
                                    if(blockValueCounts.TryGetValue((instrBlock1.Value.high, instrBlock1.Value.low), out int oldCount1))
                                    {
                                        if(oldSecret)
                                            blockValueCounts[(instrBlock1.Value.high, instrBlock1.Value.low)] = oldCount1 + 1;
                                    }
                                    else
                                    {
                                        blockValueCounts.Add((instrBlock1.Value.high, instrBlock1.Value.low), 0);
                                    }
                                }

                                if(oldSecret)
                                    _interestingBlockAddresses.Add(instrBlockAddress);
                            }

                            if(!inSequence)
                            {
                                // Next instr line
                                currentInstrLine = memTraceInstrReader.ReadLine();
                                ++instrLineNumber;
                                ++instrSequenceNumber;
                                break;
                            }
                        }
                    }

                    // Next instr line
                    currentInstrLine = memTraceInstrReader.ReadLine();
                    ++instrLineNumber;
                }

                if(!foundEquivalent)
                {
                    Console.WriteLine($"Can not find equivalent instr memtrace line for #{oldLineNumber}/{instrLineNumber}/{instrSequenceNumber} image {oldImageId} offset {oldOffset:x} (last instr: image {instrImageId} offset {instrInstructionOffset:x})");
                    filesMatch = false;
                    break;
                }

                ++oldLineNumber;
            }

            Console.WriteLine($"--> Files {(filesMatch ? "" : "don't")} match");
            Console.WriteLine($"    {(memTraceInstrReader.BaseStream.Length - memTraceInstrReader.BaseStream.Position)} bytes missing from instr memtrace");

            foreach(var blockValueCounts in _blockAddressToBlockValueCountMapping)
            {
                if(!_interestingBlockAddresses.Contains(blockValueCounts.Key))
                    continue;

                Console.WriteLine($"Block {blockValueCounts.Key:x}");
                int uniqueCount = 0;
                foreach(var valueCount in blockValueCounts.Value)
                {
                    if(valueCount.Value == 0)
                        ++uniqueCount;
                    else
                        Console.WriteLine($"  {valueCount.Key.high:x16}{valueCount.Key.low:x16}  {valueCount.Value}");
                }

                Console.WriteLine($"  Unique: {uniqueCount}");
            }

            Console.WriteLine($"Total {_interestingBlockAddresses.Count} blocks");
        }
        finally
        {
            Console.WriteLine($"Processed {oldLineNumber} lines");
        }
    }
}