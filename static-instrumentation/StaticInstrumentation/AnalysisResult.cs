using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Iced.Intel;

namespace StaticInstrumentation;

/// <summary>
/// Offers functionality for parsing and accessing the output of the memory access analysis.
/// </summary>
public class AnalysisResult
{
    public Dictionary<int, ImageData> Images { get; } = new();

    /// <summary>
    /// Image memory blocks containing private data.
    /// </summary>
    public Dictionary<int, ImageMemoryBlock> ImageMemoryBlocks { get; } = new();

    public StackMemoryBlock StackData { get; private set; }

    /// <summary>
    /// Heap memory blocks containing private data.
    /// </summary>
    public Dictionary<int, HeapMemoryBlock> HeapMemoryBlocks { get; } = new();

    public Dictionary<(int imageId, uint offset), StackFrameData> StackFrames { get; } = new();

    public Dictionary<(int imageId, uint offset), InstructionData> Instructions { get; } = new();

    private AnalysisResult()
    {
    }

    /// <summary>
    /// Parses the given file.
    /// </summary>
    /// <param name="path">File path.</param>
    /// <returns></returns>
    public static AnalysisResult FromFile(string path)
    {
        // Create new result object
        var result = new AnalysisResult();

        // Load file
        var lines = File.ReadAllLines(path);
        using var filteredLinesEnumerator = lines
            .Where(l => !string.IsNullOrWhiteSpace(l) && !l.StartsWith('['))
            .GetEnumerator();
        filteredLinesEnumerator.MoveNext();

        // Read images
        int imageCount = int.Parse(filteredLinesEnumerator.Current!);
        filteredLinesEnumerator.MoveNext();
        for(int i = 0; i < imageCount; ++i)
        {
            var line = filteredLinesEnumerator.Current;
            filteredLinesEnumerator.MoveNext();

            var lineSplit = line!.Split('\t');

            var id = int.Parse(lineSplit[0]);
            // size [1]
            var name = lineSplit[2];
            var start = ulong.Parse(lineSplit[3], NumberStyles.HexNumber);
            var end = ulong.Parse(lineSplit[4], NumberStyles.HexNumber);

            result.Images.Add(id, new ImageData(id, name, start, end));
        }

        // Read stack frames
        int stackFrameCount = int.Parse(filteredLinesEnumerator.Current!);
        filteredLinesEnumerator.MoveNext();
        for(int i = 0; i < stackFrameCount; ++i)
        {
            var line = filteredLinesEnumerator.Current;
            filteredLinesEnumerator.MoveNext();

            var lineSplit = line!.Split('\t', StringSplitOptions.RemoveEmptyEntries);

            var imageId = int.Parse(lineSplit[0]);
            var imageOffset = uint.Parse(lineSplit[1], NumberStyles.HexNumber);
            var size = uint.Parse(lineSplit[2], NumberStyles.HexNumber);
            var secretOffsetsCount = int.Parse(lineSplit[3]);

            var secretOffsets = Enumerable
                .Range(0, secretOffsetsCount)
                .Select(o => uint.Parse(lineSplit[4 + o], NumberStyles.HexNumber))
                .ToList();

            result.StackFrames[(imageId, imageOffset)] = new StackFrameData(imageId, imageOffset, size, secretOffsets);
        }

        // Read memory blocks
        int memoryBlockCount = int.Parse(filteredLinesEnumerator.Current!);
        filteredLinesEnumerator.MoveNext();
        for(int i = 0; i < memoryBlockCount; ++i)
        {
            var line = filteredLinesEnumerator.Current;
            filteredLinesEnumerator.MoveNext();

            var lineSplit = line!.Split('\t');

            var imageId = int.Parse(lineSplit[0]);
            var offset = int.Parse(lineSplit[1], NumberStyles.HexNumber);
            var id = int.Parse(lineSplit[2]);
            var size = int.Parse(lineSplit[3], NumberStyles.HexNumber);
            // start [4]
            // end [5]
            var type = int.Parse(lineSplit[6]);
            var secure = int.Parse(lineSplit[7]) != 0;

            if(type == 1 && secure)
                result.ImageMemoryBlocks.Add(id, new ImageMemoryBlock(id, imageId, offset, size));
            else if(type == 2)
                result.StackData = new StackMemoryBlock(id, size);
            else if(type == 3)
                result.HeapMemoryBlocks.Add(id, new HeapMemoryBlock(id, size, new List<CallStackEntry>(), secure));
        }

        // Read heap memory block call stacks
        int callStackEntryCount = int.Parse(filteredLinesEnumerator.Current!);
        filteredLinesEnumerator.MoveNext();
        for(int i = 0; i < callStackEntryCount; ++i)
        {
            var line = filteredLinesEnumerator.Current;
            filteredLinesEnumerator.MoveNext();

            var lineSplit = line!.Split('\t');

            var sourceImageId = int.Parse(lineSplit[0]);
            var sourceImageOffset = int.Parse(lineSplit[1], NumberStyles.HexNumber);
            var targetImageId = int.Parse(lineSplit[2]);
            var targetImageOffset = int.Parse(lineSplit[3], NumberStyles.HexNumber);
            // source address [4]
            // target address [5]
            var blockId = int.Parse(lineSplit[6]);

            // Ignore dummy entry
            if(sourceImageId == 0 && sourceImageOffset == 0)
                continue;
                
            result.HeapMemoryBlocks[blockId].CallStack.Add(new CallStackEntry(sourceImageId, sourceImageOffset, targetImageId, targetImageOffset));
        }

        // Read instructions
        int instructionCount = int.Parse(filteredLinesEnumerator.Current!);
        filteredLinesEnumerator.MoveNext();
        for(int i = 0; i < instructionCount; ++i)
        {
            var line = filteredLinesEnumerator.Current;
            filteredLinesEnumerator.MoveNext();

            var lineSplit = line!.Split('\t');

            var address = ulong.Parse(lineSplit[0], NumberStyles.HexNumber);
            var imageId = int.Parse(lineSplit[1]);
            if(imageId == 0)
            {
                Console.WriteLine($"Skipping instruction {address:x} (could not resolve image)");
                continue;
            }

            var offset = uint.Parse(lineSplit[2], NumberStyles.HexNumber);
            // size [3]
            var accessType = (AccessType)int.Parse(lineSplit[4]);

            if(result.Instructions.TryGetValue((imageId, offset), out var instructionData))
            {
                instructionData.AccessesOnlySecretBlocks &= (accessType == AccessType.Secret);
            }
            else
            {
                result.Instructions.Add((imageId, offset), new InstructionData
                {
                    ImageId = imageId,
                    ImageOffset = offset,
                    HandlesSecretData = true,
                    AccessesOnlySecretBlocks = (accessType == AccessType.Secret),
                    ReadRegisters = new HashSet<Register>(),
                    WriteRegisters = new HashSet<Register>(),
                    KeepRegisters = new HashSet<Register>(),
                    ReadFlags = new HashSet<RflagsBits>(),
                    WriteFlags = new HashSet<RflagsBits>(),
                    KeepFlags = new HashSet<RflagsBits>()
                });
            }
        }

        return result;
    }

    public class ImageData
    {
        public ImageData(int id, string name, ulong baseAddress, ulong endAddress)
        {
            Id = id;
            Name = name;
            BaseAddress = baseAddress;
            EndAddress = endAddress;
        }

        public int Id { get; }
        public string Name { get; }
        public ulong BaseAddress { get; }
        public ulong EndAddress { get; }
    }

    public class ImageMemoryBlock
    {
        public ImageMemoryBlock(int id, int imageId, int offset, int size)
        {
            Id = id;
            ImageId = imageId;
            Offset = offset;
            Size = size;
        }

        public int Id { get; }
        public int ImageId { get; }
        public int Offset { get; }
        public int Size { get; }
    }

    public class StackMemoryBlock
    {
        public StackMemoryBlock(int id, int size)
        {
            Id = id;
            Size = size;
        }

        public int Id { get; }
        public int Size { get; }
    }

    public class HeapMemoryBlock
    {
        public HeapMemoryBlock(int id, int size, List<CallStackEntry> callStack, bool secret)
        {
            Id = id;
            Size = size;
            CallStack = callStack;
            Secret = secret;
        }

        public int Id { get; }
        public int Size { get; }
        public List<CallStackEntry> CallStack { get; }
        public bool Secret { get; }
    }

    public class CallStackEntry
    {
        public CallStackEntry(int sourceImageId, int sourceImageOffset, int targetImageId, int targetImageOffset)
        {
            SourceImageId = sourceImageId;
            SourceImageOffset = sourceImageOffset;
            TargetImageId = targetImageId;
            TargetImageOffset = targetImageOffset;
        }

        public int SourceImageId { get; }
        public int SourceImageOffset { get; }
        public int TargetImageId { get; }
        public int TargetImageOffset { get; }
    }

    public class StackFrameData
    {
        public int ImageId { get; }
        public uint ImageOffset { get; }
        public uint Size { get; }
        public List<uint> SecretOffsets { get; }

        public StackFrameData(int imageId, uint imageOffset, uint size, List<uint> secretOffsets)
        {
            ImageId = imageId;
            ImageOffset = imageOffset;
            Size = size;
            SecretOffsets = secretOffsets;
        }
    }

    public class InstructionData
    {
        public int ImageId { get; init; }
        public uint ImageOffset { get; init; }
        public bool HandlesSecretData { get; init; }
        public bool AccessesOnlySecretBlocks { get; set; }
        public HashSet<Register> ReadRegisters { get; init; }
        public HashSet<Register> WriteRegisters { get; init; }
        public HashSet<Register> KeepRegisters { get; init; }
        public HashSet<RflagsBits> ReadFlags { get; set; }
        public HashSet<RflagsBits> WriteFlags { get; set; }
        public HashSet<RflagsBits> KeepFlags { get; set; }
    }

    private enum AccessType
    {
        None = 0,
        Secret = 1,
        Public = 2,
        Both = 3
    }
}