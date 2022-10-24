using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ElfTools;
using ElfTools.Chunks;
using ElfTools.Enums;

namespace StaticInstrumentation;

/// <summary>
/// Provides functions to build the .instr.text section from the code template.
/// </summary>
public class InstrTextSectionBuilder
{
    private readonly byte[] _templateData;
    private readonly Dictionary<string, int> _templateDataSymbolOffsets;

    /// <summary>
    /// Base address of the .instr.text section.
    /// </summary>
    public ulong BaseAddress { get; set; }

    /// <summary>
    /// Address of the pointer to __libc_start_main.
    /// </summary>
    public ulong LibcStartMainPointerAddress { get; set; }

    /// <summary>
    /// Instrumented basic blocks.
    /// These will be inserted at the address which <see cref="GetBasicBlockInstrumentationAreaBaseAddress"/> returns.
    /// </summary>
    public byte[] BasicBlockInstrumentationArea { get; set; }

    /// <summary>
    /// Addresses of all int3 instructions and their instrumentation section counterparts.
    /// </summary>
    public List<(ulong int3Address, ulong instrumentationAddress)> Int3Addresses { get; set; }

    /// <summary>
    /// Address of the first constructor from the .init_array section.
    /// </summary>
    public ulong FirstConstructorAddress { get; set; }

    /// <summary>
    /// Addresses of segments which need a corresponding mask buffer.
    /// </summary>
    public List<(ulong baseAddress, int length, bool readOnly)> SegmentAddresses { get; set; }

    /// <summary>
    /// Addresses of private data blocks.
    /// </summary>
    public List<(ulong baseAddress, int length)> PrivateDataBlockAddresses { get; set; }

    /// <summary>
    /// End address of the instrumentation header.
    /// Only valid after <see cref="Build"/> was called.
    /// </summary>
    public ulong HeaderEndAddress { get; private set; }


    /// <summary>
    /// Creates a new .instr.text section builder from the given template object file.
    /// </summary>
    /// <param name="templateObjectPath">Path to template object.</param>
    public InstrTextSectionBuilder(string templateObjectPath)
    {
        // Load template object
        var template = ElfReader.Load(templateObjectPath);
        var sectionNameStringTableChunk = (StringTableChunk)template.Chunks[template.GetChunkAtFileOffset(template.SectionHeaderTable.SectionHeaders[template.Header.SectionHeaderStringTableIndex].FileOffset)!.Value.chunkIndex];
        var stringTableChunk = (StringTableChunk)template.Chunks[template.GetChunkAtFileOffset(template.SectionHeaderTable.SectionHeaders.First(s => sectionNameStringTableChunk.GetString(s.NameStringTableOffset) == ".strtab").FileOffset)!.Value.chunkIndex];

        // Copy .text section
        var textSectionHeader = template.SectionHeaderTable.SectionHeaders.First(s => sectionNameStringTableChunk.GetString(s.NameStringTableOffset) == ".text");
        var textSectionChunk = (RawSectionChunk)template.Chunks[template.GetChunkAtFileOffset(textSectionHeader.FileOffset)!.Value.chunkIndex];
        _templateData = textSectionChunk.Bytes;

        // Read symbols
        var symtabSectionHeader = template.SectionHeaderTable.SectionHeaders.First(s => s.Type == SectionType.SymbolTable);
        var symtabSectionChunk = (SymbolTableChunk)template.Chunks[template.GetChunkAtFileOffset(symtabSectionHeader.FileOffset)!.Value.chunkIndex];
        _templateDataSymbolOffsets = symtabSectionChunk.Entries
            .Select(s => new { symbolData = s, symbolName = stringTableChunk.GetString(s.Name) })
            .Where(s => !string.IsNullOrWhiteSpace(s.symbolName) && (s.symbolData.Info & SymbolInfo.MaskType) is not SymbolInfo.TypeFile or SymbolInfo.TypeSection)
            .ToDictionary(s => s.symbolName, s => (int)s.symbolData.Value);
    }

    /// <summary>
    /// Builds the .instr.text section.
    /// </summary>
    /// <param name="symbols">List of symbols inserted into the instrumentation section (for debugging).</param>
    /// <returns></returns>
    public byte[] Build(out List<(ulong address, string name)> symbols)
    {
        using var outputStream = new MemoryStream();
        using var outputWriter = new BinaryWriter(outputStream);

        // Label addresses
        int headerBegin = _templateDataSymbolOffsets["instrument_header_begin"];
        int headerEntryPointMainCall = _templateDataSymbolOffsets["instrument_entrypoint_main_call"];
        int headerConstructorJump = _templateDataSymbolOffsets["library_init.constructor_jump"];
        int segmentsPointer = _templateDataSymbolOffsets["segments_pointer"];
        int privateDataBlocksPointer = _templateDataSymbolOffsets["private_data_blocks_pointer"];
        int headerSignalHandlerHashTable = _templateDataSymbolOffsets["instrument_signal_handler_hash_table"];
        int headerEnd = _templateDataSymbolOffsets["instrument_header_end"];

        var templateSpan = _templateData.AsSpan();
        symbols = new List<(ulong address, string name)>();

        // Prepare int3 hash table
        const int signalHandlerTableCount = 16;
        List<List<(ulong, ulong)>> int3HashTable = new();
        for(int i = 0; i < signalHandlerTableCount; ++i)
            int3HashTable.Add(new List<(ulong, ulong)>());
        foreach((ulong int3Address, ulong instrumentationAddress) in Int3Addresses)
        {
            ulong int3Distance = unchecked(int3Address + 1 - (BaseAddress + (ulong)headerBegin)); // +1 due to RIP pointing to the instruction _after_ int3
            ulong instrumentationDistance = unchecked(instrumentationAddress - (BaseAddress + (ulong)headerBegin));

            int hash = (int)((int3Distance >> 3) & (signalHandlerTableCount - 1));
            int3HashTable[hash].Add((int3Distance, instrumentationDistance));
        }

        // Write first parts of header until jump to library constructor
        outputWriter.Write(templateSpan[headerBegin..headerEntryPointMainCall]);
        outputWriter.Write((byte)0xff);
        outputWriter.Write((byte)0x15);
        outputWriter.Write((uint)(LibcStartMainPointerAddress - (BaseAddress + (ulong)headerEntryPointMainCall + 6)));
        outputWriter.Write(templateSpan[(headerEntryPointMainCall + 6)..headerConstructorJump]);

        // Jump to overwritten address of constructor
        if(FirstConstructorAddress != 0)
        {
            outputWriter.Write((byte)0xe9);
            outputWriter.Write((uint)(FirstConstructorAddress - (BaseAddress + (ulong)headerConstructorJump + 5)));
        }
        else
        {
            // There is no other constructor, just return
            outputWriter.Write((byte)0xc3);
            outputWriter.Write((byte)0xf4);
            outputWriter.Write((byte)0xf4);
            outputWriter.Write((byte)0xf4);
            outputWriter.Write((byte)0xf4);
        }

        outputWriter.Write(templateSpan[(headerConstructorJump + 5)..headerSignalHandlerHashTable]);

        // Write hash table
        int bbAreaOffset = (int)(GetBasicBlockInstrumentationAreaBaseAddress() - BaseAddress);
        int signalHandlerTableDataOffset = (bbAreaOffset + BasicBlockInstrumentationArea.Length + 64) & ~0x3f; // Align to 64 bytes
        int signalHandlerTableDataOffsetCurrent = signalHandlerTableDataOffset;
        foreach(var entries in int3HashTable)
        {
            outputWriter.Write((ulong)(signalHandlerTableDataOffsetCurrent - headerBegin));

            signalHandlerTableDataOffsetCurrent += 16 * (entries.Count + 1);
        }

        // Remaining header
        outputWriter.Write(templateSpan[(headerSignalHandlerHashTable + signalHandlerTableCount * 8)..headerEnd]);
        HeaderEndAddress = BaseAddress + (ulong)outputStream.Length;

        // Padding
        if(outputStream.Length > bbAreaOffset)
            throw new InvalidOperationException("The output stream has moved past the expected BB instrumentation area base address.");
        outputWriter.Write(Enumerable.Repeat<byte>(0x00, (int)(bbAreaOffset - outputStream.Position)).ToArray());

        // Basic blocks
        outputWriter.Write(BasicBlockInstrumentationArea);

        // Padding
        if(outputStream.Length > signalHandlerTableDataOffset)
            throw new InvalidOperationException("The output stream has moved past the expected signal handler data area base address.");
        outputWriter.Write(Enumerable.Repeat<byte>(0x00, (int)(signalHandlerTableDataOffset - outputStream.Position)).ToArray());

        // Write signal handler offsets
        foreach(var entries in int3HashTable)
        {
            // Write entries
            foreach(var entry in entries)
            {
                outputWriter.Write(entry.Item1);
                outputWriter.Write(entry.Item2);
            }

            // Write terminating NULL entry
            outputWriter.Write(0ul);
            outputWriter.Write(0ul);
        }

        // Merge overlapping segments and adjust offsets
        List<(ulong baseAddress, int length, bool readOnly)> segments = new();
        foreach(var segmentInfo in SegmentAddresses.OrderBy(s => s.baseAddress))
        {
            // Align base address and length
            ulong alignedBaseAddress = (segmentInfo.baseAddress & 0xfff) == 0 ? segmentInfo.baseAddress : (segmentInfo.baseAddress + 0x1000) & ~0xffful;
            ulong alignedLength = (segmentInfo.length & 0xfff) == 0 ? (ulong)segmentInfo.length : ((ulong)segmentInfo.length + 0x1000) & ~0xffful;

            // Is there an overlapping segment?
            bool found = false;
            for(int i = 0; i < segments.Count; ++i)
            {
                var currentSegment = segments[i];
                if(currentSegment.baseAddress <= alignedBaseAddress && alignedBaseAddress <= currentSegment.baseAddress + (ulong)currentSegment.length)
                {
                    // We can simply extend the existing segment
                    segments[i] = (currentSegment.baseAddress, (int)(Math.Max(currentSegment.baseAddress + (ulong)currentSegment.length, alignedBaseAddress + alignedLength) - currentSegment.baseAddress), segmentInfo.readOnly && currentSegment.readOnly);

                    found = true;
                    break;
                }
            }

            if(found)
                continue;

            // Not known yet, insert it into the list
            segments.Add((alignedBaseAddress, (int)alignedLength, segmentInfo.readOnly));
        }

        // Write segment list
        int segmentListOffset = (int)outputWriter.BaseStream.Position;
        outputWriter.Seek(segmentsPointer, SeekOrigin.Begin);
        outputWriter.Write((ulong)(segmentListOffset - headerBegin));
        outputWriter.Seek(segmentListOffset, SeekOrigin.Begin);
        foreach(var segmentInfo in segments)
        {
            outputWriter.Write(unchecked(segmentInfo.baseAddress - (BaseAddress + (ulong)headerBegin))); // 8 bytes
            outputWriter.Write(segmentInfo.length); // 4 bytes
            outputWriter.Write(0); // 4 bytes padding
        }

        outputWriter.Write(Enumerable.Repeat((byte)0, 16).ToArray()); // Terminator

        // Write data block info
        int privateDataBlocksListOffset = (int)outputWriter.BaseStream.Position;
        outputWriter.Seek(privateDataBlocksPointer, SeekOrigin.Begin);
        outputWriter.Write((ulong)(privateDataBlocksListOffset - headerBegin));
        outputWriter.Seek(privateDataBlocksListOffset, SeekOrigin.Begin);
        foreach(var dataBlockInfo in PrivateDataBlockAddresses)
        {
            var segment = segments.First(s => s.baseAddress <= dataBlockInfo.baseAddress && dataBlockInfo.baseAddress + (uint)dataBlockInfo.length <= s.baseAddress + (uint)s.length);

            outputWriter.Write(unchecked(dataBlockInfo.baseAddress - (BaseAddress + (ulong)headerBegin))); // 8 bytes
            outputWriter.Write(dataBlockInfo.length); // 4 bytes
            outputWriter.Write((byte)(segment.readOnly ? 0 : 1)); // 1 byte

            outputWriter.Write((byte)0); // 1 byte padding
            outputWriter.Write((ushort)0); // 2 bytes padding
        }

        outputWriter.Write(Enumerable.Repeat((byte)0, 16).ToArray()); // Terminator

        // Return header symbols for easier debugging
        symbols.AddRange(
            _templateDataSymbolOffsets
                .Where(s => headerBegin <= s.Value && s.Value <= headerEnd)
                .Select(s => ((ulong)s.Value + BaseAddress, s.Key))
        );

        outputWriter.Flush();
        return outputStream.ToArray();
    }

    /// <summary>
    /// Returns the address of the given instrumentation symbol.
    /// Ensure that <see cref="BaseAddress"/> has been set before.
    /// </summary>
    /// <param name="name">Symbol name.</param>
    /// <returns>Symbol offset.</returns>
    public ulong GetAddressOfSymbol(string name)
    {
        return BaseAddress + (ulong)_templateDataSymbolOffsets[name];
    }

    /// <summary>
    /// Returns the guaranteed base address of the instrumented basic blocks area which follows instrumentation header code.
    /// </summary>
    /// <returns></returns>
    public ulong GetBasicBlockInstrumentationAreaBaseAddress()
    {
        // Compute size of header
        int headerBegin = _templateDataSymbolOffsets["instrument_header_begin"];
        int headerEnd = _templateDataSymbolOffsets["instrument_header_end"];
        int headerSize = headerEnd - headerBegin;

        // Align
        headerSize = (headerSize + 0x40) & ~0x3f;

        return BaseAddress + (ulong)headerSize;
    }
}