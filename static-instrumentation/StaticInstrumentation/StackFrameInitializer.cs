using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace StaticInstrumentation;

public class StackFrameInitializer
{
    private readonly Assembler _assembler = new(64);

    public List<Instruction> InitializeStackFrame(Instruction instruction, AnalysisResult.InstructionData instructionData, AnalysisResult.StackFrameData stackFrameData)
    {
        // Initialize fresh state
        _assembler.Reset();
        ToyRegisterAllocator registerAllocator = new(_assembler, instructionData);

        // We may need to keep flags, if the stack frame initializer is mistakenly placed within a function (e.g. jump within a function misdetected as tail call)
        registerAllocator.SaveFlags(instructionData.KeepFlags);

        var maskedOffsets = stackFrameData.SecretOffsets
            .Select(o => -(int)o)
            .OrderBy(o => o)
            .ToList();
        var zeroOffsets = Enumerable
            .Range(1, (int)stackFrameData.Size)
            .Except(
                stackFrameData.SecretOffsets
                    .Select(o => (int)o)
            )
            .Select(o => -o)
            .OrderBy(o => o)
            .ToList();

        // First, convert zero and masked areas into a series of chunks
        var maskedChunks = GetPowerOf2Subsequences(maskedOffsets).ToList();
        var zeroChunks = GetPowerOf2Subsequences(zeroOffsets).ToList();

        // Get total length of respective chunks
        int maskedChunksTotalLength = maskedChunks.Sum(c => c.length);
        int zeroChunksTotalLength = zeroChunks.Sum(c => c.length);
        int totalLength = maskedChunksTotalLength + zeroChunksTotalLength;
        Debug.Assert(totalLength == stackFrameData.Size);

        _assembler.DebugMarkSkippableSectionBegin();

        /*
         * We have a couple of relevant cases:
         * - No secret data in this stack frame at all
         * - Interleaved secret/non-secret data
         *   - Large secret area, small non-secret area
         *   - Large non-secret area, small secret area
         *   - Both areas similarly sized
         *
         * In addition, the areas may be heavily intertwined, or entirely separate.
         *
         * In general, we would prefer to use a `rep stosq` instruction to initialize as much memory as possible at once.
         * However, if there is great overlap between zeros/masks, we would write twice to the same memory, which is not
         * efficient.
         *
         * To make this even more complicated, there is a certain threshold where `rep stosq` becomes more efficient than
         * a vectorized write, and a threshold where a vectorized write is more efficient than a sequence of `mov`s.
         *
         * For now, we only distinguish between small and large stack frames, where the former are initialized with normal
         * `mov`s, and the latter are initialized with AVX instructions.
         */

        using var toy1 = registerAllocator.AllocateToyRegister();

        // Generate mask, if necessary
        if(maskedChunks.Count > 0)
        {
            if(MaskUtils.UseSecrecyBuffer)
            {
                // Secrecy buffer flags
                _assembler.mov(toy1.Reg64, -1);
            }
            else
            {
                // We use the same initial mask value for all secrets
                MaskUtils.GenerateMask(_assembler, toy1.Reg64);
            }
        }

        int bufferOffset = MaskUtils.UseSecrecyBuffer ? MaskUtils.SecrecyBufferOffset : MaskUtils.MaskBufferOffset;

        if(totalLength <= 64)
        {
            foreach(var chunk in maskedChunks)
            {
                switch(chunk.length)
                {
                    case 1:
                        _assembler.mov(__byte_ptr[rsp + chunk.start + bufferOffset], toy1.Reg8);
                        break;
                    case 2:
                        _assembler.mov(__word_ptr[rsp + chunk.start + bufferOffset], toy1.Reg16);
                        break;
                    case 4:
                        _assembler.mov(__dword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg32);
                        break;
                    case 8:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        break;
                    case 16:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 8 + bufferOffset], toy1.Reg64);
                        break;
                    case 32:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 8 + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 16 + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 24 + bufferOffset], toy1.Reg64);
                        break;
                }
            }

            _assembler.xor(toy1.Reg32, toy1.Reg32);
            foreach(var chunk in zeroChunks)
            {
                switch(chunk.length)
                {
                    case 1:
                        _assembler.mov(__byte_ptr[rsp + chunk.start + bufferOffset], toy1.Reg8);
                        break;
                    case 2:
                        _assembler.mov(__word_ptr[rsp + chunk.start + bufferOffset], toy1.Reg16);
                        break;
                    case 4:
                        _assembler.mov(__dword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg32);
                        break;
                    case 8:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        break;
                    case 16:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 8 + bufferOffset], toy1.Reg64);
                        break;
                    case 32:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 8 + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 16 + bufferOffset], toy1.Reg64);
                        _assembler.mov(__qword_ptr[rsp + chunk.start + 24 + bufferOffset], toy1.Reg64);
                        break;
                }
            }
            
            // Add some padding before and after the stack frame
            if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites)
            {
                _assembler.mov(__qword_ptr[rsp + MaskUtils.SecrecyBufferOffset], toy1.Reg64);
                _assembler.mov(__qword_ptr[rsp - totalLength - 8 + MaskUtils.SecrecyBufferOffset], toy1.Reg64);
            }
        }
        else
        {
            var toyPrimary = registerAllocator.AllocateToyVectorRegister();
            var toySecondary = registerAllocator.AllocateToyVectorRegister();

            // Decide which chunk type is more prevalent
            List<(int start, int length)> chunksSecondary;
            List<int> offsetsSecondary;
            if(maskedChunksTotalLength > zeroChunksTotalLength)
            {
                chunksSecondary = zeroChunks;
                offsetsSecondary = zeroOffsets;

                _assembler.vmovq(toySecondary.RegXMM, toy1.Reg64);
                _assembler.vpbroadcastq(toyPrimary.RegYMM, toySecondary.RegXMM);
                _assembler.vpxor(toySecondary.RegXMM, toySecondary.RegXMM, toySecondary.RegXMM);
            }
            else
            {
                chunksSecondary = maskedChunks;
                offsetsSecondary = maskedOffsets;

                _assembler.vmovq(toyPrimary.RegXMM, toy1.Reg64);
                _assembler.vpbroadcastq(toySecondary.RegYMM, toyPrimary.RegXMM);
                _assembler.vpxor(toyPrimary.RegXMM, toyPrimary.RegXMM, toyPrimary.RegXMM);
            }

            // 1. Fill entire stack frame with primary chunk types
            //    Skip chunks which are entirely of type secondary
            // 2. Write secondary chunk type

            // We can safely assume that the stack pointer is 8-byte, but not 16-byte aligned (x86-64 ABI)
            // We can safely modify the mask buffer _above_ the stack frame
            // We can safely put a mask behind the return address
            /*
             * 16 ->  |------------------|
             *        |                  |
             *        |------------------|  # Actual stack frame
             *        |    unaligned     |  #
             * 16 ->  |------------------|  # 
             *        | 16-byte aligned  |  #
             * rsp -> |------------------|  #
             *        |  return address  |
             * 16 ->  |------------------|
             */

            // Thus, we first ensure that we have a 16-byte alignment: Subtracting an 8-byte aligned size
            // from the 8-byte aligned stack pointer gives us a 16-byte aligned stack frame base address
            int alignedSize = totalLength & ~7; // 8-byte alignment
            if(alignedSize % 16 == 0)
                alignedSize -= 8;
            if(alignedSize < totalLength)
                alignedSize += 16;

            // Write 32-byte chunks
            // The chance that the stack frame base is 32-byte aligned is 50:50
            // -> TODO optimization potential: 32-byte alignment; rep stos if there are a lot of chunks
            int offset = -alignedSize;
            while(offset <= -0x18)
            {
                if(!HasConsecutiveSubsequence(offsetsSecondary, offset, 0x20))
                    _assembler.vmovdqu(__ymmword_ptr[rsp + offset + bufferOffset], toyPrimary.RegYMM);

                offset += 0x20;
            }

            // Is there a missing 16-byte chunk?
            if(offset < 0)
            {
                if(!HasConsecutiveSubsequence(offsetsSecondary, offset, 0x10))
                    _assembler.vmovdqu(__xmmword_ptr[rsp + offset + bufferOffset], toyPrimary.RegXMM);

                offset += 0x10;
                Debug.Assert(offset == 8);
            }

            // Write secondary chunks
            if(chunksSecondary == zeroChunks)
                _assembler.xor(toy1.Reg32, toy1.Reg32);
            foreach(var chunk in chunksSecondary)
            {
                switch(chunk.length)
                {
                    case 1:
                        _assembler.mov(__byte_ptr[rsp + chunk.start + bufferOffset], toy1.Reg8);
                        break;
                    case 2:
                        _assembler.mov(__word_ptr[rsp + chunk.start + bufferOffset], toy1.Reg16);
                        break;
                    case 4:
                        _assembler.mov(__dword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg32);
                        break;
                    case 8:
                        _assembler.mov(__qword_ptr[rsp + chunk.start + bufferOffset], toy1.Reg64);
                        break;
                    case 16:
                        _assembler.vmovdqu(__xmmword_ptr[rsp + chunk.start + bufferOffset], toySecondary.RegXMM);
                        break;
                    case 32:
                        _assembler.vmovdqu(__ymmword_ptr[rsp + chunk.start + bufferOffset], toySecondary.RegYMM);
                        break;
                }
            }
            
            // Add some padding before and after the stack frame
            if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites)
            {
                // Zero toy register, if necessary
                if(chunksSecondary != zeroChunks)
                    _assembler.xor(toy1.Reg32, toy1.Reg32);
                
                _assembler.mov(__qword_ptr[rsp + MaskUtils.SecrecyBufferOffset], toy1.Reg64);
                _assembler.mov(__qword_ptr[rsp - totalLength - 8 + MaskUtils.SecrecyBufferOffset], toy1.Reg64);
            }
        }

        registerAllocator.FreeToyRegister(toy1);

        // Restore toy registers and flags
        registerAllocator.Restore();

        _assembler.DebugMarkSkippableSectionEnd();

        // Assemble instructions
        using var outStream = new MemoryStream();
        var assembleWriter = new StreamCodeWriter(outStream);
        _assembler.Assemble(assembleWriter, instruction.IP);

        // ...and disassemble them again, to get consistent instruction objects
        outStream.Seek(0, SeekOrigin.Begin);
        var disassembleReader = new StreamCodeReader(outStream);
        var disassembler = Decoder.Create(64, disassembleReader, instruction.IP);
        List<Instruction> instructions = new();
        while(outStream.Position < outStream.Length)
        {
            var ins = disassembler.Decode();
            instructions.Add(ins);
        }

        return instructions;
    }

    private static bool HasConsecutiveSubsequence(IEnumerable<int> sortedSequence, int start, int length)
    {
        // Find start
        bool startFound = false;
        using var enumerator = sortedSequence.GetEnumerator();
        while(enumerator.MoveNext())
        {
            if(enumerator.Current == start)
            {
                startFound = true;
                break;
            }
        }

        if(!startFound)
            return false;

        // Check subsequent numbers
        for(int i = 1; i < length; ++i)
        {
            if(!enumerator.MoveNext())
                return false;

            if(enumerator.Current != start + i)
                return false;
        }

        return true;
    }

    /// <summary>
    /// Converts the given sequence of offsets into a series of aligned chunks of size 2^n (n &lt;= 3).
    /// </summary>
    /// <param name="sortedSequence">Sequence of offsets.</param>
    /// <returns></returns>
    private static IEnumerable<(int start, int length)> GetPowerOf2Subsequences(IEnumerable<int> sortedSequence)
    {
        // First, we look for contiguous sequences
        // Then, we split those into chunks

        int? first = null;
        int? last = null;
        foreach(var value in sortedSequence)
        {
            if(first == null)
            {
                first = value;
                last = value;
                continue;
            }

            if(value > last.Value + 1)
            {
                // The current sequence ended. Yield aligned chunks
                foreach(var chunk in SplitChunk(first.Value, last.Value))
                    yield return chunk;

                first = value;
            }

            last = value;
        }

        // Generate remaining chunks
        if(first <= last)
        {
            foreach(var chunk in SplitChunk(first.Value, last.Value))
                yield return chunk;
        }
    }

    private static IEnumerable<(int start, int length)> SplitChunk(int first, int last)
    {
        int start = first;
        int length = last + 1 - first;

        // If we have a small, even length, don't care about alignment
        if(length is 8 or 4 or 2 or 1)
        {
            yield return (start, length);
            yield break;
        }

        // The length is either uneven, or big, so we need multiple chunks
        // First, we create aligned chunks of increasing size until a certain cap, where all new chunks are the same size 
        // Then, we create a few more chunks to cover the remaining bytes

        // First align the start
        if(length >= 1 && (start & 1) != 0)
        {
            yield return (start, 1);
            start += 1;
            length -= 1;
        }

        if(length >= 2 && (start & 2) != 0)
        {
            yield return (start, 2);
            start += 2;
            length -= 2;
        }

        if(length >= 4 && (start & 4) != 0)
        {
            yield return (start, 4);
            start += 4;
            length -= 4;
        }

        // We now have 8-byte alignment

        // Generate 32-byte to 8-byte chunks until we run out of space
        while(length >= 32)
        {
            yield return (start, 32);
            start += 32;
            length -= 32;
        }

        while(length >= 16)
        {
            yield return (start, 16);
            start += 16;
            length -= 16;
        }

        while(length >= 8)
        {
            yield return (start, 8);
            start += 8;
            length -= 8;
        }

        // Generate final chunks
        if(length >= 4)
        {
            yield return (start, 4);
            start += 4;
            length -= 4;
        }

        if(length >= 2)
        {
            yield return (start, 2);
            start += 2;
            length -= 2;
        }

        if(length >= 1)
        {
            yield return (start, 1);
            start += 1;
            length -= 1;
        }

        Debug.Assert(start > last && length == 0);
    }
}