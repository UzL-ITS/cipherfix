using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace StaticInstrumentation;

/// <summary>
/// Offers functionality for instrumenting memory accessing instructions.
/// </summary>
public partial class InstructionTranslator
{
    private readonly Assembler _assembler = new(64);

    public InstructionTranslator()
    {
        InitTables();
    }

    public List<Instruction> InstrumentMemoryAccessInstruction(Instruction instruction, AnalysisResult.InstructionData instructionData, out bool isWrite)
    {
        // Initialize fresh state
        _assembler.Reset();
        var registerAllocator = new ToyRegisterAllocator(_assembler, instructionData);

        // Indicates that there is a label which is not immediately followed by an instruction
        // If this is true after generating instruction instrumentation, a dummy instruction is generated
        bool pendingLabel = false; // There will always be at least one instruction, so we can safely initialize this to false

        // Dummy label for correctly handling RIP-relative accesses
        // We must do this before everything else to maintain the correct base address
        Label ripLabel = _assembler.CreateLabel();
        if(instructionData.HandlesSecretData && instruction.IsIPRelativeMemoryOperand)
            _assembler.Label(ref ripLabel);

        // Instrument instructions that may access secret data
        isWrite = false;
        if(instructionData.HandlesSecretData)
        {
            // Analyze instruction
            List<(Register register, int size)> registerOperands = new();
            int width = 0;
            Register memoryOperandBaseRegister = Register.None;
            int memoryOperandIndexScale = 0;
            Register memoryOperandIndexRegister = Register.None;
            long memoryOperandDisplacement = 0;
            ulong? immediateOperand = null;
            {
                // Evaluate operands
                for(int i = 0; i < instruction.OpCount; ++i)
                {
                    var kind = instruction.GetOpKind(i);

                    if(kind == OpKind.Register)
                    {
                        // If the destination operand is a register, we have a read
                        if(i == 0)
                            isWrite = false;

                        var register = instruction.GetOpRegister(i);
                        if(register != Register.None)
                            registerOperands.Add((register.GetFullRegister(), register.GetSize()));

                        // We don't handle -H registers at the moment
                        if(register is Register.AH or Register.BH or Register.CH or Register.DH)
                            Console.WriteLine($"  WARNING: Unsupported high 8-bit subregister in #{instruction.IP} {instruction}");
                    }
                    else if(kind == OpKind.Memory)
                    {
                        // If the destination operand is a memory address, we have a write
                        if(i == 0)
                            isWrite = true;

                        width = instruction.MemorySize.GetInfo().Size;

                        memoryOperandBaseRegister = instruction.MemoryBase.GetFullRegister();
                        memoryOperandIndexScale = instruction.MemoryIndexScale;
                        memoryOperandIndexRegister = instruction.MemoryIndex.GetFullRegister();
                        memoryOperandDisplacement = (long)instruction.MemoryDisplacement64;
                    }
                    else if(kind is OpKind.Immediate8 or OpKind.Immediate16 or OpKind.Immediate32 or OpKind.Immediate64 or OpKind.Immediate8to16 or OpKind.Immediate8to32 or OpKind.Immediate8to64 or OpKind.Immediate32to64)
                    {
                        immediateOperand = instruction.GetImmediate(i);
                    }
                }

                // Special cases where the above heuristics don't work
                if(instruction.Mnemonic == Mnemonic.Push)
                {
                    isWrite = true;
                    width = 8;
                }
                else if(instruction.Mnemonic == Mnemonic.Pop)
                {
                    isWrite = false;
                    width = 8;
                }
                else if(instruction.Mnemonic == Mnemonic.Call)
                {
                    // We only care for calls which read their displacement from somewhere
                    isWrite = false;
                }
                else if(instruction.Mnemonic is Mnemonic.Stosq or Mnemonic.Movsq)
                {
                    isWrite = true;
                    width = 8;
                }
                else if(instruction.Mnemonic is Mnemonic.Cmp or Mnemonic.Test)
                {
                    isWrite = false;
                }
                else if(instruction.Mnemonic is Mnemonic.Mul or Mnemonic.Div)
                {
                    isWrite = false;
                }
            }

            _assembler.DebugMarkMemtraceIgnoreSectionBegin();

            // If the base address or index registers are modified by the instruction, replace them by toy registers
            if(instructionData.WriteRegisters.Contains(memoryOperandBaseRegister))
            {
                var baseRegisterToy = registerAllocator.AllocateToyRegister();
                _assembler.mov(baseRegisterToy.Reg64, new AssemblerRegister64(memoryOperandBaseRegister));
                memoryOperandBaseRegister = baseRegisterToy.Reg64;
            }

            if(instructionData.WriteRegisters.Contains(memoryOperandIndexRegister))
            {
                var indexRegisterToy = registerAllocator.AllocateToyRegister();
                _assembler.mov(indexRegisterToy.Reg64, new AssemblerRegister64(memoryOperandIndexRegister));
                memoryOperandIndexRegister = indexRegisterToy.Reg64;
            }

            // Compute memory address
            AssemblerMemoryOperand memoryOperand;
            if(memoryOperandBaseRegister == Register.RIP)
            {
                // rip + disp32
                memoryOperand = __[ripLabel];
                memoryOperand = __[memoryOperand + (memoryOperandDisplacement - memoryOperand.Displacement)];
            }
            else if(memoryOperandBaseRegister != Register.None)
            {
                var baseRegister = new AssemblerRegister64(memoryOperandBaseRegister);

                if(memoryOperandIndexRegister != Register.None)
                {
                    // base + index * scale + disp32
                    var indexRegister = new AssemblerRegister64(memoryOperandIndexRegister);

                    memoryOperand = baseRegister + indexRegister * memoryOperandIndexScale + memoryOperandDisplacement;
                }
                else
                {
                    // base + disp32
                    memoryOperand = __[baseRegister + memoryOperandDisplacement];
                }
            }
            else if(memoryOperandIndexRegister != Register.None)
            {
                // index * scale + disp32
                var indexRegister = new AssemblerRegister64(memoryOperandIndexRegister);

                memoryOperand = indexRegister * memoryOperandIndexScale + memoryOperandDisplacement;
            }
            else
            {
                // const
                memoryOperand = __[memoryOperandDisplacement];
            }

            _assembler.DebugMarkMemtraceSectionEnd();

            // Generic memory operand factory for more readable access
            // ReSharper disable once InconsistentNaming
            var __width_ptr = GenericMemoryOperandFactory.GetVariableWidthMemoryOperandFactory(width);

            // Handle reads and writes separately
            if(isWrite)
            {
                // We always need a toy register for holding the mask    

                // Handle different operation classes
                if(instruction.Mnemonic is Mnemonic.Add or Mnemonic.Sub or Mnemonic.And or Mnemonic.Or or Mnemonic.Xor)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    using var dataToy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(dataToy, __width_ptr[memoryOperand]);
                    _assembler.mov(maskToy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(maskToy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(dataToy, maskToy);

                    // Run actual operation
                    if(registerOperands.Count == 0)
                        ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, dataToy, null, immediateOperand);
                    else
                        ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, dataToy, new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width }, immediateOperand);

                    // Ensure that resulting status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.WriteFlags);

                    if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites && width == 1)
                    {
                        using var mergeToy = registerAllocator.AllocateToyRegister();

                        var wideMemoryOperand = memoryOperand - 3;

                        // Read old data
                        _assembler.mov(mergeToy.Reg64, __qword_ptr[wideMemoryOperand + MaskUtils.MaskBufferOffset]);
                        _assembler.and(mergeToy.Reg64, __qword_ptr[wideMemoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.xor(mergeToy.Reg64, __qword_ptr[wideMemoryOperand]);

                        // Merge new data
                        _assembler.mov(maskToy.Reg64, 0xffffffff00ffffff);
                        _assembler.and(mergeToy.Reg64, maskToy.Reg64);
                        _assembler.shl(dataToy.Reg32, 24);
                        _assembler.or(mergeToy.Reg64, dataToy.Reg64);

                        // Update mask
                        UpdateMask(wideMemoryOperand, maskToy, 8, false);

                        // Encode with new mask and store
                        _assembler.xor(mergeToy.Reg64, maskToy.Reg64);
                        _assembler.mov(__qword_ptr[wideMemoryOperand], mergeToy.Reg64);
                    }
                    else
                    {
                        // Update mask
                        UpdateMask(memoryOperand, maskToy, width, instructionData.AccessesOnlySecretBlocks);

                        // Encode with new mask and store
                        _assembler.xor(dataToy, maskToy);
                        _assembler.mov(__width_ptr[memoryOperand], dataToy);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic == Mnemonic.Xadd)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // xadd [mem], reg
                    // For this proof-of-concept, we ignore the lock prefix

                    using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    using var dataToy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    var regOperand = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Read stored value and decode it
                    _assembler.mov(dataToy, __width_ptr[memoryOperand]);
                    _assembler.mov(maskToy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(maskToy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(dataToy, maskToy);

                    // Run actual operation
                    if(width == 8)
                        _assembler.xadd(dataToy.Reg64, regOperand.Reg64);
                    else if(width == 4)
                        _assembler.xadd(dataToy.Reg32, regOperand.Reg32);
                    else if(width == 2)
                        _assembler.xadd(dataToy.Reg16, regOperand.Reg16);
                    else if(width == 1)
                        _assembler.xadd(dataToy.Reg8, regOperand.Reg8);

                    // Ensure that resulting status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.WriteFlags);

                    if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites && width == 1)
                    {
                        Console.WriteLine($"  FIXME: Need small write instrumentation for {instructionData.ImageOffset:x}  '{instruction}'");
                    }
                    else
                    {
                        // Update mask
                        UpdateMask(memoryOperand, maskToy, width, instructionData.AccessesOnlySecretBlocks);

                        // Encode with new mask and store
                        _assembler.xor(dataToy, maskToy);
                        _assembler.mov(__width_ptr[memoryOperand], dataToy);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic is Mnemonic.Shl or Mnemonic.Shr or Mnemonic.Sal or Mnemonic.Sar)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    using var dataToy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(dataToy, __width_ptr[memoryOperand]);
                    _assembler.mov(maskToy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(maskToy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(dataToy, maskToy);

                    // Run actual operation
                    ReproduceShiftOperation(instruction.Mnemonic, width, dataToy, immediateOperand);

                    // Ensure that resulting status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.WriteFlags);

                    if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites && width == 1)
                    {
                        Console.WriteLine($"  FIXME: Need small write instrumentation for {instructionData.ImageOffset:x}  '{instruction}'");
                    }
                    else
                    {
                        // Update mask
                        UpdateMask(memoryOperand, maskToy, width, instructionData.AccessesOnlySecretBlocks);

                        // Encode with new mask and store
                        _assembler.xor(dataToy, maskToy);
                        _assembler.mov(__width_ptr[memoryOperand], dataToy);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic is Mnemonic.Neg)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    using var dataToy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(dataToy, __width_ptr[memoryOperand]);
                    _assembler.mov(maskToy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(maskToy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(dataToy, maskToy);

                    // Run actual operation
                    ReproduceUnaryArithmeticOperation(instruction.Mnemonic, width, dataToy);

                    // Ensure that resulting status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.WriteFlags);

                    if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites && width == 1)
                    {
                        Console.WriteLine($"  FIXME: Need small write instrumentation for {instructionData.ImageOffset:x}  '{instruction}'");
                    }
                    else
                    {
                        // Update mask
                        UpdateMask(memoryOperand, maskToy, width, instructionData.AccessesOnlySecretBlocks);

                        // Encode with new mask and store
                        _assembler.xor(dataToy, maskToy);
                        _assembler.mov(__width_ptr[memoryOperand], dataToy);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(_setccMnemonics.Contains(instruction.Mnemonic))
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    using var dataToy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Run actual operation
                    // We do this before everything else, when flags are still unmodified
                    _setccDescriptors[instruction.Mnemonic].OpRL8(dataToy.Reg8);

                    if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites && width == 1)
                    {
                        Console.WriteLine($"  FIXME: Need small write instrumentation for {instructionData.ImageOffset:x}  '{instruction}'");
                    }
                    else
                    {
                        // Update mask
                        if(!MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.mov(maskToy.Reg8, __byte_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        UpdateMask(memoryOperand, maskToy, width, instructionData.AccessesOnlySecretBlocks);

                        // Encode with new mask and store
                        _assembler.xor(dataToy.Reg8, maskToy.Reg8);
                        _assembler.mov(__byte_ptr[memoryOperand], dataToy.Reg8);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic == Mnemonic.Mov)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    if(MaskUtils.UseSecrecyBuffer && MaskUtils.AvoidSmallWrites && width == 1)
                    {
                        using var toy1 = registerAllocator.AllocateToyRegister();
                        using var mergeToy = registerAllocator.AllocateToyRegister();

                        var wideMemoryOperand = memoryOperand - 3;

                        // Read old data
                        _assembler.mov(mergeToy.Reg64, __qword_ptr[wideMemoryOperand + MaskUtils.MaskBufferOffset]);
                        _assembler.and(mergeToy.Reg64, __qword_ptr[wideMemoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.xor(mergeToy.Reg64, __qword_ptr[wideMemoryOperand]);

                        // Merge new data
                        _assembler.mov(toy1.Reg64, 0xffffffff00ffffff);
                        _assembler.and(mergeToy.Reg64, toy1.Reg64);

                        if(registerOperands.Count == 0)
                            _assembler.mov(toy1.Reg32, (uint)(immediateOperand!.Value << 24));
                        else
                        {
                            var regOperand = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };
                            _assembler.mov(toy1.Reg8, regOperand.Reg8);
                            _assembler.shl(toy1.Reg32, 24);
                        }

                        _assembler.or(mergeToy.Reg64, toy1.Reg64);

                        // Update mask
                        UpdateMask(wideMemoryOperand, toy1, 8, false);

                        // Encode with new mask and store
                        _assembler.xor(mergeToy.Reg64, toy1.Reg64);
                        _assembler.mov(__qword_ptr[wideMemoryOperand], mergeToy.Reg64);
                    }
                    else
                    {
                        using var toy1 = registerAllocator.AllocateToyRegister(preferredWidth: width);

                        // Update mask
                        if(!MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.mov(toy1, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        UpdateMask(memoryOperand, toy1, width, instructionData.AccessesOnlySecretBlocks);

                        // Load new value into toy register
                        if(registerOperands.Count == 0)
                        {
                            // No need to XOR when writing 0
                            if(immediateOperand!.Value != 0)
                            {
                                // There is no XOR with 64-bit immediate
                                if(width == 8 && immediateOperand.Value > int.MaxValue)
                                {
                                    using var toy2 = registerAllocator.AllocateToyRegister(preferredWidth: width);
                                    _assembler.mov(toy2, immediateOperand!.Value);
                                    _assembler.xor(toy1, toy2);
                                }
                                else
                                    _assembler.xor(toy1, immediateOperand!.Value);
                            }
                        }
                        else
                        {
                            var regOperand = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };
                            _assembler.xor(toy1, regOperand);
                        }

                        // Encode with new mask and store
                        _assembler.mov(__width_ptr[memoryOperand], toy1);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic is Mnemonic.Movdqa or Mnemonic.Movdqu or Mnemonic.Movaps or Mnemonic.Movapd or Mnemonic.Movups or Mnemonic.Movupd
                        or Mnemonic.Vmovdqa or Mnemonic.Vmovdqu)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    var vectorToy = registerAllocator.AllocateToyVectorRegister(preferredWidth: width);

                    // Generate and store new mask
                    _assembler.DebugMarkSkippableSectionBegin();
                    if(MaskUtils.UseSecrecyBuffer)
                    {
                        MaskUtils.GenerateMask(_assembler, vectorToy, registerAllocator)?.Free(); // Discard potentially allocated small mask toy register

                        // Store mask, and apply secrecy value, if necessary
                        if(width == 16)
                        {
                            _assembler.vmovdqu(__xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset], vectorToy.RegXMM);

                            if(!instructionData.AccessesOnlySecretBlocks)
                                _assembler.vpand(vectorToy.RegXMM, vectorToy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        }
                        else if(width == 32)
                        {
                            _assembler.vmovdqu(__ymmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset], vectorToy.RegYMM);

                            if(!instructionData.AccessesOnlySecretBlocks)
                                _assembler.vpand(vectorToy.RegYMM, vectorToy.RegYMM, __ymmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        }
                    }
                    else
                    {
                        Label skipMaskUpdateLabel = _assembler.CreateLabel();
                        if(!instructionData.AccessesOnlySecretBlocks)
                        {
                            // Automatic freeing of the toy register does not generate new instructions, so using "Dispose" is safe
                            using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                            // If the mask check is negative, we need to be sure that the mask vector register is zero
                            _assembler.vpxor(vectorToy, vectorToy, vectorToy);

                            _assembler.mov(maskToy.Reg64, __qword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                            _assembler.test(maskToy.Reg64, maskToy.Reg64);
                            _assembler.je(skipMaskUpdateLabel);
                        }

                        MaskUtils.GenerateMask(_assembler, vectorToy, registerAllocator)?.Free(); // Discard potentially allocated small mask toy register

                        if(!instructionData.AccessesOnlySecretBlocks)
                            _assembler.Label(ref skipMaskUpdateLabel);

                        // Store mask
                        if(width == 16)
                            _assembler.vmovdqu(__xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset], vectorToy.RegXMM);
                        else if(width == 32)
                            _assembler.vmovdqu(__ymmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset], vectorToy.RegYMM);
                    }

                    _assembler.DebugMarkSkippableSectionEnd();

                    // Handle different operand sizes
                    if(width == 16)
                    {
                        var srcRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);

                        // Encode with new mask and store
                        _assembler.vpxor(vectorToy.RegXMM, vectorToy.RegXMM, srcRegister.RegXMM);
                        _assembler.vmovdqu(__xmmword_ptr[memoryOperand], vectorToy.RegXMM);
                    }
                    else if(width == 32)
                    {
                        var srcRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);

                        // Encode with new mask and store
                        _assembler.vpxor(vectorToy.RegYMM, vectorToy.RegYMM, srcRegister.RegYMM);
                        _assembler.vmovdqu(__ymmword_ptr[memoryOperand], vectorToy.RegYMM);
                    }
                    else
                        throw new NotSupportedException("Unsupported vector size.");

                    registerAllocator.FreeToyVectorRegister(vectorToy);

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic is Mnemonic.Movd or Mnemonic.Movq)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    var srcRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);

                    using var maskToy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    using var dataToy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Update mask
                    if(!MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.mov(maskToy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    UpdateMask(memoryOperand, maskToy, width, instructionData.AccessesOnlySecretBlocks);

                    // Load new value into toy register
                    if(width == 8)
                        _assembler.movq(dataToy.Reg64, srcRegister.RegXMM);
                    else if(width == 4)
                        _assembler.movd(dataToy.Reg32, srcRegister.RegXMM);

                    // Encode with new mask and store
                    _assembler.xor(dataToy, maskToy);
                    _assembler.mov(__width_ptr[memoryOperand], dataToy);

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.Mnemonic == Mnemonic.Push)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // We only support 64-bit push

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy1 = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                    // Update mask
                    if(!MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.mov(toy1, __qword_ptr[rsp - 8 + MaskUtils.MaskBufferOffset]);
                    UpdateMask(rsp - 8, toy1, 8, instructionData.AccessesOnlySecretBlocks);

                    if(registerOperands.Count > 0)
                    {
                        // push r64

                        // Encode new value with mask
                        _assembler.xor(toy1.Reg64, new AssemblerRegister64(registerOperands[0].register));
                    }
                    else if(immediateOperand != null)
                    {
                        // push imm

                        // Load new value into toy register and encode with mask
                        if(immediateOperand < uint.MaxValue)
                            _assembler.xor(toy1.Reg64, unchecked((int)immediateOperand.Value));
                        else
                        {
                            using var toy2 = registerAllocator.AllocateToyRegister(preferredWidth: 8);
                            _assembler.mov(toy2.Reg64, immediateOperand.Value);
                            _assembler.xor(toy1.Reg64, toy2.Reg64);
                        }
                    }
                    else
                    {
                        // push m64

                        // Read stored value and decode+encode it
                        _assembler.xor(toy1.Reg64, __qword_ptr[memoryOperand]);
                        _assembler.xor(toy1.Reg64, __qword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    }

                    // Store new value
                    _assembler.push(toy1.Reg64);

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else if(instruction.HasRepPrefix && instruction.Mnemonic == Mnemonic.Stosq)
                {
                    _assembler.DebugMarkMemtraceIgnoreSectionBegin();

                    var storeLoopLabel = _assembler.CreateLabel();
                    var storeSkipMaskCheckLabel = _assembler.CreateLabel();
                    var storeEndLabel = _assembler.CreateLabel();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy1 = registerAllocator.AllocateToyRegister(preferredWidth: 8);
                    using var toy2 = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                    _assembler.DebugMarkMemtraceSectionEnd();

                    if(instructionData.AccessesOnlySecretBlocks && !AssemblerExtensions.DebugInsertMarkersForMemtraceEvaluation)
                    {
                        // Simply fill both mask buffer and data buffer with the same mask/masked data

                        // Save loop counter
                        _assembler.mov(toy2.Reg64, rcx); // Loop counter

                        // Create mask
                        MaskUtils.GenerateMask(_assembler, toy1.Reg64);

                        // Write masked data
                        _assembler.xor(rax, toy1.Reg64); // Mask data
                        _assembler.rep.stosq();

                        // Write mask
                        _assembler.DebugMarkSkippableSectionBegin();
                        {
                            _assembler.mov(rcx, toy2.Reg64); // Loop counter
                            _assembler.mov(toy2.Reg64, rax); // Masked data
                            _assembler.mov(rax, toy1.Reg64); // Mask
                            _assembler.lea(toy1.Reg64, rcx * 8);
                            _assembler.sub(rdi, toy1.Reg64);
                            _assembler.add(rdi, MaskUtils.MaskBufferOffset);
                            _assembler.rep.stosq();
                        }
                        _assembler.DebugMarkSkippableSectionEnd();

                        // Restore data
                        _assembler.xor(rax, toy2.Reg64);
                        _assembler.sub(rdi, MaskUtils.MaskBufferOffset);
                    }
                    else
                    {
                        // We can't be sure that all data is treated the same, so we have to check the mask/apply the secrecy value on each iteration.
                        // However, we can safely use the same mask for all.
                        // TODO rdi needs to contain the final address

                        // Check whether loop count is 0
                        _assembler.test(rcx, rcx);
                        _assembler.je(storeEndLabel);

                        // Create mask
                        MaskUtils.GenerateMask(_assembler, toy1.Reg64);

                        // Loop
                        _assembler.Label(ref storeLoopLabel);

                        _assembler.DebugMarkMemtraceSequenceSectionBegin();

                        if(MaskUtils.UseSecrecyBuffer)
                        {
                            // Store new mask
                            MaskUtils.StoreMask(_assembler, __[rdi + rcx * 8 - 8], toy1.Reg64);

                            // Apply secrecy value to new mask
                            _assembler.mov(toy2.Reg64, toy1.Reg64);
                            _assembler.and(toy2.Reg64, __qword_ptr[rdi + rcx * 8 - 8 + MaskUtils.SecrecyBufferOffset]);
                        }
                        else
                        {
                            // Read and check old mask
                            _assembler.mov(toy2.Reg64, __qword_ptr[rdi + rcx * 8 - 8 + MaskUtils.MaskBufferOffset]);
                            _assembler.test(toy2.Reg64, toy2.Reg64);
                            _assembler.mov(toy2.Reg32, 0); // can't do XOR here, as we would override status flags
                            _assembler.je(storeSkipMaskCheckLabel);

                            // Store new mask and prepare data encoding
                            MaskUtils.StoreMask(_assembler, __[rdi + rcx * 8 - 8], toy1.Reg64);
                            _assembler.mov(toy2.Reg64, toy1.Reg64);

                            _assembler.Label(ref storeSkipMaskCheckLabel);
                        }

                        // Store data
                        _assembler.xor(toy2.Reg64, rax);
                        _assembler.mov(__qword_ptr[rdi + rcx * 8 - 8], toy2.Reg64);

                        _assembler.DebugMarkMemtraceSectionEnd();

                        // Next iteration?
                        _assembler.dec(rcx);
                        _assembler.jne(storeLoopLabel);

                        _assembler.Label(ref storeEndLabel);
                        pendingLabel = true;
                    }
                }
                else if(instruction.HasRepPrefix && instruction.Mnemonic == Mnemonic.Movsq)
                {
                    var storeLoopLabel = _assembler.CreateLabel();
                    var storeSkipMaskCheckLabel = _assembler.CreateLabel();
                    var storeEndLabel = _assembler.CreateLabel();

                    _assembler.DebugMarkMemtraceIgnoreSectionBegin();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy1 = registerAllocator.AllocateToyRegister(preferredWidth: 8);
                    using var toy2 = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                    _assembler.DebugMarkMemtraceSectionEnd();

                    // Check whether loop count is 0
                    _assembler.test(rcx, rcx);
                    _assembler.je(storeEndLabel);

                    // Create mask
                    // We can't be sure that all data is treated the same, so we have to check the mask/apply the secrecy value on each iteration.
                    // However, we can safely use the same mask for all.
                    MaskUtils.GenerateMask(_assembler, toy1.Reg64);

                    // Loop
                    _assembler.Label(ref storeLoopLabel);

                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    if(MaskUtils.UseSecrecyBuffer)
                    {
                        using var toy3 = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                        // Store new mask 
                        MaskUtils.StoreMask(_assembler, __[rdi + rcx * 8 - 8], toy1.Reg64);

                        // Read old mask, apply secrecy value and decode data
                        _assembler.mov(toy2.Reg64, __qword_ptr[rsi + rcx * 8 - 8 + MaskUtils.MaskBufferOffset]);
                        _assembler.and(toy2.Reg64, __qword_ptr[rsi + rcx * 8 - 8 + MaskUtils.SecrecyBufferOffset]);
                        _assembler.xor(toy2.Reg64, __qword_ptr[rsi + rcx * 8 - 8]);

                        // Read new secrecy value and transform mask
                        _assembler.mov(toy3.Reg64, __qword_ptr[rdi + rcx * 8 - 8 + MaskUtils.SecrecyBufferOffset]);
                        _assembler.and(toy3.Reg64, toy1.Reg64);

                        // Encode data with new transformed mask
                        _assembler.xor(toy2.Reg64, toy3.Reg64);
                        _assembler.mov(__qword_ptr[rdi + rcx * 8 - 8], toy2.Reg64);
                    }
                    else
                    {
                        // We always decode the old data with its mask. For encoding, we check whether the mask buffer is zero
                        _assembler.mov(toy2.Reg64, __qword_ptr[rdi + rcx * 8 - 8 + MaskUtils.MaskBufferOffset]);
                        _assembler.test(toy2.Reg64, toy2.Reg64);
                        _assembler.je(storeSkipMaskCheckLabel);

                        // Store new mask 
                        MaskUtils.StoreMask(_assembler, __[rdi + rcx * 8 - 8], toy1.Reg64);

                        // Prepare data encoding
                        _assembler.mov(toy2.Reg64, toy1.Reg64);

                        // Decode with old mask & encode with new mask, then store
                        // toy2 <- newMask ^ oldMask
                        // toy2 <- newMask ^ oldMask ^ oldData == newMask ^ oldMask ^ (oldMask ^ data)
                        _assembler.Label(ref storeSkipMaskCheckLabel);
                        _assembler.xor(toy2.Reg64, __qword_ptr[rsi + rcx * 8 - 8 + MaskUtils.MaskBufferOffset]);
                        _assembler.xor(toy2.Reg64, __qword_ptr[rsi + rcx * 8 - 8]);
                        _assembler.mov(__qword_ptr[rdi + rcx * 8 - 8], toy2.Reg64);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();

                    // Next iteration?
                    _assembler.dec(rcx);
                    _assembler.jne(storeLoopLabel);

                    _assembler.Label(ref storeEndLabel);
                    pendingLabel = true;
                }
                else if(!instruction.HasRepPrefix && instruction.Mnemonic == Mnemonic.Movsq)
                {
                    _assembler.DebugMarkMemtraceSequenceSectionBegin();

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy1 = registerAllocator.AllocateToyRegister(preferredWidth: 8);
                    using var toy2 = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                    // Create mask
                    MaskUtils.GenerateMask(_assembler, toy1.Reg64);

                    if(MaskUtils.UseSecrecyBuffer)
                    {
                        using var toy3 = registerAllocator.AllocateToyRegister(preferredWidth: 8);

                        // Store new mask
                        MaskUtils.StoreMask(_assembler, __[rdi], toy1.Reg64);

                        // Read old mask, apply secrecy value and decode data
                        _assembler.mov(toy2.Reg64, __qword_ptr[rsi + MaskUtils.MaskBufferOffset]);
                        _assembler.and(toy2.Reg64, __qword_ptr[rsi + MaskUtils.SecrecyBufferOffset]);
                        _assembler.xor(toy2.Reg64, __qword_ptr[rsi]);

                        // Read new secrecy value and transform mask
                        _assembler.mov(toy3.Reg64, __qword_ptr[rdi + MaskUtils.SecrecyBufferOffset]);
                        _assembler.and(toy3.Reg64, toy1.Reg64);

                        // Encode data with new transformed mask
                        _assembler.xor(toy2.Reg64, toy3.Reg64);
                        _assembler.mov(__qword_ptr[rdi], toy2.Reg64);
                    }
                    else
                    {
                        var storeSkipMaskCheckLabel = _assembler.CreateLabel();

                        // We always decode the old data with its mask. For encoding, we check whether the mask buffer is zero
                        _assembler.mov(toy2.Reg64, __qword_ptr[rdi + MaskUtils.MaskBufferOffset]);
                        _assembler.test(toy2.Reg64, toy2.Reg64);
                        _assembler.je(storeSkipMaskCheckLabel);

                        // Store new mask
                        MaskUtils.StoreMask(_assembler, __[rdi], toy1.Reg64);

                        // Prepare data encoding
                        _assembler.mov(toy2.Reg64, toy1.Reg64);

                        // Decode with old mask & encode with new mask, then store
                        // toy2 <- newMask ^ oldMask
                        // toy2 <- newMask ^ oldMask ^ oldData == newMask ^ oldMask ^ (oldMask ^ data)
                        _assembler.Label(ref storeSkipMaskCheckLabel);
                        _assembler.xor(toy2.Reg64, __qword_ptr[rsi + MaskUtils.MaskBufferOffset]);
                        _assembler.xor(toy2.Reg64, __qword_ptr[rsi]);
                        _assembler.mov(__qword_ptr[rdi], toy2.Reg64);
                    }

                    _assembler.DebugMarkMemtraceSectionEnd();
                }
                else
                {
                    Console.WriteLine($"  ERROR: Can not instrument write at #{instruction.IP:x}: {instruction} (not supported)");
                }
            }
            else
            {
                // READ

                // Handle different operation classes
                if(instruction.Mnemonic is Mnemonic.Add or Mnemonic.Sub or Mnemonic.And or Mnemonic.Or or Mnemonic.Xor)
                {
                    // Only reads, so the left operand is always a register. We thus don't have to care about
                    // non-commutativity of `sub`

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    var destRegister = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Run actual operation
                    ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, destRegister, toy, null);
                }
                else if(instruction.Mnemonic is Mnemonic.Adc or Mnemonic.Sbb)
                {
                    // Arithmetic that uses flag values

                    // Only reads, so the left operand is always a register. We thus don't have to care about
                    // non-commutativity of `sbb`

                    // We need to restore the status flags before the operation
                    registerAllocator.SaveFlags(instructionData.ReadFlags.Concat(instructionData.KeepFlags));

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    var destRegister = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Run actual operation
                    registerAllocator.RestoreFlags();
                    ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, destRegister, toy, null);
                }
                else if(instruction.Mnemonic is Mnemonic.Adcx or Mnemonic.Adox)
                {
                    // These operations rely on flags, so we need to preserve them
                    registerAllocator.SaveFlags(instructionData.ReadFlags.Concat(instructionData.KeepFlags));

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);
                    var destRegister = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    registerAllocator.RestoreFlags();

                    // Handle different operand sizes
                    if(width == 8)
                    {
                        if(instruction.Mnemonic == Mnemonic.Adcx)
                            _assembler.adcx(destRegister.Reg64, toy.Reg64);
                        else if(instruction.Mnemonic == Mnemonic.Adox)
                            _assembler.adox(destRegister.Reg64, toy.Reg64);
                    }
                    else if(width == 4)
                    {
                        if(instruction.Mnemonic == Mnemonic.Adcx)
                            _assembler.adcx(destRegister.Reg32, toy.Reg32);
                        else if(instruction.Mnemonic == Mnemonic.Adox)
                            _assembler.adox(destRegister.Reg32, toy.Reg32);
                    }
                }
                else if(instruction.Mnemonic is Mnemonic.Cmp)
                {
                    // This is mostly identical to the other arithmetic operators, except that we don't have
                    // a destination register and the memory operand may be the first or second operand.

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Run actual operation
                    if(instruction.GetOpKind(0) == OpKind.Memory)
                    {
                        if(immediateOperand != null)
                            ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, toy, null, immediateOperand); // cmp [mem], imm
                        else
                            ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, toy, new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width }, null); // cmp [mem], reg
                    }
                    else
                    {
                        ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width }, toy, null); // cmp reg, [mem]
                    }
                }
                else if(instruction.Mnemonic is Mnemonic.Test)
                {
                    // This is handled the same as cmp, except that the memory operand is always the first operand.

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Run actual operation
                    if(immediateOperand != null)
                        ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, toy, null, immediateOperand); // test [mem], imm
                    else
                        ReproduceBinaryArithmeticOperation(instruction.Mnemonic, width, toy, new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width }, null); // test [mem], reg
                }
                else if(instruction.Mnemonic == Mnemonic.Mul)
                {
                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Run actual operation
                    if(width == 8)
                        _assembler.mul(toy.Reg64);
                    else if(width == 4)
                        _assembler.mul(toy.Reg32);
                    else if(width == 2)
                        _assembler.mul(toy.Reg16);
                    else if(width == 1)
                        _assembler.mul(toy.Reg8);
                }
                else if(instruction.Mnemonic == Mnemonic.Imul)
                {
                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Run actual operation
                    var destRegister = new AssemblerRegister64(registerOperands[0].register);
                    if(width == 8)
                        _assembler.imul(destRegister, toy.Reg64);
                    else if(width == 4)
                        _assembler.imul(destRegister.GetSubRegister32(), toy.Reg32);
                    else if(width == 2)
                        _assembler.imul(destRegister.GetSubRegister16(), toy.Reg16);
                }
                else if(instruction.Mnemonic == Mnemonic.Mulx)
                {
                    // mulx regA, regB, [mem]

                    // This operation promises to preserve flags
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    var regOperandA = new AssemblerRegister64(registerOperands[0].register);
                    var regOperandB = new AssemblerRegister64(registerOperands[1].register);

                    // Run actual operation
                    if(width == 8)
                        _assembler.mulx(regOperandA, regOperandB, toy.Reg64);
                    else if(width == 4)
                        _assembler.mulx(regOperandA.GetSubRegister32(), regOperandB.GetSubRegister32(), toy.Reg32);
                }
                else if(instruction.Mnemonic == Mnemonic.Div)
                {
                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Handle different operand sizes
                    if(width == 8)
                        _assembler.div(toy.Reg64);
                    else if(width == 4)
                        _assembler.div(toy.Reg32);
                    else if(width == 2)
                        _assembler.div(toy.Reg16);
                    else if(width == 1)
                        _assembler.div(toy.Reg8);
                }
                else if(_vectorArithmeticMnemonics.Contains(instruction.Mnemonic))
                {
                    // Only reads, so the left operand is always a register. We thus don't have to care about
                    // non-commutativity of `sub`

                    var destRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);

                    // Handle different operand sizes
                    if(width == 16)
                    {
                        var toy = registerAllocator.AllocateToyVectorRegister();

                        // Read stored value and decode it
                        _assembler.vmovdqu(toy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.vpand(toy.RegXMM, toy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.vpxor(toy.RegXMM, toy.RegXMM, __xmmword_ptr[memoryOperand]);

                        // Run actual operation
                        ReproduceVectorArithmeticOperation(instruction.Mnemonic, width, destRegister, toy, null);
                    }
                    else
                        throw new NotSupportedException("Unsupported vector size.");
                }
                else if(instruction.Mnemonic == Mnemonic.Vpcmpeqb)
                {
                    // TODO generalize this, there are lots of similar instructions

                    var vectorToy = registerAllocator.AllocateToyVectorRegister();

                    var regOperandA = new GenericAssemblerVectorRegister(registerOperands[0].register);
                    var regOperandB = new GenericAssemblerVectorRegister(registerOperands[1].register);

                    // Handle different operand sizes
                    if(width == 16)
                    {
                        // Read stored value and decode it
                        _assembler.vmovdqu(vectorToy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.vpand(vectorToy.RegXMM, vectorToy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.vpxor(vectorToy.RegXMM, vectorToy.RegXMM, __xmmword_ptr[memoryOperand]);

                        // Run actual operation
                        _assembler.vpcmpeqb(regOperandA.RegXMM, regOperandB.RegXMM, vectorToy.RegXMM);
                    }
                    else if(width == 32)
                    {
                        // Read stored value and decode it
                        _assembler.vmovdqu(vectorToy.RegYMM, __ymmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.vpand(vectorToy.RegYMM, vectorToy.RegYMM, __ymmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.vpxor(vectorToy.RegYMM, vectorToy.RegYMM, __ymmword_ptr[memoryOperand]);

                        // Run actual operation
                        _assembler.vpcmpeqb(regOperandA.RegYMM, regOperandB.RegYMM, vectorToy.RegYMM);
                    }
                    else
                        throw new NotSupportedException("Unsupported vector size.");
                }
                else if(instruction.Mnemonic == Mnemonic.Mov)
                {
                    var destRegister = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    // Read stored value and decode it
                    _assembler.mov(destRegister, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(destRegister, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(destRegister, __width_ptr[memoryOperand]);
                }
                else if(instruction.Mnemonic is Mnemonic.Movdqa or Mnemonic.Movdqu or Mnemonic.Movaps or Mnemonic.Movapd or Mnemonic.Movups or Mnemonic.Movupd
                        or Mnemonic.Vmovdqa or Mnemonic.Vmovdqu)
                {
                    var destRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);

                    // Handle different operand sizes
                    if(width == 16)
                    {
                        // Read stored value and decode it
                        _assembler.vmovdqu(destRegister.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.vpand(destRegister.RegXMM, destRegister.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.vpxor(destRegister.RegXMM, destRegister.RegXMM, __xmmword_ptr[memoryOperand]);
                    }
                    else if(width == 32)
                    {
                        // Read stored value and decode it
                        _assembler.vmovdqu(destRegister.RegYMM, __ymmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                        if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                            _assembler.vpand(destRegister.RegYMM, destRegister.RegYMM, __ymmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                        _assembler.vpxor(destRegister.RegYMM, destRegister.RegYMM, __ymmword_ptr[memoryOperand]);
                    }
                    else
                        throw new NotSupportedException("Unsupported vector size.");
                }
                else if(instruction.Mnemonic is Mnemonic.Vinserti128)
                {
                    var destRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);
                    var srcRegister = new GenericAssemblerVectorRegister(registerOperands[1].register);
                    byte imm8 = (byte)immediateOperand.Value;

                    var toy = registerAllocator.AllocateToyVectorRegister();

                    // Read stored value and decode it
                    _assembler.vmovdqu(toy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.vpand(toy.RegXMM, toy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.vpxor(toy.RegXMM, toy.RegXMM, __xmmword_ptr[memoryOperand]);

                    // Do insert operation
                    _assembler.vinserti128(destRegister.RegYMM, srcRegister.RegYMM, toy.RegXMM, imm8);
                }
                else if(instruction.Mnemonic is Mnemonic.Movd or Mnemonic.Movq or Mnemonic.Vmovd or Mnemonic.Vmovq)
                {
                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    var destRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);
                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Move into vector register
                    if(width == 8)
                        _assembler.movq(destRegister.RegXMM, toy.Reg64);
                    else if(width == 4)
                        _assembler.movd(destRegister.RegXMM, toy.Reg32);
                }
                else if(instruction.Mnemonic is Mnemonic.Movhps)
                {
                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    var destRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);
                    using var toy = registerAllocator.AllocateToyRegister();

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Move into vector register
                    if(width == 8)
                        _assembler.pinsrq(destRegister.RegXMM, toy.Reg64, 1);
                    else
                        throw new NotSupportedException("Unsupported movhps size.");
                }
                else if(instruction.Mnemonic is Mnemonic.Shufps)
                {
                    var destRegister = new GenericAssemblerVectorRegister(registerOperands[0].register);

                    var toy = registerAllocator.AllocateToyVectorRegister();

                    // Read stored value and decode it
                    _assembler.movdqu(toy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.pand(toy.RegXMM, __xmmword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.pxor(toy.RegXMM, __xmmword_ptr[memoryOperand]);

                    // Execute shuffle operation
                    _assembler.shufps(destRegister.RegXMM, toy.RegXMM, (byte)immediateOperand);
                }
                else if(instruction.Mnemonic == Mnemonic.Movzx)
                {
                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value into toy register and subtract mask
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    int regOperandSize = registerOperands[0].size;
                    var regOperand = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Copy into destination register with zero extension
                    if(width == 2)
                    {
                        if(regOperandSize == 8)
                            _assembler.movzx(regOperand.Reg64, toy.Reg16);
                        else if(regOperandSize == 4)
                            _assembler.movzx(regOperand.Reg32, toy.Reg16);
                    }
                    else if(width == 1)
                    {
                        if(regOperandSize == 8)
                            _assembler.movzx(regOperand.Reg64, toy.Reg8);
                        else if(regOperandSize == 4)
                            _assembler.movzx(regOperand.Reg32, toy.Reg8);
                        else if(regOperandSize == 2)
                            _assembler.movzx(regOperand.Reg16, toy.Reg8);
                    }
                }
                else if(instruction.Mnemonic is Mnemonic.Movsx or Mnemonic.Movsxd)
                {
                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value into toy register and subtract mask
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    int regOperandSize = registerOperands[0].size;
                    var regOperand = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    // Copy into destination register with sign extension
                    if(width == 4)
                    {
                        if(regOperandSize == 8)
                            _assembler.movsxd(regOperand.Reg64, toy.Reg32);
                        else if(regOperandSize == 4)
                            _assembler.movsxd(regOperand.Reg32, toy.Reg32);
                    }
                    else if(width == 2)
                    {
                        if(regOperandSize == 8)
                            _assembler.movsx(regOperand.Reg64, toy.Reg16);
                        else if(regOperandSize == 4)
                            _assembler.movsx(regOperand.Reg32, toy.Reg16);
                        else if(regOperandSize == 2)
                            _assembler.movsxd(regOperand.Reg16, toy.Reg16);
                    }
                    else if(width == 1)
                    {
                        if(regOperandSize == 8)
                            _assembler.movsx(regOperand.Reg64, toy.Reg8);
                        else if(regOperandSize == 4)
                            _assembler.movsx(regOperand.Reg32, toy.Reg8);
                        else if(regOperandSize == 2)
                            _assembler.movsx(regOperand.Reg16, toy.Reg8);
                    }
                }
                else if(instruction.IsCmov())
                {
                    // cmovcc reg, [mem]

                    // Ensure that used status flags are preserved during unmasking
                    registerAllocator.SaveFlags(instructionData.ReadFlags.Concat(instructionData.KeepFlags));

                    var destRegister = new GenericAssemblerRegister(registerOperands[0].register) { PreferredWidth = width };

                    using var toy = registerAllocator.AllocateToyRegister(preferredWidth: width);

                    // Read stored value and decode it
                    _assembler.mov(toy, __width_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy, __width_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy, __width_ptr[memoryOperand]);

                    // Restore status flags for CMOV operation
                    registerAllocator.RestoreFlags();

                    // Run actual CMOV
                    ReproduceCmovOperation(instruction.Mnemonic, width, destRegister, toy);
                }
                else if(instruction.Mnemonic == Mnemonic.Pop)
                {
                    // We only support `pop r64`

                    var destRegister = new AssemblerRegister64(registerOperands[0].register);

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    // Read stored value and decode it
                    _assembler.mov(destRegister, __qword_ptr[rsp + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(destRegister, __qword_ptr[rsp + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(destRegister, __qword_ptr[rsp]);

                    // Increment stack pointer
                    _assembler.add(rsp, 8);
                }
                else if(instruction.Mnemonic == Mnemonic.Leave)
                {
                    // mov rsp, rbp
                    // pop rbp

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    // Restore stack pointer
                    _assembler.lea(rsp, __[rbp + 8]);

                    // Read stored RBP value and decode it
                    _assembler.mov(rbp, __qword_ptr[rsp - 8 + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(rbp, __qword_ptr[rsp - 8 + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(rbp, __qword_ptr[rsp - 8]);
                }
                else if(instruction.Mnemonic == Mnemonic.Call)
                {
                    // We only support `call m64`

                    // Ensure that previous status flags are preserved, if they are used
                    registerAllocator.SaveFlags(instructionData.KeepFlags);

                    // We can't do the usual toy register cleanup after a call, so we have to rely on
                    // there being a register available
                    var toy = registerAllocator.AllocateToyRegisterUnused();

                    // Read stored value and decode it
                    _assembler.mov(toy.Reg64, __qword_ptr[memoryOperand + MaskUtils.MaskBufferOffset]);
                    if(MaskUtils.UseSecrecyBuffer && !instructionData.AccessesOnlySecretBlocks)
                        _assembler.and(toy.Reg64, __qword_ptr[memoryOperand + MaskUtils.SecrecyBufferOffset]);
                    _assembler.xor(toy.Reg64, __qword_ptr[memoryOperand]);

                    // Early restore
                    registerAllocator.Restore();

                    // Call function
                    _assembler.call(toy.Reg64);

                    pendingLabel = false;
                }
                else
                {
                    Console.WriteLine($"  ERROR: Can not instrument read at #{instruction.IP:x}: {instruction} (not supported)");
                }
            }
        }
        else
        {
            // This instruction does not need to be instrumented, just insert it as-is
            // (path for stack frame handling)
            _assembler.AddInstruction(instruction);
        }

        // Restore toy registers and flags
        _assembler.DebugMarkMemtraceIgnoreSectionBegin();
        if(registerAllocator.Restore())
            pendingLabel = false;
        _assembler.DebugMarkMemtraceSectionEnd();

        // Is there still a label that does not point to an instruction?
        if(pendingLabel)
            _assembler.nop();

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

    /// <summary>
    /// Updates the mask at the given memory location.
    /// </summary>
    /// <param name="dataMemoryOperand">Data memory location.</param>
    /// <param name="maskToy">Toy register for mask generation, containing the old mask (only used when <see cref="MaskUtils.UseSecrecyBuffer"/> is false). The new mask will be left in this register, so it can be used directly.</param>
    /// <param name="width">Mask width.</param>
    /// <param name="skipPreviousMaskCheck">If true, the check for an existing zero-mask is omitted.</param>
    private void UpdateMask(AssemblerMemoryOperand dataMemoryOperand, GenericAssemblerRegister maskToy, int width, bool skipPreviousMaskCheck)
    {
        Label skipMaskUpdateLabel = _assembler.CreateLabel();
        if(!MaskUtils.UseSecrecyBuffer)
        {
            // Do not update mask if it is zero
            if(!skipPreviousMaskCheck)
            {
                if(width == 8)
                    _assembler.test(maskToy.Reg64, maskToy.Reg64);
                else if(width == 4)
                    _assembler.test(maskToy.Reg32, maskToy.Reg32);
                else if(width == 2)
                    _assembler.test(maskToy.Reg16, maskToy.Reg16);
                else if(width == 1)
                    _assembler.test(maskToy.Reg8, maskToy.Reg8);
                else
                    _assembler.test(maskToy.Reg64, maskToy.Reg64);

                _assembler.je(skipMaskUpdateLabel);
            }
        }

        switch(width)
        {
            case 1:
                MaskUtils.GenerateAndStoreMask(_assembler, dataMemoryOperand, maskToy.Reg8);
                break;
            case 2:
                MaskUtils.GenerateAndStoreMask(_assembler, dataMemoryOperand, maskToy.Reg16);
                break;
            case 4:
                MaskUtils.GenerateAndStoreMask(_assembler, dataMemoryOperand, maskToy.Reg32);
                break;
            case 8:
                MaskUtils.GenerateAndStoreMask(_assembler, dataMemoryOperand, maskToy.Reg64);
                break;

            default:
                throw new NotSupportedException($"Not supported width {width}");
        }

        if(!MaskUtils.UseSecrecyBuffer && !skipPreviousMaskCheck)
            _assembler.Label(ref skipMaskUpdateLabel);
    }

    private void ReproduceUnaryArithmeticOperation(Mnemonic mnemonic, int width, GenericAssemblerRegister register)
    {
        if(_unaryArithmeticDescriptors.TryGetValue(mnemonic, out var descriptor))
        {
            if(width == 8)
                descriptor.Op64R(register.Reg64);
            else if(width == 4)
                descriptor.Op32R(register.Reg32);
            else if(width == 2)
                descriptor.Op16R(register.Reg16);
            else if(width == 1)
                descriptor.Op8R(register.Reg8);
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    private void ReproduceBinaryArithmeticOperation(Mnemonic mnemonic, int width, GenericAssemblerRegister destRegister, GenericAssemblerRegister srcRegister, ulong? srcImmediate)
    {
        if(_binaryArithmeticDescriptors.TryGetValue(mnemonic, out var descriptor))
        {
            if(srcRegister == null)
            {
                if(srcImmediate == null)
                    throw new InvalidOperationException();

                if(width == 8)
                    descriptor.Op64RI(destRegister.Reg64, (int)srcImmediate.Value);
                else if(width == 4)
                    descriptor.Op32RI(destRegister.Reg32, (uint)srcImmediate.Value);
                else if(width == 2)
                    descriptor.Op16RI(destRegister.Reg16, (ushort)srcImmediate.Value);
                else if(width == 1)
                    descriptor.Op8RI(destRegister.Reg8, (byte)srcImmediate.Value);
            }
            else
            {
                if(width == 8)
                    descriptor.Op64RR(destRegister.Reg64, srcRegister.Reg64);
                else if(width == 4)
                    descriptor.Op32RR(destRegister.Reg32, srcRegister.Reg32);
                else if(width == 2)
                    descriptor.Op16RR(destRegister.Reg16, srcRegister.Reg16);
                else if(width == 1)
                    descriptor.Op8RR(destRegister.Reg8, srcRegister.Reg8);
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    private void ReproduceShiftOperation(Mnemonic mnemonic, int width, GenericAssemblerRegister destRegister, ulong? immediate)
    {
        if(_shiftDescriptors.TryGetValue(mnemonic, out var descriptor))
        {
            if(immediate != null)
            {
                if(width == 8)
                    descriptor.Op64RI(destRegister.Reg64, (byte)immediate.Value);
                else if(width == 4)
                    descriptor.Op32RI(destRegister.Reg32, (byte)immediate.Value);
                else if(width == 2)
                    descriptor.Op16RI(destRegister.Reg16, (byte)immediate.Value);
                else if(width == 1)
                    descriptor.Op8RI(destRegister.Reg8, (byte)immediate.Value);
            }
            else
            {
                AssemblerRegister8 cl = new AssemblerRegister8(Register.CL);

                if(width == 8)
                    descriptor.Op64RCL(destRegister.Reg64, cl);
                else if(width == 4)
                    descriptor.Op32RCL(destRegister.Reg32, cl);
                else if(width == 2)
                    descriptor.Op16RCL(destRegister.Reg16, cl);
                else if(width == 1)
                    descriptor.Op8RCL(destRegister.Reg8, cl);
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    private void ReproduceCmovOperation(Mnemonic mnemonic, int width, GenericAssemblerRegister destRegister, GenericAssemblerRegister srcRegister)
    {
        if(_cmovDescriptors.TryGetValue(mnemonic, out var descriptor))
        {
            if(width == 8)
                descriptor.Op64RR(destRegister.Reg64, srcRegister.Reg64);
            else if(width == 4)
                descriptor.Op32RR(destRegister.Reg32, srcRegister.Reg32);
            else if(width == 2)
                descriptor.Op16RR(destRegister.Reg16, srcRegister.Reg16);
        }
        else
        {
            throw new NotSupportedException();
        }
    }

    private void ReproduceVectorArithmeticOperation(Mnemonic mnemonic, int width, GenericAssemblerVectorRegister destRegister, GenericAssemblerVectorRegister srcRegister1, GenericAssemblerVectorRegister srcRegister2)
    {
        if(_vectorArithmeticDescriptors.TryGetValue(mnemonic, out var descriptor))
        {
            if(srcRegister2 == null)
            {
                descriptor.Op128RR
                (
                    destRegister.RegXMM,
                    srcRegister1.RegXMM
                );
            }
            else
            {
                if(width == 16)
                {
                    descriptor.Op128RRR
                    (
                        destRegister.RegXMM,
                        srcRegister1.RegXMM,
                        srcRegister2.RegXMM
                    );
                }
                else if(width == 32)
                {
                    descriptor.Op256RRR
                    (
                        destRegister.RegYMM,
                        srcRegister1.RegYMM,
                        srcRegister2.RegYMM
                    );
                }
            }
        }
        else
        {
            throw new NotSupportedException();
        }
    }
}