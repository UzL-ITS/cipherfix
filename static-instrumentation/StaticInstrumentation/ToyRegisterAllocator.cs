using System;
using System.Collections.Generic;
using System.Linq;
using Iced.Intel;
using static Iced.Intel.AssemblerRegisters;

namespace StaticInstrumentation;

public class ToyRegisterAllocator
{
    private readonly Assembler _assembler;
    private readonly AnalysisResult.InstructionData _instructionData;

    /// <summary>
    /// General purpose registers that aren't read or written by the instruction.
    /// </summary>
    private  List<Register> _instructionNoReadWriteGpRegisters;

    /// <summary>
    /// General purpose registers that aren't read or written and also don't need to be kept by the instruction.
    /// I.e., cluttering these registers is fine.
    /// </summary>
    private  List<Register> _instructionNoReadWriteKeepGpRegisters;

    /// <summary>
    /// General purpose registers which have been saved before using them as toy registers.
    /// </summary>
    private readonly List<Register> _savedGpRegisters = new();

    /// <summary>
    /// Toy general purpose registers that were used and then marked as available (but were not yet restored).
    /// This ensures that toy registers are re-used efficiently, avoiding performance penalties from unnecessary saving/restoring.
    /// </summary>
    private readonly HashSet<Register> _freedGpRegisters = new();

    /// <summary>
    /// Toy vector register for saving the original values of toy general purpose registers.
    /// </summary>
    private AssemblerRegisterXMM? _storageVectorRegister = null;

    /// <summary>
    /// Toy register containing the saved status flags.
    /// </summary>
    private ToyRegister _flagsRegister = null;

    /// <summary>
    /// Tracks whether flags need to be restored.
    /// </summary>
    private bool _needsFlagRestore = false;

    /// <summary>
    /// Vector registers that aren't read or written by the instruction.
    /// </summary>
    private  List<Register> _instructionNoReadWriteVectorRegisters;

    /// <summary>
    /// Vector registers that aren't read or written and also don't need to be kept by the instruction.
    /// I.e., cluttering these registers is fine.
    /// </summary>
    private  List<Register> _instructionNoReadWriteKeepVectorRegisters;

    /// <summary>
    /// Vector registers which have been saved before using them as toy registers.
    /// </summary>
    private readonly List<Register> _savedVectorRegisters = new();

    /// <summary>
    /// Toy vector registers that were used and then marked as available (but were not yet restored).
    /// This ensures that toy registers are re-used efficiently, avoiding performance penalties from unnecessary saving/restoring.
    /// </summary>
    private readonly HashSet<Register> _freedVectorRegisters = new();

    public ToyRegisterAllocator(Assembler assembler, AnalysisResult.InstructionData instructionData)
    {
        _assembler = assembler ?? throw new ArgumentNullException(nameof(assembler));
        _instructionData = instructionData ?? throw new ArgumentNullException(nameof(instructionData));

        // Initialize register lists
        InitRegisterLists();
    }

    private void InitRegisterLists()
    {
        _instructionNoReadWriteGpRegisters = GeneralPurposeRegisters
            .Except(_instructionData.ReadRegisters)
            .Except(_instructionData.WriteRegisters)
            .ToList();
        _instructionNoReadWriteKeepGpRegisters = _instructionNoReadWriteGpRegisters
            .Except(_instructionData.KeepRegisters)
            .ToList();

        _instructionNoReadWriteVectorRegisters = _vectorRegisters
            .Except(_instructionData.ReadRegisters)
            .Except(_instructionData.WriteRegisters)
            .Select(r => RegisterExtensions.Vector256Lookup[r].Value)
            .ToList();
        _instructionNoReadWriteKeepVectorRegisters = _vectorRegisters
            .Except(_instructionData.ReadRegisters)
            .Except(_instructionData.WriteRegisters)
            .Except(_instructionData.KeepRegisters)
            .Select(r => RegisterExtensions.Vector256Lookup[r].Value)
            .ToList();
    }

    public ToyRegister AllocateToyRegisterUnused(IEnumerable<Register> excludedRegisters = null, int preferredWidth = 0)
    {
        if(_instructionNoReadWriteKeepGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).Any())
        {
            var register = _instructionNoReadWriteKeepGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).First();

            // Do not allocate it again in the future
            _instructionNoReadWriteGpRegisters.Remove(register);
            _instructionNoReadWriteKeepGpRegisters.Remove(register);

            // The register does not need to be saved
            return new ToyRegister(register, this) { PreferredWidth = preferredWidth, Freed = false };
        }

        return null;
    }

    public ToyRegister AllocateToyRegister(IEnumerable<Register> excludedRegisters = null, int preferredWidth = 0)
    {
        // Short path for toy registers which were already used
        if(_freedGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).Any())
        {
            var freedRegister = _freedGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).First();
            _freedGpRegisters.Remove(freedRegister);
            return new ToyRegister(freedRegister, this) { PreferredWidth = preferredWidth, Freed = false };
        }

        // Look for registers that don't need to be saved
        var toyRegister = AllocateToyRegisterUnused(excludedRegisters, preferredWidth);
        if(toyRegister != null)
            return toyRegister;

        // We need to save a register
        var register = _instructionNoReadWriteGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).First();
        _instructionNoReadWriteGpRegisters.Remove(register);

        toyRegister = new ToyRegister(register, this) { PreferredWidth = preferredWidth, Freed = false };

        // We need to save this register. Just drop it into a vector register
        if(_storageVectorRegister == null)
        {
            // There is no storage vector register yet, so allocate one
            // Note that it's cheaper to once do the expensive work for saving/restoring a big vector register
            // than doing this for each general purpose register. We assume that most instrumentation will
            // use more than one general purpose toy register.

            _storageVectorRegister = AllocateToyVectorRegister().RegXMM;
        }

        // Save register
        if(_savedGpRegisters.Count == 0)
            _assembler.vmovq(_storageVectorRegister.Value, toyRegister.Reg64);
        else if(_savedGpRegisters.Count == 1)
            _assembler.vpinsrq(_storageVectorRegister.Value, _storageVectorRegister.Value, toyRegister.Reg64, 1);
        else
            throw new InvalidOperationException("Currently only two general purpose toy registers are supported.");

        _savedGpRegisters.Add(register);
        return toyRegister;
    }

    public void FreeToyRegister(ToyRegister toy)
    {
        if(toy.Freed)
            return;
        toy.Freed = true;

        // We do not reuse the "toy" object directly, as its IDisposable implementation can call this function
        _freedGpRegisters.Add(toy.Reg64);
    }

    public GenericAssemblerVectorRegister AllocateToyVectorRegister()
    {
        // Short path for toy registers which were already used
        if(_freedVectorRegisters.Count > 0)
        {
            var register = _freedVectorRegisters.First();
            _freedVectorRegisters.Remove(register);
            return new GenericAssemblerVectorRegister(register);
        }

        // Find usable register
        if(_instructionNoReadWriteKeepVectorRegisters.Count > 0)
        {
            var register = _instructionNoReadWriteKeepVectorRegisters[0];

            // Do not allocate it again in the future
            _instructionNoReadWriteVectorRegisters.Remove(register);
            _instructionNoReadWriteKeepVectorRegisters.RemoveAt(0);

            // The register does not need to be saved
            return new GenericAssemblerVectorRegister(register);
        }
        else
        {
            var register = _instructionNoReadWriteVectorRegisters[0];
            _instructionNoReadWriteVectorRegisters.RemoveAt(0);

            var asmRegister = new GenericAssemblerVectorRegister(register);

            // Save register
            // For now we use the stack as a thread-safe way for storing toy registers. This works as long as the stack pointer is
            // not modified, i.e., we don't use this method for instrumenting push/pop and call.
            // We subtract 128 to ensure that we don't write into the red zone.
            // TODO Ensure in push/pop instrumentation that this method is indeed safe
            // TODO Mask register value if necessary
            Console.WriteLine("WARNING: Saving vector register"); // Remove this after addressing the above TODOs
            int registerIndex = register.GetNumber();
            _assembler.vmovdqu(__ymmword_ptr[rsp - 128 - 32 * (registerIndex + 1)], asmRegister.RegYMM);

            _savedVectorRegisters.Add(register);
            return asmRegister;
        }
    }

    public void FreeToyVectorRegister(GenericAssemblerVectorRegister register)
    {
        _freedVectorRegisters.Add(register.RegYMM);
    }

    public void SaveFlags(IEnumerable<RflagsBits> flags)
    {
        if(_flagsRegister != null)
            throw new InvalidOperationException("Cannot save flags twice.");

        if(!flags.Any())
            return;

        // TODO This needs optimization. pushf/popf are slow and may leak flags to the stack
        //      Experiments with tweetnacl show that these instructions are _very_ rarely needed. So probably not worth the effort
        //      But this may overwrite data in leaf functions which use the red zone, which is bad

        // Allocate toy register
        _flagsRegister = AllocateToyRegister();

        // Store flags
        _assembler.DebugMarkSkippableSectionBegin();
        _assembler.pushfq();
        _assembler.pop(_flagsRegister.Reg64);
        _assembler.DebugMarkSkippableSectionEnd();

        _needsFlagRestore = true;
    }

    public void RestoreFlags()
    {
        // Restore flags
        _assembler.DebugMarkSkippableSectionBegin();
        _assembler.push(_flagsRegister.Reg64);
        _assembler.popfq();
        _assembler.DebugMarkSkippableSectionEnd();

        FreeToyRegister(_flagsRegister);
        _flagsRegister = null;
        _needsFlagRestore = false;
    }

    /// <summary>
    /// Restores all flags and registers that have been saved.
    /// Returns whether any new instructions have been emitted.
    /// </summary>
    public bool Restore()
    {
        bool instructionsEmitted = false;

        // Restore flags
        if(_needsFlagRestore)
        {
            RestoreFlags();
            instructionsEmitted = true;
        }

        // Free general purpose registers
        switch(_savedGpRegisters.Count)
        {
            case 1:
                _assembler.vmovq(new AssemblerRegister64(_savedGpRegisters[0]), _storageVectorRegister!.Value);
                instructionsEmitted = true;
                break;

            case 2:
                _assembler.vpextrq(new AssemblerRegister64(_savedGpRegisters[1]), _storageVectorRegister!.Value, 1);
                _assembler.vmovq(new AssemblerRegister64(_savedGpRegisters[0]), _storageVectorRegister.Value);
                instructionsEmitted = true;
                break;
        }

        // Free vector registers
        foreach(var register in _savedVectorRegisters)
        {
            int registerIndex = register.GetNumber();
            _assembler.vmovdqu(new AssemblerRegisterYMM(register), __ymmword_ptr[rsp - 128 - 32 * (registerIndex + 1)]);
        }

        // Reset register lists
        _savedGpRegisters.Clear();
        _savedVectorRegisters.Clear();
        _freedGpRegisters.Clear();
        _freedVectorRegisters.Clear();
        InitRegisterLists();

        return instructionsEmitted;
    }

    /// <summary>
    /// General purpose registers.
    /// </summary>
    public static readonly HashSet<Register> GeneralPurposeRegisters = new()
    {
        Register.RAX,
        Register.RBX,
        Register.RCX,
        Register.RDX,
        Register.RDI,
        Register.RSI,
        Register.RBP,
        Register.R8,
        Register.R9,
        Register.R10,
        Register.R11,
        Register.R12,
        Register.R13,
        Register.R14,
        Register.R15
    };

    /// <summary>
    /// Vector registers.
    /// </summary>
    private static readonly HashSet<Register> _vectorRegisters = new()
    {
        Register.ZMM0,
        Register.ZMM1,
        Register.ZMM2,
        Register.ZMM3,
        Register.ZMM4,
        Register.ZMM5,
        Register.ZMM6,
        Register.ZMM7,
        Register.ZMM8,
        Register.ZMM9,
        Register.ZMM10,
        Register.ZMM11,
        Register.ZMM12,
        Register.ZMM13,
        Register.ZMM14,
        Register.ZMM15,
    };
}