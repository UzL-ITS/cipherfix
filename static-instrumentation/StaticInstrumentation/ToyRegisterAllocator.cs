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
    private List<Register> _instructionNoReadWriteGpRegisters;

    /// <summary>
    /// General purpose registers that aren't read or written and also don't need to be kept by the instruction.
    /// I.e., cluttering these registers is fine.
    /// </summary>
    private List<Register> _instructionNoReadWriteKeepGpRegisters;

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
    private List<AssemblerRegisterXMM> _storageVectorRegisters = new();

    /// <summary>
    /// Toy register containing the saved status flags.
    /// </summary>
    private ToyRegister _flagsRegister = null;

    /// <summary>
    /// Tracks the currently saved status flags.
    /// </summary>
    private RflagsBits[] _savedFlags = null;

    /// <summary>
    /// Vector registers that aren't read or written by the instruction.
    /// </summary>
    private List<Register> _instructionNoReadWriteVectorRegisters;

    /// <summary>
    /// Vector registers that aren't read or written and also don't need to be kept by the instruction.
    /// I.e., cluttering these registers is fine.
    /// </summary>
    private List<Register> _instructionNoReadWriteKeepVectorRegisters;

    /// <summary>
    /// Vector registers which have been saved before using them as toy registers.
    /// </summary>
    private readonly List<Register> _savedVectorRegisters = new();

    /// <summary>
    /// Toy vector registers that were used and then marked as available (but were not yet restored).
    /// This ensures that toy registers are re-used efficiently, avoiding performance penalties from unnecessary saving/restoring.
    /// </summary>
    private readonly HashSet<Register> _freedVectorRegisters = new();

    /// <summary>
    /// Vector registers that are marked as reserved and thus are never allocated.
    /// </summary>
    private static readonly HashSet<Register> _reservedVectorRegisters = new();

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

    public static void MarkRegisterAsReserved(Register register)
    {
        if(register.IsVectorRegister())
            _reservedVectorRegisters.Add(RegisterExtensions.Vector256Lookup[register]);
        else
            throw new InvalidOperationException();
    }

    /// <summary>
    /// Tries to allocate a specific toy register.
    /// Only returns registers that are directly available.
    /// </summary>
    /// <param name="register">Register.</param>
    /// <param name="preferredWidth">Width.</param>
    /// <returns></returns>
    public ToyRegister AllocateSpecificToyRegister(Register register, int preferredWidth = 0)
    {
        // Did we already use this register?
        if(_freedGpRegisters.Contains(register))
        {
            _freedGpRegisters.Remove(register);
            return new ToyRegister(register, this) { PreferredWidth = preferredWidth, Freed = false };
        }
        
        if(_instructionNoReadWriteKeepGpRegisters.Contains(register))
        {
            // Do not allocate it again in the future
            _instructionNoReadWriteGpRegisters.Remove(register);
            _instructionNoReadWriteKeepGpRegisters.Remove(register);

            // The register does not need to be saved
            return new ToyRegister(register, this) { PreferredWidth = preferredWidth, Freed = false };
        }

        return null;
    }

    public ToyRegister AllocateToyRegisterUnused(IEnumerable<Register> excludedRegisters = null, int preferredWidth = 0)
    {
        if(_instructionNoReadWriteKeepGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).Any())
        {
            var register = _instructionNoReadWriteKeepGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).FirstAvoidingRegister(Register.RAX);

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
            var freedRegister = _freedGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).FirstAvoidingRegister(Register.RAX);
            _freedGpRegisters.Remove(freedRegister);
            return new ToyRegister(freedRegister, this) { PreferredWidth = preferredWidth, Freed = false };
        }

        // Look for registers that don't need to be saved
        var toyRegister = AllocateToyRegisterUnused(excludedRegisters, preferredWidth);
        if(toyRegister != null)
            return toyRegister;

        // We need to save a register
        var register = _instructionNoReadWriteGpRegisters.Except(excludedRegisters ?? Enumerable.Empty<Register>()).FirstAvoidingRegister(Register.RAX);
        _instructionNoReadWriteGpRegisters.Remove(register);

        toyRegister = new ToyRegister(register, this) { PreferredWidth = preferredWidth, Freed = false };

        // We need to save this register. Just drop it into a vector register
        AssemblerRegisterXMM storageVectorRegister;
        if(_savedGpRegisters.Count % 2 == 0)
        {
            // There is no storage vector register with a free slot, so allocate new one
            // Note that it's cheaper to once do the expensive work for saving/restoring a big vector register
            // than doing this for each general purpose register. We assume that most instrumentation will
            // use more than one general purpose toy register.

            storageVectorRegister = AllocateToyVectorRegister().RegXMM;
            _storageVectorRegisters.Add(storageVectorRegister);
        }
        else
            storageVectorRegister = _storageVectorRegisters.Last();

        // Save register
        if(_savedGpRegisters.Count % 2 == 0)
            _assembler.vmovq(storageVectorRegister, toyRegister.Reg64);
        else
            _assembler.vpinsrq(storageVectorRegister, storageVectorRegister, toyRegister.Reg64, 1);

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

    public GenericAssemblerVectorRegister AllocateToyVectorRegister(int preferredWidth = 0)
    {
        // Short path for toy registers which were already used
        if(_freedVectorRegisters.Count > 0)
        {
            var register = _freedVectorRegisters.First();
            _freedVectorRegisters.Remove(register);
            return new GenericAssemblerVectorRegister(register) { PreferredWidth = preferredWidth };
        }

        // Find usable register
        for(int i = 0; i < _instructionNoReadWriteKeepVectorRegisters.Count; ++i)
        {
            var register = _instructionNoReadWriteKeepVectorRegisters[i];

            if(!_reservedVectorRegisters.Contains(register))
            {
                // Do not allocate it again in the future
                _instructionNoReadWriteVectorRegisters.Remove(register);
                _instructionNoReadWriteKeepVectorRegisters.RemoveAt(i);

                // The register does not need to be saved
                return new GenericAssemblerVectorRegister(register) { PreferredWidth = preferredWidth };
            }
        }

        // No hit, we need to save one
        for(int i = 0; i < _instructionNoReadWriteVectorRegisters.Count; ++i)
        {
            var register = _instructionNoReadWriteVectorRegisters[i];

            if(!_reservedVectorRegisters.Contains(register))
            {
                _instructionNoReadWriteVectorRegisters.RemoveAt(i);

                var asmRegister = new GenericAssemblerVectorRegister(register) { PreferredWidth = preferredWidth };

                // Save register
                // For now we use the stack as a thread-safe way for storing toy registers. This works as long as the stack pointer is
                // not modified, i.e., we don't use this method for instrumenting push/pop and call.
                // We subtract 128 to ensure that we don't write into the red zone.
                // TODO Ensure in push/pop instrumentation that this method is indeed safe
                // TODO Mask register value if necessary
                Console.WriteLine($"WARNING: Saving vector register"); // Remove this after addressing the above TODOs
                int registerIndex = register.GetNumber();
                _assembler.vmovdqu(__ymmword_ptr[rsp - 128 - 32 * (registerIndex + 1)], asmRegister.RegYMM);

                _savedVectorRegisters.Add(register);
                return asmRegister;
            }
        }

        throw new Exception("No vector toy available.");
    }

    public void FreeToyVectorRegister(GenericAssemblerVectorRegister register)
    {
        _freedVectorRegisters.Add(register.RegYMM);
    }

    public void SaveFlags(IEnumerable<RflagsBits> flags)
    {
        if(_flagsRegister != null)
            throw new InvalidOperationException("Cannot save flags twice.");

        var flagArray = flags.ToArray();
        if(!flagArray.Any())
            return;

        // Allocate toy register
        bool gotRax = true;
        _flagsRegister = AllocateSpecificToyRegister(rax);
        if(_flagsRegister == null)
        {
            _flagsRegister = AllocateToyRegister();
            gotRax = false;
        }

        // Fast path for single flags
        if(flagArray.Length == 1)
        {
            switch(flagArray[0])
            {
                case RflagsBits.OF:
                    _assembler.seto(_flagsRegister.Reg8);
                    break;
                case RflagsBits.SF:
                    _assembler.sets(_flagsRegister.Reg8);
                    break;
                case RflagsBits.ZF:
                    _assembler.setz(_flagsRegister.Reg8);
                    break;
                case RflagsBits.AF:
                    _assembler.seta(_flagsRegister.Reg8);
                    break;
                case RflagsBits.CF:
                    _assembler.setc(_flagsRegister.Reg8);
                    break;
                case RflagsBits.PF:
                    _assembler.setp(_flagsRegister.Reg8);
                    break;
                default:
                    throw new Exception("Unsupported flag");
            }
        }
        else if(gotRax)
        {
            // With RAX, we can use the LAHF/SAHF instructions directly
            
             _assembler.lahf();
        }
        else
        {
            // We didn't get RAX, but we can use LAHF/SAHF anyway. We just have to save RAX somewhere
            _assembler.mov(_flagsRegister.Reg64, rax);
            _assembler.lahf();
            _assembler.xchg(_flagsRegister.Reg64, rax);
            
            /*
            Console.WriteLine($"  WARNING: Using pushf to save flags: {_instructionData.ImageOffset:x} {string.Join(' ', flagArray.Select(f => f.ToString()))}");
                
            // Save flags on the stack
            // TODO This may overwrite data in leaf functions which use the red zone, which is bad
            _assembler.DebugMarkSkippableSectionBegin();
            _assembler.pushfq();
            _assembler.pop(_flagsRegister.Reg64);
            _assembler.DebugMarkSkippableSectionEnd();
            */
        }

        _savedFlags = flagArray;
    }

    public void RestoreFlags()
    {
        bool gotRax = _flagsRegister.Register == Register.RAX;
        
        // Fast path for single flags
        if(_savedFlags.Length == 1)
        {
            switch(_savedFlags[0])
            {
                case RflagsBits.OF:
                    _assembler.add(_flagsRegister.Reg8, 0x7f);
                    break;
                case RflagsBits.SF:
                    _assembler.add(_flagsRegister.Reg8, 0x7f);
                    break;
                case RflagsBits.ZF:
                    _assembler.sub(_flagsRegister.Reg8, 1);
                    break;
                case RflagsBits.AF:
                    throw new NotSupportedException("Missing handler for A flag");
                case RflagsBits.CF:
                    _assembler.add(_flagsRegister.Reg8, 0xff);
                    break;
                case RflagsBits.PF:
                    throw new NotSupportedException("Missing handler for P flag");
                default:
                    throw new Exception("Unsupported flag");
            }
        }
        else if(gotRax)
        {
            _assembler.sahf();
        }
        else
        {
            _assembler.xchg(_flagsRegister.Reg64, rax);
            _assembler.sahf();
            _assembler.mov(rax, _flagsRegister.Reg64);

            /*
            // Restore flags from the stack
            _assembler.DebugMarkSkippableSectionBegin();
            _assembler.push(_flagsRegister.Reg64);
            _assembler.popfq();
            _assembler.DebugMarkSkippableSectionEnd();
            */
        }

        FreeToyRegister(_flagsRegister);
        _flagsRegister = null;
        _savedFlags = null;
    }

    /// <summary>
    /// Restores all flags and registers that have been saved.
    /// Returns whether any new instructions have been emitted.
    /// </summary>
    public bool Restore()
    {
        bool instructionsEmitted = false;

        // Restore flags
        if(_savedFlags != null)
        {
            RestoreFlags();
            instructionsEmitted = true;
        }

        // Free general purpose registers
        int savedGpIndex = 0;
        foreach(var storageVectorRegister in _storageVectorRegisters)
        {
            if(savedGpIndex < _savedGpRegisters.Count)
            {
                _assembler.vmovq(new AssemblerRegister64(_savedGpRegisters[savedGpIndex]), storageVectorRegister);
                instructionsEmitted = true;
                ++savedGpIndex;
            }

            if(savedGpIndex < _savedGpRegisters.Count)
            {
                _assembler.vpextrq(new AssemblerRegister64(_savedGpRegisters[savedGpIndex]), storageVectorRegister, 1);
                instructionsEmitted = true;
                ++savedGpIndex;
            }
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