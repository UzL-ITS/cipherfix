using System.Collections.Generic;
using System.Collections.ObjectModel;
using Iced.Intel;

namespace StaticInstrumentation;

public static class RegisterExtensions
{
    /// <summary>
    /// 64-bit -> 32-bit sub register mapping.
    /// </summary>
    public static readonly ReadOnlyDictionary<Register, AssemblerRegister32> Register32Lookup = new(new Dictionary<Register, AssemblerRegister32>
    {
        [Register.RAX] = new(Register.EAX),
        [Register.RBX] = new(Register.EBX),
        [Register.RCX] = new(Register.ECX),
        [Register.RDX] = new(Register.EDX),
        [Register.RDI] = new(Register.EDI),
        [Register.RSI] = new(Register.ESI),
        [Register.RBP] = new(Register.EBP),
        [Register.R8] = new(Register.R8D),
        [Register.R9] = new(Register.R9D),
        [Register.R10] = new(Register.R10D),
        [Register.R11] = new(Register.R11D),
        [Register.R12] = new(Register.R12D),
        [Register.R13] = new(Register.R13D),
        [Register.R14] = new(Register.R14D),
        [Register.R15] = new(Register.R15D),
    });

    /// <summary>
    /// 64-bit -> 16-bit sub register mapping.
    /// </summary>
    public static readonly Dictionary<Register, AssemblerRegister16> Register16Lookup = new(new Dictionary<Register, AssemblerRegister16>
    {
        [Register.RAX] = new(Register.AX),
        [Register.RBX] = new(Register.BX),
        [Register.RCX] = new(Register.CX),
        [Register.RDX] = new(Register.DX),
        [Register.RDI] = new(Register.DI),
        [Register.RSI] = new(Register.SI),
        [Register.RBP] = new(Register.BP),
        [Register.R8] = new(Register.R8W),
        [Register.R9] = new(Register.R9W),
        [Register.R10] = new(Register.R10W),
        [Register.R11] = new(Register.R11W),
        [Register.R12] = new(Register.R12W),
        [Register.R13] = new(Register.R13W),
        [Register.R14] = new(Register.R14W),
        [Register.R15] = new(Register.R15W),
    });

    /// <summary>
    /// 64-bit -> 8-bit low sub register mapping.
    /// </summary>
    public static readonly Dictionary<Register, AssemblerRegister8> Register8LLookup = new(new Dictionary<Register, AssemblerRegister8>
    {
        [Register.RAX] = new(Register.AL),
        [Register.RBX] = new(Register.BL),
        [Register.RCX] = new(Register.CL),
        [Register.RDX] = new(Register.DL),
        [Register.RDI] = new(Register.DIL),
        [Register.RSI] = new(Register.SIL),
        [Register.RBP] = new(Register.BPL),
        [Register.R8] = new(Register.R8L),
        [Register.R9] = new(Register.R9L),
        [Register.R10] = new(Register.R10L),
        [Register.R11] = new(Register.R11L),
        [Register.R12] = new(Register.R12L),
        [Register.R13] = new(Register.R13L),
        [Register.R14] = new(Register.R14L),
        [Register.R15] = new(Register.R15L),
    });

    /// <summary>
    /// 64-bit -> 8-bit high sub register mapping.
    /// </summary>
    public static readonly Dictionary<Register, AssemblerRegister8> Register8HLookup = new(new Dictionary<Register, AssemblerRegister8>
    {
        [Register.RAX] = new(Register.AH),
        [Register.RBX] = new(Register.BH),
        [Register.RCX] = new(Register.CH),
        [Register.RDX] = new(Register.DH),
    });

    /// <summary>
    /// *-bit -> 128-bit vector sub register mapping.
    /// </summary>
    public static readonly Dictionary<Register, AssemblerRegisterXMM> Vector128Lookup = new()
    {
        [Register.XMM0] = new AssemblerRegisterXMM(Register.XMM0),
        [Register.XMM1] = new AssemblerRegisterXMM(Register.XMM1),
        [Register.XMM2] = new AssemblerRegisterXMM(Register.XMM2),
        [Register.XMM3] = new AssemblerRegisterXMM(Register.XMM3),
        [Register.XMM4] = new AssemblerRegisterXMM(Register.XMM4),
        [Register.XMM5] = new AssemblerRegisterXMM(Register.XMM5),
        [Register.XMM6] = new AssemblerRegisterXMM(Register.XMM6),
        [Register.XMM7] = new AssemblerRegisterXMM(Register.XMM7),
        [Register.XMM8] = new AssemblerRegisterXMM(Register.XMM8),
        [Register.XMM9] = new AssemblerRegisterXMM(Register.XMM9),
        [Register.XMM10] = new AssemblerRegisterXMM(Register.XMM10),
        [Register.XMM11] = new AssemblerRegisterXMM(Register.XMM11),
        [Register.XMM12] = new AssemblerRegisterXMM(Register.XMM12),
        [Register.XMM13] = new AssemblerRegisterXMM(Register.XMM13),
        [Register.XMM14] = new AssemblerRegisterXMM(Register.XMM14),
        [Register.XMM15] = new AssemblerRegisterXMM(Register.XMM15),
        [Register.YMM0] = new AssemblerRegisterXMM(Register.XMM0),
        [Register.YMM1] = new AssemblerRegisterXMM(Register.XMM1),
        [Register.YMM2] = new AssemblerRegisterXMM(Register.XMM2),
        [Register.YMM3] = new AssemblerRegisterXMM(Register.XMM3),
        [Register.YMM4] = new AssemblerRegisterXMM(Register.XMM4),
        [Register.YMM5] = new AssemblerRegisterXMM(Register.XMM5),
        [Register.YMM6] = new AssemblerRegisterXMM(Register.XMM6),
        [Register.YMM7] = new AssemblerRegisterXMM(Register.XMM7),
        [Register.YMM8] = new AssemblerRegisterXMM(Register.XMM8),
        [Register.YMM9] = new AssemblerRegisterXMM(Register.XMM9),
        [Register.YMM10] = new AssemblerRegisterXMM(Register.XMM10),
        [Register.YMM11] = new AssemblerRegisterXMM(Register.XMM11),
        [Register.YMM12] = new AssemblerRegisterXMM(Register.XMM12),
        [Register.YMM13] = new AssemblerRegisterXMM(Register.XMM13),
        [Register.YMM14] = new AssemblerRegisterXMM(Register.XMM14),
        [Register.YMM15] = new AssemblerRegisterXMM(Register.XMM15),
        [Register.ZMM0] = new AssemblerRegisterXMM(Register.XMM0),
        [Register.ZMM1] = new AssemblerRegisterXMM(Register.XMM1),
        [Register.ZMM2] = new AssemblerRegisterXMM(Register.XMM2),
        [Register.ZMM3] = new AssemblerRegisterXMM(Register.XMM3),
        [Register.ZMM4] = new AssemblerRegisterXMM(Register.XMM4),
        [Register.ZMM5] = new AssemblerRegisterXMM(Register.XMM5),
        [Register.ZMM6] = new AssemblerRegisterXMM(Register.XMM6),
        [Register.ZMM7] = new AssemblerRegisterXMM(Register.XMM7),
        [Register.ZMM8] = new AssemblerRegisterXMM(Register.XMM8),
        [Register.ZMM9] = new AssemblerRegisterXMM(Register.XMM9),
        [Register.ZMM10] = new AssemblerRegisterXMM(Register.XMM10),
        [Register.ZMM11] = new AssemblerRegisterXMM(Register.XMM11),
        [Register.ZMM12] = new AssemblerRegisterXMM(Register.XMM12),
        [Register.ZMM13] = new AssemblerRegisterXMM(Register.XMM13),
        [Register.ZMM14] = new AssemblerRegisterXMM(Register.XMM14),
        [Register.ZMM15] = new AssemblerRegisterXMM(Register.XMM15)
    };

    /// <summary>
    /// *-bit -> 256-bit vector sub register mapping.
    /// </summary>
    public static readonly Dictionary<Register, AssemblerRegisterYMM> Vector256Lookup = new()
    {
        [Register.XMM0] = new AssemblerRegisterYMM(Register.YMM0),
        [Register.XMM1] = new AssemblerRegisterYMM(Register.YMM1),
        [Register.XMM2] = new AssemblerRegisterYMM(Register.YMM2),
        [Register.XMM3] = new AssemblerRegisterYMM(Register.YMM3),
        [Register.XMM4] = new AssemblerRegisterYMM(Register.YMM4),
        [Register.XMM5] = new AssemblerRegisterYMM(Register.YMM5),
        [Register.XMM6] = new AssemblerRegisterYMM(Register.YMM6),
        [Register.XMM7] = new AssemblerRegisterYMM(Register.YMM7),
        [Register.XMM8] = new AssemblerRegisterYMM(Register.YMM8),
        [Register.XMM9] = new AssemblerRegisterYMM(Register.YMM9),
        [Register.XMM10] = new AssemblerRegisterYMM(Register.YMM10),
        [Register.XMM11] = new AssemblerRegisterYMM(Register.YMM11),
        [Register.XMM12] = new AssemblerRegisterYMM(Register.YMM12),
        [Register.XMM13] = new AssemblerRegisterYMM(Register.YMM13),
        [Register.XMM14] = new AssemblerRegisterYMM(Register.YMM14),
        [Register.XMM15] = new AssemblerRegisterYMM(Register.YMM15),
        [Register.YMM0] = new AssemblerRegisterYMM(Register.YMM0),
        [Register.YMM1] = new AssemblerRegisterYMM(Register.YMM1),
        [Register.YMM2] = new AssemblerRegisterYMM(Register.YMM2),
        [Register.YMM3] = new AssemblerRegisterYMM(Register.YMM3),
        [Register.YMM4] = new AssemblerRegisterYMM(Register.YMM4),
        [Register.YMM5] = new AssemblerRegisterYMM(Register.YMM5),
        [Register.YMM6] = new AssemblerRegisterYMM(Register.YMM6),
        [Register.YMM7] = new AssemblerRegisterYMM(Register.YMM7),
        [Register.YMM8] = new AssemblerRegisterYMM(Register.YMM8),
        [Register.YMM9] = new AssemblerRegisterYMM(Register.YMM9),
        [Register.YMM10] = new AssemblerRegisterYMM(Register.YMM10),
        [Register.YMM11] = new AssemblerRegisterYMM(Register.YMM11),
        [Register.YMM12] = new AssemblerRegisterYMM(Register.YMM12),
        [Register.YMM13] = new AssemblerRegisterYMM(Register.YMM13),
        [Register.YMM14] = new AssemblerRegisterYMM(Register.YMM14),
        [Register.YMM15] = new AssemblerRegisterYMM(Register.YMM15),
        [Register.ZMM0] = new AssemblerRegisterYMM(Register.YMM0),
        [Register.ZMM1] = new AssemblerRegisterYMM(Register.YMM1),
        [Register.ZMM2] = new AssemblerRegisterYMM(Register.YMM2),
        [Register.ZMM3] = new AssemblerRegisterYMM(Register.YMM3),
        [Register.ZMM4] = new AssemblerRegisterYMM(Register.YMM4),
        [Register.ZMM5] = new AssemblerRegisterYMM(Register.YMM5),
        [Register.ZMM6] = new AssemblerRegisterYMM(Register.YMM6),
        [Register.ZMM7] = new AssemblerRegisterYMM(Register.YMM7),
        [Register.ZMM8] = new AssemblerRegisterYMM(Register.YMM8),
        [Register.ZMM9] = new AssemblerRegisterYMM(Register.YMM9),
        [Register.ZMM10] = new AssemblerRegisterYMM(Register.YMM10),
        [Register.ZMM11] = new AssemblerRegisterYMM(Register.YMM11),
        [Register.ZMM12] = new AssemblerRegisterYMM(Register.YMM12),
        [Register.ZMM13] = new AssemblerRegisterYMM(Register.YMM13),
        [Register.ZMM14] = new AssemblerRegisterYMM(Register.YMM14),
        [Register.ZMM15] = new AssemblerRegisterYMM(Register.YMM15)
    };

    public static List<Register> VectorRegisters = new()
    {
        Register.YMM0,
        Register.YMM1,
        Register.YMM2,
        Register.YMM3,
        Register.YMM4,
        Register.YMM5,
        Register.YMM6,
        Register.YMM7,
        Register.YMM8,
        Register.YMM9,
        Register.YMM10,
        Register.YMM11,
        Register.YMM12,
        Register.YMM13,
        Register.YMM14,
        Register.YMM15
    };

    public static AssemblerRegister32 GetSubRegister32(this AssemblerRegister64 register64) => Register32Lookup[register64.Value];
    public static AssemblerRegister16 GetSubRegister16(this AssemblerRegister64 register64) => Register16Lookup[register64.Value];
    public static AssemblerRegister8 GetSubRegister8L(this AssemblerRegister64 register64) => Register8LLookup[register64.Value];
    public static AssemblerRegister8 GetSubRegister8L(this AssemblerRegister32 register32) => Register8LLookup[register32.Value.GetFullRegister()];
    public static AssemblerRegister8 GetSubRegister8L(this AssemblerRegister16 register16) => Register8LLookup[register16.Value.GetFullRegister()];
    public static AssemblerRegisterXMM GetSubRegisterXmm(this AssemblerRegisterYMM registerYmm) => Vector128Lookup[registerYmm.Value];
    public static AssemblerRegisterYMM GetSubRegisterYmm(this AssemblerRegisterYMM registerYmm) => Vector256Lookup[registerYmm.Value];
}