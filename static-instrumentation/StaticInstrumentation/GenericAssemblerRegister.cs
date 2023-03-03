using Iced.Intel;

namespace StaticInstrumentation;

public class GenericAssemblerRegister
{
    public Register Register { get; }

    /// <summary>
    /// Gets or sets the desired width of the toy register.
    /// Used by methods that automatically determine the requested register / memory operand width.
    /// </summary>
    public int PreferredWidth { get; set; }

    public GenericAssemblerRegister(Register register)
    {
        Register = register;
    }

    public AssemblerRegister64 Reg64 => new(Register);
    public AssemblerRegister32 Reg32 => RegisterExtensions.Register32Lookup[Register];
    public AssemblerRegister16 Reg16 => RegisterExtensions.Register16Lookup[Register];
    public AssemblerRegister8 Reg8 => RegisterExtensions.Register8LLookup[Register];
    public AssemblerRegister8 Reg8H => RegisterExtensions.Register8HLookup[Register];
}