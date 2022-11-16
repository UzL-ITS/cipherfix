using Iced.Intel;

namespace StaticInstrumentation;

public class GenericAssemblerVectorRegister
{
    public Register Register { get; }

    /// <summary>
    /// Gets or sets the desired width of the toy register.
    /// Used by methods that automatically determine the requested register / memory operand width.
    /// </summary>
    public int PreferredWidth { get; set; }
    
    public GenericAssemblerVectorRegister(Register register)
    {
        Register = register;
    }

    public AssemblerRegisterXMM RegXMM => RegisterExtensions.Vector128Lookup[Register];
    public AssemblerRegisterYMM RegYMM => RegisterExtensions.Vector256Lookup[Register];
}