using Iced.Intel;

namespace StaticInstrumentation;

public class GenericAssemblerVectorRegister
{
    public Register Register { get; }

    public GenericAssemblerVectorRegister(Register register)
    {
        Register = register;
    }

    public AssemblerRegisterXMM RegXMM => RegisterExtensions.Vector128Lookup[Register];
    public AssemblerRegisterYMM RegYMM => RegisterExtensions.Vector256Lookup[Register];
}