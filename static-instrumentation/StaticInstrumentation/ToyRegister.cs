using System;
using Iced.Intel;

namespace StaticInstrumentation;

/// <summary>
/// 
/// </summary>
public class ToyRegister : GenericAssemblerRegister, IDisposable
{
    private readonly ToyRegisterAllocator _allocator;

    /// <summary>
    /// Set by <see cref="ToyRegisterAllocator"/>.
    /// </summary>
    public bool Freed { get; set; }

    public ToyRegister(Register register, ToyRegisterAllocator allocator)
        : base(register)
    {
        _allocator = allocator ?? throw new ArgumentNullException(nameof(allocator));
    }

    public void Dispose()
    {
        _allocator.FreeToyRegister(this);
    }
}