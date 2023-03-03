using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Iced.Intel;

namespace StaticInstrumentation;

/// <summary>
/// Offers functionality for parsing and accessing the output of the basic block tool.
/// </summary>
public class BbToolResult
{
    public Dictionary<int, ImageData> Images { get; } = new();
    public List<BasicBlockData> BasicBlocks { get; } = new();
    public Dictionary<(int imageId, uint offset), InstructionData> Instructions { get; } = new();
    public List<SyscallData> Syscalls { get; } = new();
    public Dictionary<(int imageId, uint offset), AllocFunctionType> Allocs { get; } = new();
    public HashSet<Register> UsedRegisters { get; } = new();

    private BbToolResult()
    {
    }

    /// <summary>
    /// Parses the given file.
    /// </summary>
    /// <param name="path">File path.</param>
    /// <returns></returns>
    public static BbToolResult FromFile(string path)
    {
        // Create new result object
        var result = new BbToolResult();

        // Load file
        var lines = File.ReadAllLines(path);

        // Initialize vector register set
        Register[] vectorRegisters =
        {
            Register.XMM0, Register.XMM1, Register.XMM2, Register.XMM3, Register.XMM4, Register.XMM5, Register.XMM6, Register.XMM7, Register.XMM8, Register.XMM9, Register.XMM10, Register.XMM11, Register.XMM12, Register.XMM13, Register.XMM14, Register.XMM15,
            Register.YMM0, Register.YMM1, Register.YMM2, Register.YMM3, Register.YMM4, Register.YMM5, Register.YMM6, Register.YMM7, Register.YMM8, Register.YMM9, Register.YMM10, Register.YMM11, Register.YMM12, Register.YMM13, Register.YMM14, Register.YMM15,
            Register.ZMM0, Register.ZMM1, Register.ZMM2, Register.ZMM3, Register.ZMM4, Register.ZMM5, Register.ZMM6, Register.ZMM7, Register.ZMM8, Register.ZMM9, Register.ZMM10, Register.ZMM11, Register.ZMM12, Register.ZMM13, Register.ZMM14, Register.ZMM15,
        };

        // Initialize general purpose register set
        HashSet<Register> generalPurposeRegisters = new HashSet<Register>(new[]
        {
            Register.RAX, Register.RBX, Register.RCX, Register.RDX, Register.RDI, Register.RSI, Register.RBP, Register.RSP,
            Register.R8, Register.R9, Register.R10, Register.R11, Register.R12, Register.R13, Register.R14, Register.R15
        });

        // Parse lines
        int nextImageId = 1;
        List<RflagsBits> flags = new();
        List<Register?> registers = new();
        var imageRegex = new Regex("^I ([0-9a-f]+) ([0-9a-f]+) (.*)$");
        var basicBlockRegex = new Regex("^B ([0-9a-f]+) ([0-9a-f]+) ([01])$");
        var registerCountRegex = new Regex("^R ([0-9A-Za-z]+) ([0-9]+)$");
        var vectorRegisterNameRegex = new Regex("^[xyz]mm([0-9]+)$");
        var instructionHeaderRegex = new Regex("^#N");
        var instructionRegex = new Regex("^N ([0-9A-Za-z]+)");
        var syscallRegex = new Regex("^S ([0-9A-Za-z]+)");
        var allocRegex = new Regex("^M([a-z]) ([0-9a-f]+)");
        foreach(var line in lines)
        {
            Match match;
            if((match = imageRegex.Match(line)).Success)
            {
                var imageData = new ImageData(nextImageId++, match.Groups[3].Value, Path.GetFileName(match.Groups[3].Value), ulong.Parse(match.Groups[1].Value, NumberStyles.HexNumber), ulong.Parse(match.Groups[2].Value, NumberStyles.HexNumber));
                result.Images.Add(imageData.Id, imageData);
            }
            else if((match = basicBlockRegex.Match(line)).Success)
            {
                ulong basicBlockBegin = ulong.Parse(match.Groups[1].Value, NumberStyles.HexNumber);
                ulong basicBlockEnd = ulong.Parse(match.Groups[2].Value, NumberStyles.HexNumber);
                bool hasFallThrough = int.Parse(match.Groups[3].Value) > 0;

                // Find image
                if(!result.Images.Where(i => i.Value.BaseAddress <= basicBlockBegin && basicBlockEnd <= i.Value.EndAddress).TryFirstOrDefault(out var imageData))
                {
                    Console.WriteLine($"Warning: Could not resolve basic block {basicBlockBegin:x16}...{basicBlockEnd:x16}, skipping");
                    continue;
                }

                var basicBlockData = new BasicBlockData(imageData.Key, (uint)(basicBlockBegin - imageData.Value.BaseAddress), (uint)(basicBlockEnd - basicBlockBegin), hasFallThrough);
                result.BasicBlocks.Add(basicBlockData);
            }
            else if((match = registerCountRegex.Match(line)).Success)
            {
                // No longer needed, we now use the much finer-grained register tracking
                /*
                string registerName = match.Groups[1].Value;
                int count = int.Parse(match.Groups[2].Value);

                match = vectorRegisterNameRegex.Match(registerName);
                if(match.Success && count > 0)
                {
                    int vectorRegisterNumber = int.Parse(match.Groups[1].Value);
                    if(0 < vectorRegisterNumber && vectorRegisterNumber <= 15)
                    {
                        Register vectorRegister = vectorRegisters[vectorRegisterNumber];
                        result.UsableVectorRegisters.Remove(vectorRegister);
                    }
                }
                */
            }
            else if((match = instructionHeaderRegex.Match(line)).Success)
            {
                // Parse flag/register list
                string[] entries = line.Substring(match.Length).Split(' ', StringSplitOptions.RemoveEmptyEntries);

                for(int i = 0; i < 6; ++i)
                {
                    var flag = entries[i] switch
                    {
                        "C" => RflagsBits.CF,
                        "P" => RflagsBits.PF,
                        "A" => RflagsBits.AF,
                        "Z" => RflagsBits.ZF,
                        "S" => RflagsBits.SF,
                        "O" => RflagsBits.OF,
                        _ => throw new Exception($"Unexpected flag header: {entries[i]}")
                    };

                    flags.Add(flag);
                }

                for(int i = 6; i < entries.Length; ++i)
                {
                    if(!Enum.TryParse(entries[i], true, out Register register) || (!generalPurposeRegisters.Contains(register) && !vectorRegisters.Contains(register)))
                    {
                        registers.Add(null); // Ignore other registers
                        continue;
                    }

                    registers.Add(register.GetFullRegister());
                }
            }
            else if((match = instructionRegex.Match(line)).Success)
            {
                ulong instructionAddress = ulong.Parse(match.Groups[1].Value, NumberStyles.HexNumber);

                // Find image
                if(!result.Images.Where(i => i.Value.BaseAddress <= instructionAddress && instructionAddress <= i.Value.EndAddress).TryFirstOrDefault(out var imageData))
                {
                    Console.WriteLine($"Warning: Could not resolve instruction {instructionAddress:x16}, skipping");
                    continue;
                }

                // Parse flag/register data
                List<(Register register, AccessInfo accessInfo)> registerData = new();
                List<(RflagsBits flag, AccessInfo accessInfo)> flagData = new();
                string[] entries = line.Substring(match.Length).Split(' ', StringSplitOptions.RemoveEmptyEntries);

                for(int i = 0; i < flags.Count; ++i)
                {
                    AccessInfo accessInfo = 0;
                    if(entries[i][0] == 'r')
                        accessInfo |= AccessInfo.Read;
                    if(entries[i][1] == 'w')
                        accessInfo |= AccessInfo.Write;
                    if(entries[i][2] == 'k')
                        accessInfo |= AccessInfo.Keep;

                    flagData.Add((flags[i], accessInfo));
                }

                for(int i = 0; i < registers.Count; ++i)
                {
                    if(registers[i] == null)
                        continue;

                    AccessInfo accessInfo = 0;
                    if(entries[flags.Count + i][0] == 'r')
                        accessInfo |= AccessInfo.Read;
                    if(entries[flags.Count + i][1] == 'w')
                        accessInfo |= AccessInfo.Write;
                    if(entries[flags.Count + i][2] == 'k')
                        accessInfo |= AccessInfo.Keep;

                    registerData.Add((registers[i].Value, accessInfo));

                    if(accessInfo != 0)
                        result.UsedRegisters.Add(registers[i].Value);
                }

                uint offset = (uint)(instructionAddress - imageData.Value.BaseAddress);
                result.Instructions.Add((imageData.Key, offset), new InstructionData(imageData.Key, offset, registerData, flagData));
            }
            else if((match = syscallRegex.Match(line)).Success)
            {
                ulong instructionAddress = ulong.Parse(match.Groups[1].Value, NumberStyles.HexNumber);

                // Find image
                if(!result.Images.Where(i => i.Value.BaseAddress <= instructionAddress && instructionAddress <= i.Value.EndAddress).TryFirstOrDefault(out var imageData))
                {
                    Console.WriteLine($"Warning: Could not resolve syscall instruction {instructionAddress:x16}, skipping");
                    continue;
                }

                result.Syscalls.Add(new SyscallData(imageData.Key, (uint)(instructionAddress - imageData.Value.BaseAddress)));
            }
            else if((match = allocRegex.Match(line)).Success)
            {
                char type = match.Groups[1].Value[0];
                ulong address = ulong.Parse(match.Groups[2].Value, NumberStyles.HexNumber);

                // Find image
                if(!result.Images.Where(i => i.Value.BaseAddress <= address && address <= i.Value.EndAddress).TryFirstOrDefault(out var imageData))
                {
                    Console.WriteLine($"Warning: Could not resolve *alloc {address:x16}, skipping");
                    continue;
                }

                AllocFunctionType allocFunctionType = type switch
                {
                    'm' => AllocFunctionType.Malloc,
                    'c' => AllocFunctionType.Calloc,
                    'r' => AllocFunctionType.Realloc,
                    _ => throw new Exception($"Unknown allocation function type '{type}'")
                };

                result.Allocs.Add((imageData.Key, (uint)(address - imageData.Value.BaseAddress)), allocFunctionType);
            }
        }

        return result;
    }

    public record ImageData(int Id, string Path, string Name, ulong BaseAddress, ulong EndAddress);

    public record BasicBlockData(int ImageId, uint Offset, uint Size, bool HasFallThrough);

    public record InstructionData(int ImageId, uint Offset, List<(Register register, AccessInfo accessInfo)> Registers, List<(RflagsBits flag, AccessInfo accessInfo)> Flags);

    public record SyscallData(int ImageId, uint Offset);

    [Flags]
    public enum AccessInfo
    {
        Read = 1,
        Write = 2,
        Keep = 4
    }

    public enum AllocFunctionType
    {
        Malloc,
        Calloc,
        Realloc
    }
}