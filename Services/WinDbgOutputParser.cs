using System.Globalization;
using System.Text.RegularExpressions;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed record ParsedDebuggerOutput(
    string BugCheckCode,
    string BugCheckName,
    string BugCheckString,
    IReadOnlyList<string> BugCheckArguments,
    string Parameters,
    string ExceptionCode,
    string ExceptionName,
    string ExceptionRecord,
    string ContextRecord,
    string FaultingIp,
    string FaultingThread,
    string ProcessName,
    string ImageName,
    string ModuleName,
    string SymbolName,
    string FailureBucket,
    string FailureIdHash,
    string ProbablyCausedBy,
    string StackText,
    string StackCommand,
    string ReadAddress,
    string WriteAddress,
    string AccessType,
    string AttemptedAddress,
    string FaultingAddress,
    string FaultingModule,
    string FaultingSymbol,
    string FaultingInstruction,
    string CustomerCrashCount,
    string DefaultBucketId,
    IReadOnlyDictionary<string, string> Registers,
    IReadOnlyDictionary<string, int> StackModuleOccurrences,
    IReadOnlyList<string> MemoryCorruptionIndicators,
    IReadOnlyList<string> InvalidPointerIndicators,
    string PointerAnalysis)
{
    public FaultEvidenceSource FaultEvidenceSource { get; init; }
    public string DisassemblyContext { get; init; } = "";
    public DateTime? CrashTime { get; init; }
    public bool SymbolsIncomplete { get; init; }
}

public sealed class WinDbgOutputParser
{
    private static readonly string[] RegisterNames =
        ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];

    public ParsedDebuggerOutput Parse(string output, string eventMessage = "")
    {
        output ??= "";
        eventMessage ??= "";
        var heading = Regex.Match(output, @"(?im)^\s*([A-Z][A-Z0-9_]+)\s+\(([0-9a-fA-F]+)\)\s*$");
        var bugCode = Value(output, "BUGCHECK_CODE");
        if (string.IsNullOrWhiteSpace(bugCode) && heading.Success) bugCode = heading.Groups[2].Value;
        if (string.IsNullOrWhiteSpace(bugCode))
        {
            bugCode = Regex.Match(output, @"(?im)Bugcheck code\s+([0-9a-fA-F`]+)").Groups[1].Value;
        }

        var eventHex = Regex.Matches(eventMessage, @"(?i)0x[0-9a-f]{1,16}").Select(x => x.Value).ToList();
        if (string.IsNullOrWhiteSpace(bugCode) && eventHex.Count > 0) bugCode = eventHex[0];
        bugCode = BugCheckKnowledgeBase.NormalizeCode(bugCode);

        var args = ParseArguments(output);
        if (args.Count == 0 && eventHex.Count > 1) args.AddRange(eventHex.Skip(1).Take(4));
        var knowledge = BugCheckKnowledgeBase.Get(bugCode);
        var bugName = heading.Success ? heading.Groups[1].Value.Trim() : knowledge.Name;

        var exceptionCode = ExtractHex(Value(output, "EXCEPTION_CODE"), 8);
        if (string.IsNullOrWhiteSpace(exceptionCode)) exceptionCode = ExtractHex(Value(output, "EXCEPTION_CODE_STR"), 8);
        if (string.IsNullOrWhiteSpace(exceptionCode)) exceptionCode = BugCheckKnowledgeBase.InferExceptionCode(bugCode, args);
        var exceptionName = DescribeException(exceptionCode);
        var readAddress = NormalizeOptionalAddress(Value(output, "READ_ADDRESS"));
        var writeAddress = NormalizeOptionalAddress(Value(output, "WRITE_ADDRESS"));
        var access = ParseExceptionAccess(output, readAddress, writeAddress);
        if (string.IsNullOrWhiteSpace(access.Type)) access = access with { Type = BugCheckKnowledgeBase.InferAccessType(bugCode, args) };
        if (string.IsNullOrWhiteSpace(access.Address))
        {
            access = access with { Address = !string.IsNullOrWhiteSpace(readAddress) ? readAddress : !string.IsNullOrWhiteSpace(writeAddress) ? writeAddress : BugCheckKnowledgeBase.InferAttemptedAddress(bugCode, args) };
        }

        var faultingAddress = FirstNonEmpty(
            AddressFromField(Value(output, "ExceptionAddress")),
            BugCheckKnowledgeBase.InferFaultingAddress(bugCode, args));
        var registers = ParseRegisters(output, faultingAddress);
        if (string.IsNullOrWhiteSpace(faultingAddress) && registers.TryGetValue("RIP", out var rip)) faultingAddress = rip;
        var faulting = ParseFaultingInstruction(output, faultingAddress);
        var symbol = Value(output, "SYMBOL_NAME");
        var module = Value(output, "MODULE_NAME");
        var faultingModule = ModuleAtAddress(output, faultingAddress);
        var faultingSymbol = faulting.Symbol;
        var pointer = AnalyzePointer(faulting.Instruction, registers);
        var invalidPointers = BuildInvalidPointerIndicators(access.Address, pointer);
        var memoryIndicators = BuildMemoryIndicators(output, bugCode, exceptionCode, invalidPointers);

        return new ParsedDebuggerOutput(
            bugCode,
            bugName,
            Value(output, "BUGCHECK_STR"),
            args,
            BugCheckKnowledgeBase.DescribeParameters(bugCode, args),
            exceptionCode,
            exceptionName,
            AddressFromField(Value(output, "EXCEPTION_RECORD")),
            AddressFromField(Value(output, "CONTEXT")),
            Value(output, "FAULTING_IP"),
            AddressFromField(Value(output, "FAULTING_THREAD")),
            Value(output, "PROCESS_NAME"),
            NormalizeModule(Value(output, "IMAGE_NAME")),
            NormalizeModule(module),
            symbol,
            Value(output, "FAILURE_BUCKET_ID"),
            Value(output, "FAILURE_ID_HASH"),
            Regex.Match(output, @"(?im)^\s*Probably caused by\s*:\s*(.+)$").Groups[1].Value.Trim(),
            ExtractPrimaryStackText(output),
            Value(output, "STACK_COMMAND"),
            readAddress,
            writeAddress,
            access.Type,
            access.Address,
            faultingAddress,
            faultingModule,
            faultingSymbol,
            faulting.Instruction,
            Value(output, "CUSTOMER_CRASH_COUNT"),
            Value(output, "DEFAULT_BUCKET_ID"),
            registers,
            ParseStackOccurrences(output),
            memoryIndicators,
            invalidPointers,
            pointer.Text)
        {
            FaultEvidenceSource = string.IsNullOrWhiteSpace(faultingModule)
                ? FaultEvidenceSource.Unknown : FaultEvidenceSource.ExceptionAddressModuleRange,
            DisassemblyContext = string.Join(Environment.NewLine, output.Split('\n').Where(x => !string.IsNullOrEmpty(ParseInstructionLine(x.TrimEnd('\r')).Instruction))),
            CrashTime = ParseCrashTime(output),
            SymbolsIncomplete = Regex.IsMatch(output, "symbols are wrong|symbol file could not be found|unable to load image|wrong_symbols", RegexOptions.IgnoreCase)
        };
    }

    private static List<string> ParseArguments(string output)
    {
        var result = new List<string>();
        for (var i = 1; i <= 4; i++)
        {
            var match = Regex.Match(output, $@"(?im)^\s*(?:Arg{i}|BUGCHECK_P{i})\s*:\s*([^\r\n]+)");
            result.Add(match.Success ? ExtractAddressToken(match.Groups[1].Value) : "");
        }
        return result.All(string.IsNullOrEmpty) ? [] : result;
    }

    private static AccessData ParseExceptionAccess(string output, string readAddress, string writeAddress)
    {
        if (!string.IsNullOrWhiteSpace(writeAddress)) return new AccessData("Write", writeAddress);
        if (!string.IsNullOrWhiteSpace(readAddress)) return new AccessData("Read", readAddress);
        var p0 = Regex.Match(output, @"(?im)^\s*Parameter\[0\]\s*:\s*([0-9a-fx`]+)").Groups[1].Value;
        var p1 = Regex.Match(output, @"(?im)^\s*Parameter\[1\]\s*:\s*([0-9a-fx`]+)").Groups[1].Value;
        if (!BugCheckKnowledgeBase.TryParseHex(p0, out var operation)) return new AccessData("", "");
        var type = operation switch { 0 => "Read", 1 => "Write", 8 => "Execute", _ => "" };
        return new AccessData(type, NormalizeOptionalAddress(p1));
    }

    private static FaultingData ParseFaultingInstruction(string output, string targetAddress)
    {
        if (!BugCheckKnowledgeBase.TryParseHex(targetAddress, out var target) || target == 0) return new("", "", "", "");
        var lines = output.Replace("\r", "").Split('\n');
        foreach (var marker in new[] { "ITCHY_CONTEXT_DISASSEMBLY", "FAULTING_IP", "ITCHY_DISASSEMBLY" })
        {
            for (var i = 0; i < lines.Length; i++)
            {
                if (!lines[i].Trim().Equals(marker, StringComparison.OrdinalIgnoreCase) &&
                    !lines[i].Trim().Equals(marker + ":", StringComparison.OrdinalIgnoreCase)) continue;
                var pendingModule = "";
                var pendingSymbol = "";
                for (var j = i + 1; j < Math.Min(lines.Length, i + 70); j++)
                {
                    if (lines[j].TrimStart().StartsWith("ITCHY_", StringComparison.Ordinal) || Regex.IsMatch(lines[j], @"^\s*[A-Z_]{3,}:")) break;
                    var symbolHeader = Regex.Match(lines[j], @"(?i)^\s*([a-z][a-z0-9_.-]*)(?:!([^\s:]+)|\+([^\s:]+)):?\s*$");
                    if (symbolHeader.Success)
                    {
                        pendingModule = NormalizeModule(symbolHeader.Groups[1].Value);
                        pendingSymbol = symbolHeader.Groups[2].Success
                            ? symbolHeader.Groups[2].Value
                            : "+" + symbolHeader.Groups[3].Value;
                        continue;
                    }
                    var parsed = ParseInstructionLine(lines[j]);
                    if (!string.IsNullOrWhiteSpace(parsed.Instruction) &&
                        BugCheckKnowledgeBase.TryParseHex(parsed.Address, out var address) && address == target)
                    {
                        return parsed with
                        {
                            Module = string.IsNullOrWhiteSpace(parsed.Module) ? pendingModule : parsed.Module,
                            Symbol = string.IsNullOrWhiteSpace(parsed.Symbol) ? pendingSymbol : parsed.Symbol
                        };
                    }
                }
            }
        }

        return new FaultingData("", "", "", "");
    }

    private static FaultingData ParseInstructionLine(string line)
    {
        var match = Regex.Match(line, @"(?i)^\s*([0-9a-f`]{8,17})\s+(?:(\w[\w.-]*)(?:!|\+)([^\s:]+):?\s+)?(?:[0-9a-f]{2,32}\s+)+(.+)$");
        if (!match.Success) return new FaultingData("", "", "", "");
        var instruction = match.Groups[4].Value.Trim();
        if (instruction.StartsWith("***", StringComparison.Ordinal) || instruction.Contains("Unable to", StringComparison.OrdinalIgnoreCase)) return new FaultingData("", "", "", "");
        return new FaultingData(
            BugCheckKnowledgeBase.NormalizeAddress(match.Groups[1].Value),
            NormalizeModule(match.Groups[2].Value),
            match.Groups[3].Value.Trim(),
            instruction);
    }

    private static IReadOnlyDictionary<string, string> ParseRegisters(string output, string faultAddress)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        // A register bank must belong to the exception IP, never KeBugCheckEx or a failed .cxr.
        var blocks = Regex.Matches(output, @"(?im)(?:^[ \t]*(?:(?:r(?:ax|bx|cx|dx|si|di|sp|bp|ip|[89]|1[0-5])|[a-z]{2,6})=[0-9a-f`]+[ \t]*)+\r?\n?)+");
        var block = blocks.Cast<Match>().LastOrDefault(x =>
        {
            var ip = Regex.Match(x.Value, @"(?i)\brip=([0-9a-f`]+)");
            return ip.Success && BugCheckKnowledgeBase.TryParseHex(ip.Groups[1].Value, out var value) &&
                BugCheckKnowledgeBase.TryParseHex(faultAddress, out var expected) && value == expected;
        });
        if (block is null) return result;
        foreach (var name in RegisterNames)
        {
            var matches = Regex.Matches(block.Value, $@"(?i)(?<![a-z0-9]){name}=([0-9a-f`]+)");
            if (matches.Count > 0) result[name.ToUpperInvariant()] = BugCheckKnowledgeBase.NormalizeAddress(matches[^1].Groups[1].Value);
        }
        return result;
    }

    private static PointerData AnalyzePointer(string instruction, IReadOnlyDictionary<string, string> registers)
    {
        if (string.IsNullOrWhiteSpace(instruction) || registers.Count == 0) return new PointerData("", "", "");
        var operand = Regex.Match(instruction, @"(?i)\[\s*(r(?:ax|bx|cx|dx|si|di|sp|bp|8|9|10|11|12|13|14|15))(?:\s*([+-])\s*(?:0x)?([0-9a-f]+)h?)?\s*\]");
        if (!operand.Success || Regex.Matches(instruction, @"\[").Count != 1 || Regex.IsMatch(instruction, @"(?i)\b(?:lea|gs:|fs:)"))
            return new PointerData("Adresleme ifadesi desteklenmiyor; etkin pointer hesaplanmadı.", "", "");
        var register = operand.Groups[1].Value.ToUpperInvariant();
        if (!registers.TryGetValue(register, out var value) || !BugCheckKnowledgeBase.TryParseHex(value, out var baseValue)) return new PointerData("", "", "");
        var effective = baseValue;
        if (operand.Groups[3].Success && ulong.TryParse(operand.Groups[3].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var offset))
        {
            effective = operand.Groups[2].Value == "-" ? baseValue - offset : baseValue + offset;
        }
        var effectiveText = $"0x{effective:X16}";
        var invalidReason = InvalidPointerReason(effective);
        var text = string.IsNullOrWhiteSpace(invalidReason)
            ? $"Faulting instruction {register} ({value}) tabanli {effectiveText} adresini kullaniyor; adres tek basina gecersiz olarak kanitlanamadi."
            : $"Faulting instruction {register} ({value}) tabanli {effectiveText} adresine erisiyor. {invalidReason}";
        return new PointerData(text, effectiveText, invalidReason);
    }

    private static IReadOnlyList<string> BuildInvalidPointerIndicators(string attemptedAddress, PointerData pointer)
    {
        var result = new List<string>();
        if (BugCheckKnowledgeBase.TryParseHex(attemptedAddress, out var attempted))
        {
            var reason = InvalidPointerReason(attempted);
            if (!string.IsNullOrWhiteSpace(reason)) result.Add($"Attempted address {BugCheckKnowledgeBase.NormalizeAddress(attemptedAddress)}: {reason}");
        }
        if (!string.IsNullOrWhiteSpace(pointer.InvalidReason)) result.Add($"Effective address {pointer.EffectiveAddress}: {pointer.InvalidReason}");
        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static IReadOnlyList<string> BuildMemoryIndicators(string output, string bugCode, string exceptionCode, IReadOnlyList<string> invalidPointers)
    {
        var result = new List<string>();
        if (exceptionCode.Equals("0xC0000005", StringComparison.OrdinalIgnoreCase)) result.Add("0xC0000005 Access Violation");
        if (output.Contains("memory_corruption", StringComparison.OrdinalIgnoreCase)) result.Add("WinDbg memory_corruption isareti");
        if (BugCheckKnowledgeBase.IsMemoryBugCheck(bugCode)) result.Add($"{bugCode} bellek bozulmasi ailesi");
        result.AddRange(invalidPointers);
        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static string InvalidPointerReason(ulong value)
    {
        if (value <= 0x1000) return "Null veya null'a yakin pointer deseni.";
        if (value == ulong.MaxValue || value >= 0xFFFFFFFFFFFFF000) return "Tum bitleri bir veya sinir disi kernel pointer deseni.";
        const ulong userCanonicalMax = 0x00007FFFFFFFFFFF;
        const ulong kernelCanonicalMin = 0xFFFF800000000000;
        if (value > userCanonicalMax && value < kernelCanonicalMin) return "x64 canonical adres araligi disinda.";
        return "";
    }

    private static IReadOnlyDictionary<string, int> ParseStackOccurrences(string output)
    {
        var source = ExtractPrimaryStackText(output);
        var result = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in Regex.Matches(source, @"(?i)\b([a-z][a-z0-9_.-]{1,80})(?:!|\+0x[0-9a-f]+)"))
        {
            var module = NormalizeModule(match.Groups[1].Value);
            if (string.IsNullOrWhiteSpace(module)) continue;
            result[module] = result.GetValueOrDefault(module) + 1;
        }
        return result;
    }

    private static string ExtractPrimaryStackText(string output)
    {
        var sections = Regex.Matches(output, @"(?ims)^\s*STACK_TEXT:\s*(.*?)(?=^\s*[A-Z][A-Z0-9_ ]{2,}:|^\s*STACK_COMMAND:|\z)")
            .Select(x => x.Groups[1].Value)
            .ToList();
        sections.AddRange(Regex.Matches(output, @"(?ims)ITCHY_CONTEXT_STACK\s*(.*?)(?=ITCHY_CONTEXT_DISASSEMBLY|\z)")
            .Select(x => x.Groups[1].Value));
        return sections.OrderByDescending(x => Regex.Matches(x, @"\w+!").Count).FirstOrDefault()?.Trim() ?? "";
    }

    private static string DescribeException(string code) => code.ToUpperInvariant() switch
    {
        "0XC0000005" => "Access Violation",
        "0XC000001D" => "Illegal Instruction",
        "0XC0000094" => "Integer Divide By Zero",
        "0XC0000096" => "Privileged Instruction",
        "0X80000003" => "Breakpoint",
        _ => ""
    };

    private static string Value(string output, string key)
    {
        var match = Regex.Match(output, $@"(?im)^[ \t]*{Regex.Escape(key)}[ \t]*:[ \t]*([^\r\n]*)");
        return match.Success ? match.Groups[1].Value.Trim() : "";
    }

    private static string ExtractHex(string value, int width)
    {
        var match = Regex.Match(value ?? "", @"(?i)(?:0x)?([0-9a-f]{6,16})");
        if (!match.Success || !ulong.TryParse(match.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var parsed)) return "";
        return $"0x{parsed.ToString($"X{width}", CultureInfo.InvariantCulture)}";
    }

    private static string NormalizeOptionalAddress(string value)
    {
        var token = ExtractAddressToken(value);
        return BugCheckKnowledgeBase.TryParseHex(token, out _) ? BugCheckKnowledgeBase.NormalizeAddress(token) : "";
    }

    private static string AddressFromField(string value) => NormalizeOptionalAddress(value);

    private static string ExtractAddressToken(string value)
    {
        var match = Regex.Match(value ?? "", @"(?i)^\s*(?:0x)?[0-9a-f`]{1,17}(?=\s|,|$)");
        return match.Success ? match.Value : "";
    }

    private static string NormalizeModule(string value)
    {
        var token = Regex.Match(value ?? "", @"(?i)\b[a-z0-9_.-]+(?:\.sys|\.dll|\.exe)?\b").Value;
        return token.Trim();
    }

    private static string ModuleFromSymbol(string symbol)
    {
        var match = Regex.Match(symbol ?? "", @"(?i)^([^!+\s]+)[!+]");
        return match.Success ? NormalizeModule(match.Groups[1].Value) : "";
    }

    private static string FirstNonEmpty(params string[] values) => values.FirstOrDefault(x => !string.IsNullOrWhiteSpace(x)) ?? "";

    private static string ModuleAtAddress(string output, string address)
    {
        if (!BugCheckKnowledgeBase.TryParseHex(address, out var ip) || ip == 0) return "";
        foreach (Match m in Regex.Matches(output, @"(?im)^\s*([0-9a-f`]{8,17})\s+([0-9a-f`]{8,17})\s+([a-z][\w.-]*)(?:\s|$)"))
        {
            if (BugCheckKnowledgeBase.TryParseHex(m.Groups[1].Value, out var start) &&
                BugCheckKnowledgeBase.TryParseHex(m.Groups[2].Value, out var end) && start <= ip && ip < end)
                return m.Groups[3].Value;
        }
        return "";
    }

    public static DateTime? ParseCrashTime(string output)
    {
        var match = Regex.Match(output, @"(?im)^Debug session time:\s*(.+?)\s*\(UTC\s*([+-])\s*(\d+):(\d+)\)");
        if (!match.Success) return null;
        var timestamp = match.Groups[1].Value.Trim();
        if (!DateTime.TryParseExact(timestamp,
                ["ddd MMM d HH:mm:ss.FFFFFFF yyyy", "ddd MMM d HH:mm:ss yyyy"],
                CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var date)) return null;
        var offset = new TimeSpan(int.Parse(match.Groups[3].Value), int.Parse(match.Groups[4].Value), 0);
        if (match.Groups[2].Value == "-") offset = -offset;
        if (offset.Duration() > TimeSpan.FromHours(14)) return null;
        return new DateTimeOffset(DateTime.SpecifyKind(date, DateTimeKind.Unspecified), offset).LocalDateTime;
    }

    private sealed record AccessData(string Type, string Address);
    private sealed record FaultingData(string Address, string Module, string Symbol, string Instruction);
    private sealed record PointerData(string Text, string EffectiveAddress, string InvalidReason);
}
