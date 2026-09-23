using System.Diagnostics;
using System.IO;
using System.Text;
using ItchyWindowsTroubleshooter.Models;
using ItchyWindowsTroubleshooter.Services;
using Xunit;

namespace ItchyWindowsTroubleshooter.Tests;

public sealed class EvidenceSafetyTests
{
    private static DumpAnalysisItem Dump(string name = "test.dmp") =>
        new(name, name, DateTime.Now, "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "");

    [Theory]
    [InlineData("MODULE_NAME: nvlddmkm")]
    [InlineData("IMAGE_NAME: nvlddmkm.sys")]
    [InlineData("SYMBOL_NAME: nvlddmkm+1234")]
    public void ModuleHintsAreNotDirectFaults(string output)
    {
        var parsed = new WinDbgOutputParser().Parse(output);
        Assert.Empty(parsed.FaultingModule);
        Assert.Equal(FaultEvidenceSource.Unknown, parsed.FaultEvidenceSource);
        var evidence = new DriverClassificationService().BuildEvidence(parsed);
        Assert.DoesNotContain(evidence, x => x.DirectFault);
        var result = new DumpCorrelationService().Analyze([Dump() with { ImportantThirdPartyDrivers = evidence }], []);
        Assert.DoesNotContain(result.TroubleshootingSteps, x => x.Contains("DDU"));
        Assert.DoesNotContain(result.Candidates, x => x.EvidenceScore >= 65);
    }

    [Fact]
    public void DisassemblySelectsExactExceptionAddress_NotFirstInstruction()
    {
        var parsed = new WinDbgOutputParser().Parse("""
            BUGCHECK_CODE: 3b
            Arg1: c0000005
            Arg2: fffff80512345678
            Arg3: ffff900011112222
            ITCHY_CONTEXT_DISASSEMBLY
            fffff805`12345658 488b00 mov rax,qword ptr [rax]
            fffff805`12345678 488b4708 mov rax,qword ptr [rdi+8]
            ITCHY_INSTRUCTION_CONTEXT
            """);
        Assert.Equal("mov rax,qword ptr [rdi+8]", parsed.FaultingInstruction);
        Assert.Contains("12345658", parsed.DisassemblyContext);
        Assert.Empty(parsed.FaultingModule); // No module range, even though instruction is available.
    }

    [Theory]
    [InlineData("fffff80512345677")]
    [InlineData("fffff80512345679")]
    public void NoAssemblyAtExceptionAddress_DoesNotGuess(string address)
    {
        var parsed = new WinDbgOutputParser().Parse($"""
            BUGCHECK_CODE: 3b
            Arg2: fffff80512345678
            FAULTING_IP:
            {address} 488b00 mov rax,qword ptr [rax]
            """);
        Assert.Empty(parsed.FaultingInstruction);
    }

    [Fact]
    public void ComplexOperandDoesNotProduceGuessedPointer()
    {
        var parsed = new WinDbgOutputParser().Parse("""
            BUGCHECK_CODE: 3b
            Arg2: fffff80512345678
            rdi=ffffffffffffffff rcx=0000000000000002 rip=fffff80512345678
            FAULTING_IP:
            fffff805`12345678 488b440f08 mov rax,qword ptr [rdi+rcx*8+8]
            """);
        Assert.NotEmpty(parsed.Registers);
        Assert.Contains("desteklenmiyor", parsed.PointerAnalysis);
        Assert.Empty(parsed.InvalidPointerIndicators);
    }

    [Fact]
    public void MismatchingContextDoesNotSupplyRegisters()
    {
        var parsed = new WinDbgOutputParser().Parse("""
            BUGCHECK_CODE: 3b
            Arg2: fffff80512345678
            rdi=ffffffffffffffff rip=fffff80599999999
            FAULTING_IP:
            fffff805`12345678 488b4708 mov rax,qword ptr [rdi+8]
            """);
        Assert.Empty(parsed.Registers);
        Assert.Empty(parsed.PointerAnalysis);
    }

    [Fact]
    public void MissingParameterDoesNotShiftBugcheckSemantics()
    {
        var parsed = new WinDbgOutputParser().Parse("BUGCHECK_CODE: 3b\nArg3: ffff900012345678");
        Assert.Equal("", parsed.BugCheckArguments[0]);
        Assert.Equal("", parsed.FaultingAddress);
        Assert.Equal("0xFFFF900012345678", BugCheckKnowledgeBase.TryGetContextRecord("0x3B", parsed.BugCheckArguments, ""));
        Assert.Equal("", BugCheckKnowledgeBase.TryGetContextRecord("0xD1", parsed.BugCheckArguments, "ffff900012345678"));
    }

    [Fact]
    public void RepeatedWeakStackEvidenceIsCapped()
    {
        var driver = new StackDriverEvidence("nvlddmkm.sys", "NVIDIA", "Graphics", 3, false, false, false, false, true, "");
        var dumps = Enumerable.Range(0, 10).Select(i => Dump($"{i}.dmp") with { ImportantThirdPartyDrivers = [driver] }).ToList();
        var result = new DumpCorrelationService().Analyze(dumps, []);
        Assert.DoesNotContain(result.Candidates, x => x.Category == RootCauseCategory.GraphicsDriver);
        Assert.DoesNotContain(result.TroubleshootingSteps, x => x.Contains("DDU"));
    }

    [Fact]
    public void MissingSymbolsReduceDirectFaultStrengthAndDoNotOfferDdu()
    {
        var parsed = new WinDbgOutputParser().Parse("""
            BUGCHECK_CODE: 3b
            Arg2: fffff80512345678
            MODULE_NAME: nvlddmkm
            fffff805`12000000 fffff805`13000000 nvlddmkm
            *** ERROR: Symbol file could not be found.
            """);
        Assert.True(parsed.SymbolsIncomplete);
        var result = new DumpCorrelationService().Analyze([Dump() with
        {
            SymbolsIncomplete = parsed.SymbolsIncomplete,
            ImportantThirdPartyDrivers = new DriverClassificationService().BuildEvidence(parsed)
        }], []);
        Assert.All(result.Candidates, x => Assert.True(x.EvidenceScore < 65));
        Assert.DoesNotContain(result.TroubleshootingSteps, x => x.Contains("DDU"));
    }

    [Fact]
    public void DriverAliasesAreCountedOnce()
    {
        var parsed = new WinDbgOutputParser().Parse("IMAGE_NAME: nvlddmkm.sys\nMODULE_NAME: nvlddmkm");
        Assert.Single(new DriverClassificationService().BuildEvidence(parsed));
    }

    [Fact]
    public void RepeatedEventsAreNotIndependentEvidence()
    {
        var dump = Dump();
        var item = new EventRecordItem(dump.CreatedAt, "System", "Display", 4101, "Warning", "timeout");
        var one = new DumpCorrelationService().Analyze([dump], [item]);
        var many = new DumpCorrelationService().Analyze([dump], Enumerable.Repeat(item, 100).ToList());
        Assert.Equal(one.Candidates.Count, many.Candidates.Count);
        Assert.Empty(many.Candidates);
    }

    [Fact]
    public void UnknownCrashTimeDoesNotCorrelateHostEvents()
    {
        var result = new DumpCorrelationService().Analyze([Dump() with { CreatedAt = null }],
            [new(DateTime.Now, "System", "WHEA-Logger", 18, "Error", "processor")]);
        Assert.Empty(result.Candidates);
        Assert.Null(WinDbgOutputParser.ParseCrashTime("File modified: today"));
    }

    [Fact]
    public void CrashTimestampUsesDebuggerTimezone()
    {
        var time = WinDbgOutputParser.ParseCrashTime("Debug session time: Wed Sep 23 12:34:56.000 2026 (UTC + 3:00)");
        Assert.NotNull(time);
        Assert.Equal(new DateTime(2026, 9, 23, 9, 34, 56, DateTimeKind.Utc), time.Value.ToUniversalTime());
    }

    [Fact]
    public async Task ExternalDumpDoesNotQueryHostEventsOrUseFileTimestamp()
    {
        var path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "synthetic invalid dump");
            var before = await File.ReadAllBytesAsync(path);
            var runner = new FakeRunner(new("", 0, "", true));
            var service = new SystemAnalysisService(runner, _ => Task.CompletedTask);
            var result = await service.AnalyzeSelectedDumpsAsync([path], CancellationToken.None);
            var dump = Assert.Single(result.DumpAnalyses);
            Assert.Null(dump.CreatedAt);
            Assert.Equal(AnalysisMode.ExternalCase, dump.AnalysisMode);
            Assert.DoesNotContain(runner.Scripts, x => x.Contains("Get-WinEvent"));
            Assert.Equal(before, await File.ReadAllBytesAsync(path));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void ResourceNullsAreNotZeroOrNormal()
    {
        var result = ResourceAnalysisService.Parse("""{"CpuAverage":null,"MemoryAverage":null,"DiskAverage":null,"SampleCounts":{"Cpu":0,"Memory":0,"Disk":0}}""");
        Assert.True(double.IsNaN(result.CpuAverage));
        Assert.All(result.Metrics, x => Assert.NotEqual("Normal", x.Status));
        Assert.All(result.Metrics, x => Assert.NotEqual(DataAvailability.Read, x.Availability));
    }

    [Fact]
    public void PartialResourceSamplesRemainPartial()
    {
        var result = ResourceAnalysisService.Parse("""{"CpuAverage":12,"CpuPeak":15,"SampleCounts":{"Cpu":2}}""");
        Assert.Equal(DataAvailability.Partial, result.Metrics[0].Availability);
        Assert.Equal("Kısmi", result.Metrics[0].Status);
    }

    [Theory]
    [InlineData("The operation completed successfully.", "Yorumlanamadi")]
    [InlineData("No component store corruption detected.", "Normal")]
    [InlineData("The component store is repairable.", "Uyari")]
    [InlineData("The component store cannot be repaired.", "Uyari")]
    public void DismRequiresRecognizedHealthStatement(string output, string status)
        => Assert.Equal(status, SystemHealthAnalysisService.BuildDismCheck(new("", 0, output, true)).Status);

    [Fact]
    public void EventCoverageRetainsIndividualFailureAndTruncation()
    {
        var result = EventCollectionService.Parse(new("", 0, """
            {"Events":[],"Coverage":[{"Source":"System","Status":"Kismi","RecordCount":180,"Detail":"limit"},{"Source":"Setup","Status":"Erisilemedi","RecordCount":0,"Detail":"denied"}]}
            """, true));
        Assert.Equal(2, result.Coverage.Count);
        Assert.Contains(result.Coverage, x => x.Status == "Kismi");
        Assert.Contains(result.Coverage, x => x.Status == "Erisilemedi");
    }

    [Theory]
    [InlineData("Succeeded", false, 0, RepairOutcome.Failed)]
    [InlineData("Succeeded", true, 1, RepairOutcome.Failed)]
    [InlineData("Partial", false, 2, RepairOutcome.PartiallySucceeded)]
    [InlineData("RestartRequired", true, 0, RepairOutcome.RestartRequired)]
    public void RepairOutcomeCannotHideFailedSteps(string status, bool step, int code, RepairOutcome expected)
    {
        var json = $$"""{"ItchyRepair":true,"Status":"{{status}}","Steps":[{"Name":"test","Success":{{step.ToString().ToLowerInvariant()}}}]}""";
        Assert.Equal(expected, RepairOutcomeParser.Parse(new("", code, json, code == 0)));
    }

    [Fact]
    public void ExitZeroWithoutPostconditionIsUnverified()
        => Assert.Equal(RepairOutcome.Unverified, RepairOutcomeParser.Parse(new("", 0, "completed", true)));

    [Fact]
    public async Task FailedUpdateResetIsNotSuccessful()
    {
        var runner = new FakeRunner(new("", 2, """{"ItchyRepair":true,"Status":"Partial","Steps":[{"Success":false}]}""", false));
        var result = await new RepairService(runner).RunAsync("wu-reset", CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal(RepairOutcome.PartiallySucceeded, result.Outcome);
        Assert.Equal(CommandCancellationPolicy.WaitForCompletion, runner.Policy);
    }

    [Fact]
    public void DiskRepairHasNoFixedConfirmationAndValidatesTarget()
    {
        Assert.Throws<ArgumentException>(() => RepairScripts.Disk("C:;bad", true, false));
        var script = RepairScripts.Disk("D:", true, false);
        Assert.Contains("DriveLetter='D:'", script);
        Assert.Contains("RecoverBadSectors=$false", script);
        Assert.Contains("ReturnValue -eq 1", script);
        Assert.DoesNotContain("echo Y", script);
    }

    internal sealed class FakeRunner(CommandResult result) : ICommandRunner
    {
        public List<string> Scripts { get; } = [];
        public CommandCancellationPolicy Policy { get; private set; }
        public Task<CommandResult> RunPowerShellAsync(string script, CancellationToken cancellationToken, bool streamOutput = true,
            string? displayCommand = null, TimeSpan? timeout = null, CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree)
        { Scripts.Add(script); Policy = policy; return Task.FromResult(result); }
        public Task<CommandResult> RunCmdAsync(string command, CancellationToken cancellationToken, CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree)
        { Scripts.Add(command); Policy = policy; return Task.FromResult(result); }
        public Task<CommandResult> RunExecutableAsync(string fileName, string arguments, string displayCommand,
            CancellationToken cancellationToken, TimeSpan timeout, bool streamOutput = false, CommandCancellationPolicy policy = CommandCancellationPolicy.StopProcessTree)
        { Scripts.Add(arguments); Policy = policy; return Task.FromResult(result); }
    }
}

