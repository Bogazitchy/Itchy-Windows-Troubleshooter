using ItchyWindowsTroubleshooter.Models;
using ItchyWindowsTroubleshooter.Services;
using Xunit;

namespace ItchyWindowsTroubleshooter.Tests;

public sealed class DumpAnalysisEngineTests
{
    private readonly WinDbgOutputParser _parser = new();
    private readonly DriverClassificationService _drivers = new();
    private readonly DumpCorrelationService _correlation = new();

    [Fact]
    public void KmodeAccessViolation_WithDirectNvidiaFault_MakesGraphicsStrongCandidate()
    {
        var parsed = _parser.Parse("""
            KMODE_EXCEPTION_NOT_HANDLED (1e)
            Arg1: 00000000c0000005, The exception code
            Arg2: fffff80512345678, The address
            BUGCHECK_CODE: 1e
            EXCEPTION_CODE: (NTSTATUS) 0xc0000005 - Access violation
            Parameter[0]: 0000000000000000
            Parameter[1]: ffffffffffffffff
            PROCESS_NAME: opera.exe
            IMAGE_NAME: nvlddmkm.sys
            MODULE_NAME: nvlddmkm
            SYMBOL_NAME: nvlddmkm+dee2a0
            FAILURE_BUCKET_ID: AV_nvlddmkm!unknown_function
            FAILURE_ID_HASH: {TEST-NVIDIA-HASH}
            r11=ffffffffffffffff rip=fffff80512345678
            FAULTING_IP:
            fffff805`12345678 4d3973e0 cmp qword ptr [r11-20h],r14
            STACK_TEXT:
            ffff9000`00000000 fffff805`12345678 : nvlddmkm+0xdee2a0
            STACK_COMMAND: .cxr; kb
            """);

        var evidence = _drivers.BuildEvidence(parsed);
        var dump = CreateDump("gpu.dmp", "0x1E", "KMODE_EXCEPTION_NOT_HANDLED", "opera.exe") with
        {
            ExceptionCode = parsed.ExceptionCode,
            ExceptionName = parsed.ExceptionName,
            FaultingModule = parsed.FaultingModule,
            FaultingInstruction = parsed.FaultingInstruction,
            ImportantThirdPartyDrivers = evidence,
            MemoryCorruptionIndicators = parsed.MemoryCorruptionIndicators
        };
        var result = _correlation.Analyze([dump], []);

        Assert.Equal("0xC0000005", parsed.ExceptionCode);
        Assert.Equal("Access Violation", parsed.ExceptionName);
        Assert.Equal("Read", parsed.AccessType);
        Assert.Equal("0xFFFFFFFFFFFFFFFF", parsed.AttemptedAddress);
        Assert.NotEmpty(parsed.InvalidPointerIndicators);
        Assert.Equal("{TEST-NVIDIA-HASH}", parsed.FailureIdHash);
        Assert.Contains(evidence, x => x.DriverName.Equals("nvlddmkm.sys", StringComparison.OrdinalIgnoreCase) && x.DirectFault);
        Assert.Equal(RootCauseCategory.GraphicsDriver, result.Candidates[0].Category);
        Assert.Contains(result.Candidates[0].Strength, new[] { "Guclu", "Cok guclu" });
    }

    [Fact]
    public void SystemServiceException_KernelFaultWithVanguardStack_DoesNotBlameKernelOrVanguardDirectly()
    {
        var parsed = _parser.Parse("""
            SYSTEM_SERVICE_EXCEPTION (3b)
            Arg1: 00000000c0000005
            Arg2: fffff80011112222
            Arg3: ffff900012345678
            BUGCHECK_CODE: 3b
            EXCEPTION_CODE: (NTSTATUS) 0xc0000005
            PROCESS_NAME: Discord.exe
            IMAGE_NAME: ntoskrnl.exe
            MODULE_NAME: nt
            SYMBOL_NAME: nt!KiSystemServiceExit
            FAULTING_IP:
            fffff800`11112222 488b4708 mov rax,qword ptr [rdi+8]
            STACK_TEXT:
            ffff9000`00000000 fffff800`11112222 : nt!KiSystemServiceExit+0x10
            ffff9000`00000010 fffff805`22223333 : vgk+0x1234
            ffff9000`00000020 fffff805`22224444 : vgk+0x4567
            STACK_COMMAND: .cxr; kb
            """);

        var evidence = _drivers.BuildEvidence(parsed);

        Assert.Equal("0xFFFF900012345678", BugCheckKnowledgeBase.TryGetContextRecord("0x3B", ["c0000005", "fffff80011112222", "ffff900012345678"], ""));

        Assert.DoesNotContain(evidence, x => x.DriverName.Contains("ntoskrnl", StringComparison.OrdinalIgnoreCase));
        var vanguard = Assert.Single(evidence, x => x.DriverName.Equals("vgk.sys", StringComparison.OrdinalIgnoreCase));
        Assert.False(vanguard.DirectFault);
        Assert.False(vanguard.ProbablyCausedBy);
        Assert.Equal(2, vanguard.StackOccurrences);
    }

    [Fact]
    public void FourRelatedDumps_ProduceGraphicsThenConflictAndMemoryCandidates()
    {
        var nv = new StackDriverEvidence("nvlddmkm.sys", "NVIDIA Display Driver", "Graphics", 2, true, false, true, true, true, "");
        var vgk = new StackDriverEvidence("vgk.sys", "Riot Vanguard", "Security/AntiCheat", 5, false, false, false, false, true, "");
        var sonar = new StackDriverEvidence("SteelSeries-Sonar-VAD.sys", "SteelSeries Sonar Virtual Audio", "VirtualAudio", 2, false, false, false, false, true, "");
        var dumps = new[]
        {
            CreateDump("1.dmp", "0x3B", "SYSTEM_SERVICE_EXCEPTION", "Discord.exe") with { ExceptionCode = "0xC0000005", ExceptionName = "Access Violation", ImportantThirdPartyDrivers = [vgk], MemoryCorruptionIndicators = ["0xC0000005 Access Violation"] },
            CreateDump("2.dmp", "0x1E", "KMODE_EXCEPTION_NOT_HANDLED", "opera.exe") with { ExceptionCode = "0xC0000005", ExceptionName = "Access Violation", FaultingModule = "nvlddmkm.sys", ImportantThirdPartyDrivers = [nv], MemoryCorruptionIndicators = ["0xC0000005 Access Violation"] },
            CreateDump("3.dmp", "0x1E", "KMODE_EXCEPTION_NOT_HANDLED", "SteelSeriesEngine.exe") with { ExceptionCode = "0xC0000005", ExceptionName = "Access Violation", ImportantThirdPartyDrivers = [sonar], MemoryCorruptionIndicators = ["0xC0000005 Access Violation"] },
            CreateDump("4.dmp", "0x1E", "KMODE_EXCEPTION_NOT_HANDLED", "bf6.exe") with { ExceptionCode = "0xC0000005", ExceptionName = "Access Violation", MemoryCorruptionIndicators = ["0xC0000005 Access Violation"] }
        };

        var result = _correlation.Analyze(dumps, []);

        Assert.Equal(RootCauseCategory.GraphicsDriver, result.Candidates[0].Category);
        Assert.Contains(result.Candidates, x => x.Category == RootCauseCategory.KernelDriverConflict);
        Assert.Contains(result.Candidates, x => x.Category == RootCauseCategory.MemoryInstability);
        Assert.Contains("4/4", result.CommonPattern);
        Assert.Contains("farkli kullanici", result.CommonPattern, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void KernelPower41Alone_DoesNotCreateRootCauseCandidate()
    {
        var events = new[]
        {
            new EventRecordItem(DateTime.Now, "System", "Microsoft-Windows-Kernel-Power", 41, "Critical", "Sistem beklenmedik sekilde kapandi.")
        };

        var result = _correlation.Analyze([], events);

        Assert.Empty(result.Candidates);
        Assert.Equal(CrossDumpAnalysisResult.Empty, result);
    }

    private static DumpAnalysisItem CreateDump(string fileName, string code, string name, string process) => new(
        fileName,
        fileName,
        DateTime.Now,
        "1 MB",
        "Gecerli",
        "Tamamlandi",
        code,
        name,
        "",
        "ntoskrnl.exe",
        "Microsoft Windows Kernel",
        process,
        "",
        "Orta",
        "Kernel cokme noktasi tek basina kok neden degildir.",
        "Sentetik debugger kaniti",
        "Eslesen olay yok",
        "Kanita gore test edin.",
        "Test debugger",
        "Sentetik WinDbg ciktisi");
}
