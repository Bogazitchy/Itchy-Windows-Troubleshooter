using System.IO;
using System.Net;
using System.Text;
using ItchyWindowsTroubleshooter.Models;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class ReportService
{
    public async Task<ReportResult> CreateReportAsync(ReportSnapshot snapshot, CancellationToken cancellationToken)
    {
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "ITCHY Windows Throbleshooting", "Reports");
        Directory.CreateDirectory(dir);
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        var htmlPath = Path.Combine(dir, $"ITCHY-Windows-Troubleshooter-{stamp}.html");
        var textPath = Path.Combine(dir, $"ITCHY-Windows-Troubleshooter-{stamp}.txt");

        await File.WriteAllTextAsync(htmlPath, BuildHtml(snapshot), Encoding.UTF8, cancellationToken);
        await File.WriteAllTextAsync(textPath, BuildText(snapshot), Encoding.UTF8, cancellationToken);
        return new ReportResult(htmlPath, textPath);
    }

    private static string BuildHtml(ReportSnapshot s)
    {
        var html = new StringBuilder();
        html.AppendLine("""
            <!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
            <title>ITCHY Windows Troubleshooter Raporu</title>
            <style>
            :root{color-scheme:dark;--bg:#0b1118;--panel:#121d29;--panel2:#172536;--line:#2a3d52;--text:#edf5fc;--muted:#9fb2c6;--blue:#43a7f5;--cyan:#53d3ca;--red:#ff7481;--amber:#ffc466;--green:#65d99b}
            *{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);margin:0;line-height:1.5}button,input{font:inherit}
            .wrap{max-width:1500px;margin:auto;padding:24px}.hero{border-bottom:1px solid var(--line);padding:8px 0 22px}.brand{color:var(--blue);font-size:13px;font-weight:800;letter-spacing:.08em;text-transform:uppercase}.hero h1{font-size:30px;margin:3px 0 4px}.hero-meta{color:var(--muted);margin:0}
            .metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:18px 0}.metric{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:13px}.metric b{display:block;font-size:23px}.metric span{color:var(--muted);font-size:13px}
            .layout{display:grid;grid-template-columns:230px minmax(0,1fr);gap:18px;align-items:start}.sidebar{position:sticky;top:14px;background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:10px}.search{width:100%;background:#09121b;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:10px}.tab-button{width:100%;display:flex;align-items:center;justify-content:space-between;gap:8px;background:transparent;color:#c8d7e6;border:0;border-left:3px solid transparent;border-radius:4px;padding:10px;text-align:left;cursor:pointer}.tab-button:hover{background:#1b2b3d;color:#fff}.tab-button.active{background:#163651;border-left-color:var(--blue);color:#fff;font-weight:700}.tab-count{background:#26394d;color:#cfe5f8;border-radius:10px;padding:1px 7px;font-size:11px}.search-state{color:var(--muted);font-size:12px;padding:10px 7px 2px}
            .report-section{display:none;min-width:0}.report-section.active{display:block}.section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;border-bottom:1px solid var(--line);padding:2px 0 12px;margin-bottom:14px}.section-head h2{margin:0;font-size:23px}.section-head p{margin:0;color:var(--muted)}
            .card{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:16px;margin:0 0 12px}.card h3{margin:0 0 8px}.card p:last-child{margin-bottom:0}.summary-card{border-left:4px solid var(--blue)}.summary-card p{white-space:pre-line}.critical{color:var(--red)}.warning{color:var(--amber)}.info{color:var(--blue)}.success{color:var(--green)}.finding-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap}.finding-head h3{width:100%;margin-top:5px}.finding-meta{color:var(--muted);font-size:13px}.evidence-link{background:#173c57;color:#eef8ff;border:1px solid #346b8f;border-radius:5px;padding:7px 10px;cursor:pointer}.evidence-link:hover{background:#205477}.finding-actions{display:flex;justify-content:flex-end;margin-top:12px}
            .table-shell{border:1px solid var(--line);border-radius:7px;overflow:auto;max-height:70vh;margin:0 0 22px;background:var(--panel)}table{width:100%;border-collapse:collapse;font-size:13px}th{position:sticky;top:0;background:#203247;color:#fff;z-index:1}td,th{border-bottom:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top}tbody tr:nth-child(even){background:#142130}tbody tr:hover{background:#1d3247}.table-title{display:flex;align-items:center;justify-content:space-between;margin:20px 0 8px}.table-title h3{margin:0}.pill{color:var(--cyan);font-size:12px;border:1px solid #2d625f;border-radius:10px;padding:2px 8px}
            pre{white-space:pre-wrap;overflow:auto;background:#081018;border:1px solid var(--line);padding:12px;border-radius:7px;color:#dce8f5;max-height:70vh}details{margin-top:12px}summary{cursor:pointer;color:var(--blue);font-weight:600}.raw-block{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:12px;margin:12px 0}.raw-block>.table-title{margin-top:16px}.dump-grid{display:grid;grid-template-columns:180px minmax(0,1fr);gap:7px 14px}.label{color:var(--muted)}[hidden]{display:none!important}.empty{color:var(--muted);padding:18px;text-align:center}
            @media(max-width:900px){.wrap{padding:14px}.metrics{grid-template-columns:repeat(2,1fr)}.layout{grid-template-columns:1fr}.sidebar{position:static;display:grid;grid-template-columns:repeat(2,1fr);gap:5px}.search,.search-state{grid-column:1/-1}.dump-grid{grid-template-columns:1fr}.label{font-weight:700;margin-top:8px}}
            @media print{body{background:#fff;color:#111}.wrap{max-width:none;padding:0}.sidebar{display:none}.layout{display:block}.report-section{display:block!important;break-before:page}.report-section:first-child{break-before:auto}.card,.table-shell,pre{background:#fff;color:#111;border-color:#bbb;max-height:none;overflow:visible}th{position:static;background:#ddd;color:#111}.hero-meta,.section-head p,.label{color:#444}}
            </style></head><body><div class="wrap">
            """);
        html.AppendLine($"<header class='hero'><div class='brand'>ITCHY Diagnostics</div><h1>Windows Troubleshooter Raporu</h1><p class='hero-meta'>{E(DateTime.Now.ToString("dd.MM.yyyy HH:mm"))} | Sistem durumu: <b>{E(s.SystemStatus)}</b> | {E(s.HeaderSummary)}</p></header>");
        html.AppendLine("<div class='metrics'>");
        AppendMetric(html, s.Findings.Count(x => x.Severity == Severity.Critical).ToString(), "Kritik bulgu", "critical");
        AppendMetric(html, s.Findings.Count(x => x.Severity == Severity.Warning).ToString(), "Uyari", "warning");
        AppendMetric(html, s.DumpAnalyses.Count.ToString(), "Analiz edilen dump", "info");
        AppendMetric(html, s.Events.Count.ToString(), "Event Viewer kaydi", "success");
        html.AppendLine("</div><div class='layout'><nav class='sidebar' aria-label='Rapor bolumleri'>");
        html.AppendLine("<input id='reportSearch' class='search' type='search' placeholder='Aktif sekmede ara...' aria-label='Aktif sekmede ara'>");
        AppendTabButton(html, "overview", "Genel Bakis", 3, true);
        AppendTabButton(html, "findings", "Bulgular", s.Findings.Count, false);
        AppendTabButton(html, "bsod", "Mavi Ekran", s.DumpAnalyses.Count + s.BlueScreens.Count, false);
        AppendTabButton(html, "errors", "Hata Kayitlari", s.DiagnosticLogs.Count + s.Events.Count, false);
        AppendTabButton(html, "health", "Saglik ve Kapsam", s.HealthChecks.Count + s.ScanCoverage.Count, false);
        AppendTabButton(html, "reliability", "Guvenilirlik", s.ReliabilityRecords.Count, false);
        AppendTabButton(html, "system", "Sistem", s.SystemDetails.Count + s.Drivers.Count + s.ResourceMetrics.Count, false);
        AppendTabButton(html, "protection", "Koruma ve Onarim", s.RestorePoints.Count + s.RepairHistory.Count, false);
        AppendTabButton(html, "logs", "Ham Log", string.IsNullOrWhiteSpace(s.LogText) ? 0 : s.LogText.Split('\n').Length, false);
        html.AppendLine("<div id='searchState' class='search-state'>Sekme secin veya arama yapin.</div></nav><main>");

        BeginSection(html, "overview", "Genel Bakis", "Teknisyen icin en onemli sonuclar", true);
        html.AppendLine($"<article class='card summary-card' data-searchable><h3>Analiz Sonucu</h3><p>{E(s.AnalysisSummary)}</p></article>");
        html.AppendLine($"<article class='card' data-searchable><h3>Mavi Ekran Ozeti</h3><p>{E(s.BlueScreenSummary)}</p></article>");
        html.AppendLine($"<details class='raw-block'><summary>Sistem ozetini goster</summary><pre data-searchable>{E(s.SystemInfo)}</pre></details>");
        EndSection(html);

        BeginSection(html, "findings", "Oncelikli Bulgular", "Kritik ve uyari seviyesindeki ayiklanmis sonuclar");
        var rankedFindings = s.Findings
            .OrderBy(GetFindingReportPriority)
            .ThenByDescending(x => x.ConfidenceScore)
            .ThenBy(x => x.Severity)
            .ThenByDescending(x => x.LatestOccurrence)
            .ToList();
        foreach (var finding in rankedFindings.Take(3))
        {
            AppendFindingCard(html, finding);
        }
        if (rankedFindings.Count > 3)
        {
            html.AppendLine($"<details class='raw-block'><summary>Diger {rankedFindings.Count - 3} bulguyu goster</summary>");
            foreach (var finding in rankedFindings.Skip(3)) AppendFindingCard(html, finding);
            html.AppendLine("</details>");
        }
        if (rankedFindings.Count == 0) html.AppendLine("<div class='card empty'>Bulgu kaydi yok.</div>");
        EndSection(html);

        BeginSection(html, "bsod", "Mavi Ekran ve Dump", "Stop code, surucu, stack ve olay korelasyonu");
        AppendCrossDumpAnalysis(html, s.CrossDumpAnalysis);
        AppendTable(html, "Dump Karsilastirmasi",
            ["Dump", "Stop Code", "Exception", "Faulting Module", "Process", "Onemli Stack Suruculeri"],
            s.DumpAnalyses.Select(x => new[]
            {
                x.FileName,
                $"{x.BugCheckCode} {x.BugCheckName}".Trim(),
                x.ExceptionSummary,
                x.FaultingModule,
                x.ProcessName,
                x.ImportantThirdPartyDriversText
            }));
        AppendDumpAnalyses(html, s.DumpAnalyses);
        AppendTable(html, "Mavi Ekran Olay ve Dosya Sinyalleri", ["Zaman", "Baslik", "Ozet", "Teknik Detay"], s.BlueScreens.Select(x => new[] { x.TimeCreated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Title, x.Summary, x.TechnicalDetail }));
        EndSection(html);

        BeginSection(html, "errors", "Hata Kayitlari", "Ayiklanmis sorunlar ve ham Event Viewer verileri");
        var diagnosticGroups = GroupDiagnosticLogs(s.DiagnosticLogs);
        AppendTable(html, "Bilesene Gore Gruplanmis Hatalar", ["Son Kayit", "Kategori", "Bilesen", "Kaynak / Kod", "Tekrar", "Ornek Kanit"], diagnosticGroups.Select(x => new[] { x.Latest?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Category, x.Component, $"{x.Source} / {x.Code}", x.Count.ToString(), x.Sample }));
        html.AppendLine("<details class='raw-block'><summary>Ayiklanan tekil hata kayitlarini goster</summary>");
        AppendTable(html, "Ayiklanan Hata Kayitlari", ["Zaman", "Kategori", "Bilesen", "Kaynak", "Kod", "Ozet"], s.DiagnosticLogs.Select(x => new[] { x.TimeCreated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Category, x.Component, x.Source, x.Code, x.Summary }));
        html.AppendLine("</details><details class='raw-block'><summary>Ham Event Viewer kayitlarini goster</summary>");
        AppendTable(html, "Event Viewer Ozeti", ["Zaman", "Log", "Kaynak", "ID", "Mesaj"], s.Events.Select(x => new[] { x.TimeCreated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.LogName, x.Provider, x.Id.ToString(), x.Message }));
        html.AppendLine("</details>");
        EndSection(html);

        BeginSection(html, "health", "Saglik Denetimleri ve Tarama Kapsami", "Disk, bellek, dump, Windows sagligi ve okunabilen veri kaynaklari");
        AppendTable(html, "Sistem Saglik Denetimleri", ["Zaman", "Kategori", "Bilesen", "Durum", "Deger", "Kanit / Aciklama"], s.HealthChecks.Select(x => new[] { x.ObservedAt?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Category, x.Component, x.Status, x.Value, x.Detail }));
        AppendTable(html, "Tarama Kapsami", ["Veri Kaynagi", "Durum", "Kayit", "Kapsam Detayi"], s.ScanCoverage.Select(x => new[] { x.Source, x.Status, x.RecordCount.ToString(), x.Detail }));
        EndSection(html);

        BeginSection(html, "reliability", "Guvenilirlik Gecmisi", "Uygulama, guncelleme ve sistem kararliligi kayitlari");
        var reliabilityGroups = s.ReliabilityRecords
            .GroupBy(x => $"{x.SourceName}\u001f{x.ProductName}", StringComparer.OrdinalIgnoreCase)
            .Select(x => new { Item = x.OrderByDescending(y => y.TimeGenerated).First(), Count = x.Count(), Latest = x.Max(y => y.TimeGenerated) })
            .OrderByDescending(x => x.Count)
            .ThenByDescending(x => x.Latest)
            .ToList();
        AppendTable(html, "Urun ve Kaynaga Gore Gruplanmis Kayitlar", ["Son Kayit", "Kaynak", "Urun", "Tekrar", "Ornek Mesaj"], reliabilityGroups.Select(x => new[] { x.Latest?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Item.SourceName, x.Item.ProductName, x.Count.ToString(), x.Item.Message }));
        html.AppendLine("<details class='raw-block'><summary>Tum Reliability Monitor kayitlarini goster</summary>");
        AppendTable(html, "Reliability Monitor Ozeti", ["Zaman", "Kaynak", "Urun", "Mesaj"], s.ReliabilityRecords.Select(x => new[] { x.TimeGenerated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.SourceName, x.ProductName, x.Message }));
        html.AppendLine("</details>");
        EndSection(html);

        BeginSection(html, "system", "Sistem ve Suruculer", "Donanim envanteri, surumler ve kaynak kullanimi");
        AppendTable(html, "Sistem Ozellikleri", ["Kategori", "Ozellik", "Deger", "Durum"], s.SystemDetails.Select(x => new[] { x.Category, x.Name, x.Value, x.Status }));
        AppendTable(html, "BIOS ve Suruculer", ["Kategori", "Aygit", "Uretici", "Surum", "Tarih", "Donanim Kimligi", "Kontrol"], s.Drivers.Select(x => new[] { x.Category, x.DeviceName, x.Manufacturer, x.DriverVersion, x.DriverDate, x.HardwareId, x.Status }));
        AppendTable(html, "Kaynak Kullanimi", ["Olcum", "Deger", "Durum", "Aciklama"], s.ResourceMetrics.Select(x => new[] { x.Name, x.Value, x.Status, x.Detail }));
        EndSection(html);

        BeginSection(html, "protection", "Koruma ve Onarim", "Geri yukleme noktalari ve calistirilan islemler");
        html.AppendLine($"<article class='card' data-searchable><h3>Sistem Koruma</h3><p>{E(s.ProtectionStatus)}</p></article>");
        AppendTable(html, "Geri Yukleme Noktalari", ["Zaman", "Aciklama", "Tip"], s.RestorePoints.Select(x => new[] { x.CreatedAt?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Description, x.Type }));
        AppendTable(html, "Calistirilan Onarimlar", ["Baslik", "Basladi", "Bitti", "Sonuc"], s.RepairHistory.Select(x => new[] { x.Title, x.StartedAt.ToString("dd.MM.yyyy HH:mm"), x.FinishedAt.ToString("dd.MM.yyyy HH:mm"), x.Success ? "Basarili" : $"Hata ({x.ExitCode})" }));
        EndSection(html);

        BeginSection(html, "logs", "Ham Uygulama Logu", "Tarama ve komut calistirma gecmisi");
        html.AppendLine($"<details class='raw-block'><summary>Ham uygulama logunu goster</summary><pre data-searchable>{E(s.LogText)}</pre></details>");
        EndSection(html);

        html.AppendLine("""
            </main></div></div>
            <script>
            (()=>{const buttons=[...document.querySelectorAll('.tab-button')],sections=[...document.querySelectorAll('.report-section')],search=document.getElementById('reportSearch'),state=document.getElementById('searchState');
            const activate=(id,query='')=>{buttons.forEach(b=>b.classList.toggle('active',b.dataset.tab===id));sections.forEach(s=>s.classList.toggle('active',s.id===id));location.hash=id==='overview'?'':id;search.value=query;filter();};
            const filter=()=>{const active=document.querySelector('.report-section.active');if(!active)return;const q=search.value.trim().toLocaleLowerCase('tr-TR'),items=[...active.querySelectorAll('[data-searchable]')];let shown=0;items.forEach(item=>{const visible=!q||item.innerText.toLocaleLowerCase('tr-TR').includes(q);item.hidden=!visible;if(visible)shown++;});state.textContent=q?shown+' eslesen kayit':'Bu sekmede '+items.length+' aranabilir kayit';};
            buttons.forEach(b=>b.addEventListener('click',()=>activate(b.dataset.tab)));document.querySelectorAll('[data-evidence-query]').forEach(b=>b.addEventListener('click',()=>{document.querySelectorAll('#errors details').forEach(d=>d.open=true);activate('errors',b.dataset.evidenceQuery||'');}));search.addEventListener('input',filter);const initial=location.hash.slice(1);activate(sections.some(s=>s.id===initial)?initial:'overview');})();
            </script></body></html>
            """);
        return html.ToString();
    }

    private static string BuildText(ReportSnapshot s)
    {
        var text = new StringBuilder();
        text.AppendLine("ITCHY Windows Troubleshooter Raporu");
        text.AppendLine(DateTime.Now.ToString("dd.MM.yyyy HH:mm"));
        text.AppendLine($"Sistem Durumu: {s.SystemStatus} - {s.HeaderSummary}");
        text.AppendLine();
        text.AppendLine("Analiz Sonucu");
        text.AppendLine(s.AnalysisSummary);
        text.AppendLine();
        text.AppendLine("Mavi Ekran Derin Analiz Ozeti");
        text.AppendLine(s.BlueScreenSummary);
        text.AppendLine();
        text.AppendLine("Mavi Ekran Genel Teshisi");
        text.AppendLine(s.CrossDumpAnalysis.Summary);
        text.AppendLine();
        text.AppendLine("Ortak Dump Desenleri");
        text.AppendLine(s.CrossDumpAnalysis.CommonPattern);
        text.AppendLine(s.CrossDumpAnalysis.EvidenceSummary);
        text.AppendLine();
        text.AppendLine("Supheli Kaynaklar");
        foreach (var candidate in s.CrossDumpAnalysis.Candidates)
        {
            text.AppendLine($"{candidate.Title} - {candidate.Strength}");
            text.AppendLine($"Kanit: {candidate.Evidence}");
            text.AppendLine($"Yorum: {candidate.Interpretation}");
        }
        text.AppendLine();
        text.AppendLine("Onerilen Troubleshooting Sirasi");
        text.AppendLine(s.CrossDumpAnalysis.TroubleshootingSummary);
        text.AppendLine();
        text.AppendLine("Dump Karsilastirmasi");
        foreach (var item in s.DumpAnalyses)
        {
            text.AppendLine($"{item.FileName} | {item.BugCheckCode} {item.BugCheckName} | {item.ExceptionSummary} | {item.FaultingModule} | {item.ProcessName} | {item.ImportantThirdPartyDriversText}");
        }
        text.AppendLine();
        text.AppendLine("Sistem Ozeti");
        text.AppendLine(s.SystemInfo);
        text.AppendLine("Bulgular");
        foreach (var finding in s.Findings)
        {
            text.AppendLine($"[{finding.SeverityText}] {finding.Title} - Guven %{finding.ConfidenceScore} ({finding.Confidence})");
            text.AppendLine($"Bilesen / Rol: {finding.Component} / {finding.Role}");
            text.AppendLine($"Guncellik / Tekrar / Kaynak: {finding.RecencyText} / {finding.OccurrenceCount} / {finding.IndependentSourceCount}");
            text.AppendLine($"Mavi Ekran Iliskisi: {finding.CrashRelation}");
            text.AppendLine($"Kanit Korelasyonu: {finding.Correlation}");
            text.AppendLine($"Muhtemel Sebep: {finding.Cause}");
            text.AppendLine($"Kanit: {finding.Evidence}");
            text.AppendLine($"Onerilen Islem: {finding.Recommendation}");
            text.AppendLine();
        }

        text.AppendLine("Derin Dump Analizleri");
        foreach (var item in s.DumpAnalyses)
        {
            text.AppendLine($"Dosya: {item.FileName} ({item.FilePath})");
            text.AppendLine($"Durum: {item.AnalysisStatus}; Butunluk: {item.IntegrityStatus}");
            text.AppendLine($"BugCheck: {item.BugCheckCode} {item.BugCheckName}");
            text.AppendLine($"Exception: {item.ExceptionSummary}");
            text.AppendLine($"Faulting: {item.FaultingAddress} {item.FaultingModule} {item.FaultingSymbol} - {item.FaultingInstruction}".Trim());
            text.AppendLine($"Ucuncu parti stack: {item.ImportantThirdPartyDriversText}");
            text.AppendLine($"Supheli: {item.SuspectedComponent}; Guven: {item.Confidence}");
            text.AppendLine($"Kanit: {item.Evidence}");
            text.AppendLine($"Yorum: {item.TechnicalInterpretation}");
            text.AppendLine($"Teshis: {item.RootCauseSummary}");
            text.AppendLine($"Context: {item.RegisterContextStatus} {item.RegisterSummary}");
            text.AppendLine($"Pointer: {item.PointerAnalysis}");
            text.AppendLine($"Eslesen olaylar: {item.CorrelatedEvents}");
            text.AppendLine($"Oneri: {item.Recommendation}");
            text.AppendLine($"Debugger: {item.DebuggerUsed}");
            text.AppendLine();
        }

        text.AppendLine("Ham WinDbg Ciktilari");
        foreach (var item in s.DumpAnalyses)
        {
            text.AppendLine($"===== {item.FileName} =====");
            text.AppendLine(item.RawDebuggerOutput);
            text.AppendLine();
        }

        text.AppendLine("Mavi Ekran Olay ve Dosya Sinyalleri");
        foreach (var item in s.BlueScreens)
        {
            text.AppendLine($"{item.TimeCreated:dd.MM.yyyy HH:mm} {item.Title} - {item.Summary} - {item.TechnicalDetail}");
        }

        text.AppendLine();
        text.AppendLine("Bilesene Gore Gruplanmis Hatalar");
        foreach (var group in GroupDiagnosticLogs(s.DiagnosticLogs))
        {
            text.AppendLine($"{group.Latest:dd.MM.yyyy HH:mm} [{group.Category}] {group.Component} - {group.Source} / {group.Code} - {group.Count} tekrar - {group.Sample}");
        }

        text.AppendLine();
        text.AppendLine("Ayiklanan Tekil Hata Kayitlari");
        foreach (var item in s.DiagnosticLogs)
        {
            text.AppendLine($"{item.TimeCreated:dd.MM.yyyy HH:mm} [{item.Category}] {item.Component} - {item.Source} / {item.Code} - {item.Summary}");
        }

        text.AppendLine();
        text.AppendLine("Sistem Saglik Denetimleri");
        foreach (var item in s.HealthChecks)
        {
            text.AppendLine($"{item.ObservedAt:dd.MM.yyyy HH:mm} [{item.Category}] {item.Component} - {item.Status} - {item.Value} - {item.Detail}");
        }

        text.AppendLine();
        text.AppendLine("Tarama Kapsami");
        foreach (var item in s.ScanCoverage)
        {
            text.AppendLine($"{item.Source}: {item.Status}, {item.RecordCount} kayit - {item.Detail}");
        }

        text.AppendLine();
        text.AppendLine("Event Viewer Ozeti");
        foreach (var item in s.Events)
        {
            text.AppendLine($"{item.TimeCreated:dd.MM.yyyy HH:mm} {item.LogName} {item.Provider} {item.Id} {item.Message}");
        }

        text.AppendLine();
        text.AppendLine("Reliability Monitor Ozeti");
        foreach (var item in s.ReliabilityRecords)
        {
            text.AppendLine($"{item.TimeGenerated:dd.MM.yyyy HH:mm} {item.SourceName} {item.ProductName} {item.Message}");
        }

        text.AppendLine();
        text.AppendLine("Sistem Ozellikleri");
        foreach (var item in s.SystemDetails)
        {
            text.AppendLine($"[{item.Category}] {item.Name}: {item.Value} {item.Status}");
        }

        text.AppendLine();
        text.AppendLine("BIOS ve Suruculer");
        foreach (var item in s.Drivers)
        {
            text.AppendLine($"[{item.Category}] {item.DeviceName} - {item.Manufacturer} - {item.DriverVersion} - {item.DriverDate} - {item.Status} - {item.HardwareId}");
        }

        text.AppendLine();
        text.AppendLine("Kaynak Kullanimi");
        foreach (var item in s.ResourceMetrics)
        {
            text.AppendLine($"{item.Name}: {item.Value} - {item.Status} - {item.Detail}");
        }

        text.AppendLine();
        text.AppendLine("Sistem Koruma");
        text.AppendLine(s.ProtectionStatus);
        text.AppendLine();
        text.AppendLine("Onarim Gecmisi");
        foreach (var item in s.RepairHistory)
        {
            text.AppendLine($"{item.Title} - {(item.Success ? "Basarili" : "Hata")} - {item.StartedAt:dd.MM.yyyy HH:mm}");
            text.AppendLine(item.Output);
        }

        text.AppendLine();
        text.AppendLine("Log");
        text.AppendLine(s.LogText);
        return text.ToString();
    }

    private static void AppendFindingCard(StringBuilder html, Finding finding)
    {
        html.AppendLine("<article class='card' data-searchable>");
        html.AppendLine($"<div class='finding-head'><b class='{finding.Severity.ToString().ToLowerInvariant()}'>{E(finding.SeverityText)}</b><span class='pill'>Guven %{finding.ConfidenceScore} - {E(finding.Confidence)}</span><h3>{E(finding.Title)}</h3></div>");
        html.AppendLine($"<p class='finding-meta'><b>Bilesen:</b> {E(finding.Component)} | <b>Rol:</b> {E(finding.Role)} | <b>Guncellik:</b> {E(finding.RecencyText)} | <b>Tekrar:</b> {finding.OccurrenceCount} | <b>Bagimsiz kaynak:</b> {finding.IndependentSourceCount}</p>");
        html.AppendLine($"<p><b>Mavi ekran iliskisi:</b> {E(finding.CrashRelation)}</p><p><b>Kanit korelasyonu:</b> {E(finding.Correlation)}</p><p><b>Muhtemel Sebep:</b> {E(finding.Cause)}</p><p><b>Kanit:</b> {E(finding.Evidence)}</p><p><b>Onerilen Islem:</b> {E(finding.Recommendation)}</p>");
        if (!string.IsNullOrWhiteSpace(finding.SearchKey))
        {
            html.AppendLine($"<div class='finding-actions'><button type='button' class='evidence-link' data-evidence-query='{E(finding.SearchKey)}'>Ilgili kayitlari ac</button></div>");
        }

        html.AppendLine("</article>");
    }

    private static int GetFindingReportPriority(Finding finding)
    {
        return finding.Role switch
        {
            "Dogrudan Ariza" => 0,
            "Kok Neden Adayi" => 1,
            "Yapilandirma" => 2,
            "Cokme Kaniti" => 3,
            "Sonuc Olayi" => 4,
            "Izleme Bulgusu" or "Anlik Olcum" => 5,
            _ => 6
        };
    }

    private static IReadOnlyList<DiagnosticGroup> GroupDiagnosticLogs(IReadOnlyList<DiagnosticLogItem> logs)
    {
        return logs
            .GroupBy(x => $"{x.Category}\u001f{x.Component}\u001f{x.Source}\u001f{x.Code}", StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var latest = group.OrderByDescending(x => x.TimeCreated).First();
                return new DiagnosticGroup(
                    latest.TimeCreated,
                    latest.Category,
                    latest.Component,
                    latest.Source,
                    latest.Code,
                    group.Count(),
                    latest.Summary);
            })
            .OrderByDescending(x => x.Count)
            .ThenByDescending(x => x.Latest)
            .ToList();
    }

    private static void AppendTable(StringBuilder html, string title, string[] headers, IEnumerable<string[]> rows)
    {
        var materializedRows = rows.ToList();
        html.AppendLine($"<div class='table-title'><h3>{E(title)}</h3><span class='pill'>{materializedRows.Count} kayit</span></div><div class='table-shell'><table><thead><tr>");
        foreach (var header in headers)
        {
            html.AppendLine($"<th>{E(header)}</th>");
        }

        html.AppendLine("</tr></thead><tbody>");
        foreach (var row in materializedRows)
        {
            html.AppendLine("<tr data-searchable>");
            foreach (var cell in row)
            {
                html.AppendLine($"<td>{E(cell)}</td>");
            }

            html.AppendLine("</tr>");
        }

        if (materializedRows.Count == 0)
        {
            html.AppendLine($"<tr><td class='empty' colspan='{headers.Length}'>Kayit bulunmadi.</td></tr>");
        }

        html.AppendLine("</tbody></table></div>");
    }

    private static void AppendCrossDumpAnalysis(StringBuilder html, CrossDumpAnalysisResult analysis)
    {
        html.AppendLine($"<article class='card summary-card' data-searchable><h3>Mavi Ekran Genel Teshisi</h3><p>{E(analysis.Summary)}</p><p><b>{E(analysis.Diagnosis)}</b></p></article>");
        html.AppendLine($"<article class='card' data-searchable><h3>Ortak Dump Desenleri</h3><p style='white-space:pre-line'>{E(analysis.CommonPattern)}</p><p style='white-space:pre-line'><span class='label'>Kanit</span><br>{E(analysis.EvidenceSummary)}</p><p style='white-space:pre-line'><span class='label'>Yorum</span><br>{E(analysis.InterpretationSummary)}</p></article>");
        AppendTable(html, "Supheli Kaynaklar",
            ["Oncelik", "Aday", "Kanit Gucu", "Dogrudan Kanit", "Teknik Yorum"],
            analysis.Candidates.Select((x, index) => new[]
            {
                (index + 1).ToString(),
                x.Title,
                x.Strength,
                x.Evidence,
                x.Interpretation
            }));
        html.AppendLine($"<article class='card' data-searchable><h3>Onerilen Troubleshooting Sirasi</h3><p style='white-space:pre-line'>{E(analysis.TroubleshootingSummary)}</p></article>");
    }

    private static void AppendDumpAnalyses(StringBuilder html, IReadOnlyList<DumpAnalysisItem> analyses)
    {
        html.AppendLine($"<div class='table-title'><h3>Derin Dump Analizleri</h3><span class='pill'>{analyses.Count} dump</span></div>");
        if (analyses.Count == 0)
        {
            html.AppendLine("<div class='card'>Analiz edilebilir dump dosyasi bulunmadi.</div>");
            return;
        }

        foreach (var item in analyses)
        {
            html.AppendLine("<article class='card' data-searchable>");
            html.AppendLine($"<h3>{E(item.FileName)} - {E(item.BugCheckCode)} {E(item.BugCheckName)}</h3>");
            html.AppendLine("<div class='dump-grid'>");
            AppendPair(html, "Dosya", $"{item.FilePath} ({item.FileSize}, {item.CreatedAt:dd.MM.yyyy HH:mm})");
            AppendPair(html, "Butunluk", item.IntegrityStatus);
            AppendPair(html, "Analiz durumu", item.AnalysisStatus);
            AppendPair(html, "Exception", item.ExceptionSummary);
            AppendPair(html, "Faulting address", item.FaultingAddress);
            AppendPair(html, "Faulting module / symbol", $"{item.FaultingModule} {item.FaultingSymbol}".Trim());
            AppendPair(html, "Faulting instruction", item.FaultingInstruction);
            AppendPair(html, "Probably caused by", item.ProbablyCausedBy);
            AppendPair(html, "IMAGE / MODULE / SYMBOL", $"{item.ImageName} / {item.ModuleName} / {item.SymbolName}");
            AppendPair(html, "Supheli bilesen", item.SuspectedComponent);
            AppendPair(html, "Guven", item.Confidence);
            AppendPair(html, "Bilesen ayrintisi", item.ComponentDetails);
            AppendPair(html, "Surec", item.ProcessName);
            AppendPair(html, "Failure bucket", item.FailureBucket);
            AppendPair(html, "Failure ID hash", item.FailureIdHash);
            AppendPair(html, "Parametreler", item.BugCheckParameters);
            AppendPair(html, "Kanit", item.Evidence);
            AppendPair(html, "Yorum", item.TechnicalInterpretation);
            AppendPair(html, "Teshis", item.RootCauseSummary);
            AppendPair(html, "Ucuncu parti stack suruculeri", item.ImportantThirdPartyDriversText);
            AppendPair(html, "Register context", item.RegisterContextStatus);
            AppendPair(html, "Registerlar", item.RegisterSummary);
            AppendPair(html, "Pointer analizi", item.PointerAnalysis);
            AppendPair(html, "Eslesen olaylar", item.CorrelatedEvents);
            AppendPair(html, "Oneri", item.Recommendation);
            AppendPair(html, "Debugger", item.DebuggerUsed);
            html.AppendLine("</div>");
            html.AppendLine($"<details><summary>Ham WinDbg ciktisini goster</summary><pre>{E(item.RawDebuggerOutput)}</pre></details>");
            html.AppendLine("</article>");
        }
    }

    private static void AppendMetric(StringBuilder html, string value, string label, string cssClass)
    {
        html.AppendLine($"<div class='metric'><b class='{E(cssClass)}'>{E(value)}</b><span>{E(label)}</span></div>");
    }

    private static void AppendTabButton(StringBuilder html, string id, string label, int count, bool active)
    {
        html.AppendLine($"<button class='tab-button{(active ? " active" : "")}' type='button' data-tab='{E(id)}'><span>{E(label)}</span><span class='tab-count'>{count}</span></button>");
    }

    private static void BeginSection(StringBuilder html, string id, string title, string description, bool active = false)
    {
        html.AppendLine($"<section id='{E(id)}' class='report-section{(active ? " active" : "")}'><header class='section-head'><div><h2>{E(title)}</h2><p>{E(description)}</p></div></header>");
    }

    private static void EndSection(StringBuilder html)
    {
        html.AppendLine("</section>");
    }

    private static void AppendPair(StringBuilder html, string label, string value)
    {
        html.AppendLine($"<div class='label'>{E(label)}</div><div>{E(value)}</div>");
    }

    private sealed record DiagnosticGroup(
        DateTime? Latest,
        string Category,
        string Component,
        string Source,
        string Code,
        int Count,
        string Sample);

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
}
