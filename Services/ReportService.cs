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
            .card{background:var(--panel);border:1px solid var(--line);border-radius:7px;padding:16px;margin:0 0 12px}.card h3{margin:0 0 8px}.card p:last-child{margin-bottom:0}.summary-card{border-left:4px solid var(--blue)}.critical{color:var(--red)}.warning{color:var(--amber)}.info{color:var(--blue)}.success{color:var(--green)}
            .table-shell{border:1px solid var(--line);border-radius:7px;overflow:auto;max-height:70vh;margin:0 0 22px;background:var(--panel)}table{width:100%;border-collapse:collapse;font-size:13px}th{position:sticky;top:0;background:#203247;color:#fff;z-index:1}td,th{border-bottom:1px solid var(--line);padding:9px 10px;text-align:left;vertical-align:top}tbody tr:nth-child(even){background:#142130}tbody tr:hover{background:#1d3247}.table-title{display:flex;align-items:center;justify-content:space-between;margin:20px 0 8px}.table-title h3{margin:0}.pill{color:var(--cyan);font-size:12px;border:1px solid #2d625f;border-radius:10px;padding:2px 8px}
            pre{white-space:pre-wrap;overflow:auto;background:#081018;border:1px solid var(--line);padding:12px;border-radius:7px;color:#dce8f5;max-height:70vh}details{margin-top:12px}summary{cursor:pointer;color:var(--blue);font-weight:600}.dump-grid{display:grid;grid-template-columns:180px minmax(0,1fr);gap:7px 14px}.label{color:var(--muted)}[hidden]{display:none!important}.empty{color:var(--muted);padding:18px;text-align:center}
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
        AppendTabButton(html, "reliability", "Guvenilirlik", s.ReliabilityRecords.Count, false);
        AppendTabButton(html, "system", "Sistem", s.SystemDetails.Count + s.Drivers.Count + s.ResourceMetrics.Count, false);
        AppendTabButton(html, "protection", "Koruma ve Onarim", s.RestorePoints.Count + s.RepairHistory.Count, false);
        AppendTabButton(html, "logs", "Ham Log", string.IsNullOrWhiteSpace(s.LogText) ? 0 : s.LogText.Split('\n').Length, false);
        html.AppendLine("<div id='searchState' class='search-state'>Sekme secin veya arama yapin.</div></nav><main>");

        BeginSection(html, "overview", "Genel Bakis", "Teknisyen icin en onemli sonuclar", true);
        html.AppendLine($"<article class='card summary-card' data-searchable><h3>Analiz Sonucu</h3><p>{E(s.AnalysisSummary)}</p></article>");
        html.AppendLine($"<article class='card' data-searchable><h3>Mavi Ekran Ozeti</h3><p>{E(s.BlueScreenSummary)}</p></article>");
        html.AppendLine($"<article class='card' data-searchable><h3>Sistem Ozeti</h3><pre>{E(s.SystemInfo)}</pre></article>");
        EndSection(html);

        BeginSection(html, "findings", "Oncelikli Bulgular", "Kritik ve uyari seviyesindeki ayiklanmis sonuclar");
        foreach (var finding in s.Findings)
        {
            html.AppendLine($"<article class='card' data-searchable><b class='{finding.Severity.ToString().ToLowerInvariant()}'>{E(finding.Severity.ToString())}</b><h3>{E(finding.Title)}</h3><p><b>Muhtemel Sebep:</b> {E(finding.Cause)}</p><p><b>Kanit:</b> {E(finding.Evidence)}</p><p><b>Onerilen Islem:</b> {E(finding.Recommendation)}</p></article>");
        }
        if (s.Findings.Count == 0) html.AppendLine("<div class='card empty'>Bulgu kaydi yok.</div>");
        EndSection(html);

        BeginSection(html, "bsod", "Mavi Ekran ve Dump", "Stop code, surucu, stack ve olay korelasyonu");
        html.AppendLine($"<article class='card summary-card' data-searchable><h3>Derin Analiz Ozeti</h3><p>{E(s.BlueScreenSummary)}</p></article>");
        AppendDumpAnalyses(html, s.DumpAnalyses);
        AppendTable(html, "Mavi Ekran Olay ve Dosya Sinyalleri", ["Zaman", "Baslik", "Ozet", "Teknik Detay"], s.BlueScreens.Select(x => new[] { x.TimeCreated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Title, x.Summary, x.TechnicalDetail }));
        EndSection(html);

        BeginSection(html, "errors", "Hata Kayitlari", "Ayiklanmis sorunlar ve ham Event Viewer verileri");
        AppendTable(html, "Ayiklanan Hata Kayitlari", ["Zaman", "Kategori", "Bilesen", "Kaynak", "Kod", "Ozet"], s.DiagnosticLogs.Select(x => new[] { x.TimeCreated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.Category, x.Component, x.Source, x.Code, x.Summary }));
        AppendTable(html, "Event Viewer Ozeti", ["Zaman", "Log", "Kaynak", "ID", "Mesaj"], s.Events.Select(x => new[] { x.TimeCreated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.LogName, x.Provider, x.Id.ToString(), x.Message }));
        EndSection(html);

        BeginSection(html, "reliability", "Guvenilirlik Gecmisi", "Uygulama, guncelleme ve sistem kararliligi kayitlari");
        AppendTable(html, "Reliability Monitor Ozeti", ["Zaman", "Kaynak", "Urun", "Mesaj"], s.ReliabilityRecords.Select(x => new[] { x.TimeGenerated?.ToString("dd.MM.yyyy HH:mm") ?? "", x.SourceName, x.ProductName, x.Message }));
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
        html.AppendLine($"<pre data-searchable>{E(s.LogText)}</pre>");
        EndSection(html);

        html.AppendLine("""
            </main></div></div>
            <script>
            (()=>{const buttons=[...document.querySelectorAll('.tab-button')],sections=[...document.querySelectorAll('.report-section')],search=document.getElementById('reportSearch'),state=document.getElementById('searchState');
            const activate=id=>{buttons.forEach(b=>b.classList.toggle('active',b.dataset.tab===id));sections.forEach(s=>s.classList.toggle('active',s.id===id));location.hash=id==='overview'?'':id;search.value='';filter();};
            const filter=()=>{const active=document.querySelector('.report-section.active');if(!active)return;const q=search.value.trim().toLocaleLowerCase('tr-TR'),items=[...active.querySelectorAll('[data-searchable]')];let shown=0;items.forEach(item=>{const visible=!q||item.innerText.toLocaleLowerCase('tr-TR').includes(q);item.hidden=!visible;if(visible)shown++;});state.textContent=q?shown+' eslesen kayit':'Bu sekmede '+items.length+' aranabilir kayit';};
            buttons.forEach(b=>b.addEventListener('click',()=>activate(b.dataset.tab)));search.addEventListener('input',filter);const initial=location.hash.slice(1);activate(sections.some(s=>s.id===initial)?initial:'overview');})();
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
        text.AppendLine("Sistem Ozeti");
        text.AppendLine(s.SystemInfo);
        text.AppendLine("Bulgular");
        foreach (var finding in s.Findings)
        {
            text.AppendLine($"[{finding.Severity}] {finding.Title}");
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
            text.AppendLine($"Supheli: {item.SuspectedComponent}; Guven: {item.Confidence}");
            text.AppendLine($"Sonuc: {item.RootCauseSummary}");
            text.AppendLine($"Kanit: {item.Evidence}");
            text.AppendLine($"Eslesen olaylar: {item.CorrelatedEvents}");
            text.AppendLine($"Oneri: {item.Recommendation}");
            text.AppendLine($"Debugger: {item.DebuggerUsed}");
            text.AppendLine("Ham debugger ciktisi:");
            text.AppendLine(item.RawDebuggerOutput);
            text.AppendLine();
        }

        text.AppendLine("Mavi Ekran Olay ve Dosya Sinyalleri");
        foreach (var item in s.BlueScreens)
        {
            text.AppendLine($"{item.TimeCreated:dd.MM.yyyy HH:mm} {item.Title} - {item.Summary} - {item.TechnicalDetail}");
        }

        text.AppendLine();
        text.AppendLine("Ayiklanan Hata Kayitlari");
        foreach (var item in s.DiagnosticLogs)
        {
            text.AppendLine($"{item.TimeCreated:dd.MM.yyyy HH:mm} [{item.Category}] {item.Component} - {item.Source} / {item.Code} - {item.Summary}");
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
            AppendPair(html, "Supheli bilesen", item.SuspectedComponent);
            AppendPair(html, "Guven", item.Confidence);
            AppendPair(html, "Bilesen ayrintisi", item.ComponentDetails);
            AppendPair(html, "Surec", item.ProcessName);
            AppendPair(html, "Failure bucket", item.FailureBucket);
            AppendPair(html, "Parametreler", item.BugCheckParameters);
            AppendPair(html, "Sonuc", item.RootCauseSummary);
            AppendPair(html, "Kanit", item.Evidence);
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

    private static string E(string? value) => WebUtility.HtmlEncode(value ?? "");
}
