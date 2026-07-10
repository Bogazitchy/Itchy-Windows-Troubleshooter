using ItchyWindowsTroubleshooter.Models;
using LibreHardwareMonitor.Hardware;

namespace ItchyWindowsTroubleshooter.Services;

public sealed class HardwareSensorService
{
    public Task<IReadOnlyList<SystemInfoItem>> ReadTemperaturesAsync(CancellationToken cancellationToken)
    {
        return Task.Run<IReadOnlyList<SystemInfoItem>>(() => ReadTemperatures(cancellationToken), cancellationToken);
    }

    private static IReadOnlyList<SystemInfoItem> ReadTemperatures(CancellationToken cancellationToken)
    {
        var items = new List<SystemInfoItem>();
        string? sensorError = null;
        try
        {
            var computer = new Computer
            {
                IsCpuEnabled = true,
                IsGpuEnabled = true,
                IsMotherboardEnabled = true,
                IsStorageEnabled = true
            };
            try
            {
                computer.Open();
                computer.Accept(new UpdateVisitor());

                foreach (var hardware in Flatten(computer.Hardware))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (hardware.HardwareType is not (HardwareType.Cpu or HardwareType.GpuAmd or HardwareType.GpuIntel or HardwareType.GpuNvidia))
                    {
                        continue;
                    }

                    foreach (var sensor in hardware.Sensors.Where(x =>
                                 x.SensorType == SensorType.Temperature &&
                                 x.Value.HasValue &&
                                 x.Value.Value > 0 &&
                                 x.Value.Value < 130))
                    {
                        var value = sensor.Value!.Value;
                        var category = hardware.HardwareType == HardwareType.Cpu ? "CPU Sicakligi" : "GPU Sicakligi";
                        var status = value >= 95 ? "Kritik" : value >= 85 ? "Yuksek" : "Normal";
                        items.Add(new SystemInfoItem(category, $"{hardware.Name} / {sensor.Name}", $"{value:N1} C", status));
                    }
                }
            }
            finally
            {
                computer.Close();
            }
        }
        catch (Exception ex)
        {
            sensorError = $"Sensor erisimi desteklenmiyor veya yonetici izni gerekiyor: {ex.Message}";
        }

        var unavailableReason = sensorError ?? "Bu cihaz sensor verisini Windows'a sunmuyor olabilir. Uygulamayi yonetici olarak calistirmayi deneyin.";
        if (!items.Any(x => x.Category == "CPU Sicakligi"))
        {
            items.Add(new SystemInfoItem(
                "CPU Sicakligi",
                "CPU sensoru",
                "Okunamadi",
                unavailableReason));
        }

        if (!items.Any(x => x.Category == "GPU Sicakligi"))
        {
            items.Add(new SystemInfoItem(
                "GPU Sicakligi",
                "GPU sensoru",
                "Okunamadi",
                unavailableReason));
        }

        return items;
    }

    private static IEnumerable<IHardware> Flatten(IEnumerable<IHardware> hardwareItems)
    {
        foreach (var hardware in hardwareItems)
        {
            yield return hardware;
            foreach (var subHardware in Flatten(hardware.SubHardware))
            {
                yield return subHardware;
            }
        }
    }

    private sealed class UpdateVisitor : IVisitor
    {
        public void VisitComputer(IComputer computer) => computer.Traverse(this);

        public void VisitHardware(IHardware hardware)
        {
            hardware.Update();
            foreach (var subHardware in hardware.SubHardware)
            {
                subHardware.Accept(this);
            }
        }

        public void VisitSensor(ISensor sensor)
        {
        }

        public void VisitParameter(IParameter parameter)
        {
        }
    }
}
