using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using WindowsSecuritySentinel.Core.Models;

namespace WindowsSecuritySentinel.Converters;

public class SeverityToBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush CleanBrush = new(Color.FromRgb(22, 101, 52)); // Green
    private static readonly SolidColorBrush LowBrush = new(Color.FromRgb(7, 89, 133)); // Blue
    private static readonly SolidColorBrush MediumBrush = new(Color.FromRgb(180, 83, 9)); // Amber
    private static readonly SolidColorBrush HighBrush = new(Color.FromRgb(194, 65, 12)); // Orange
    private static readonly SolidColorBrush CriticalBrush = new(Color.FromRgb(185, 28, 28)); // Red
    private static readonly SolidColorBrush DefaultBrush = new(Color.FromRgb(100, 116, 139)); // Slate

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatSeverity severity)
        {
            return severity switch
            {
                ThreatSeverity.Clean => CleanBrush,
                ThreatSeverity.Low => LowBrush,
                ThreatSeverity.Medium => MediumBrush,
                ThreatSeverity.High => HighBrush,
                ThreatSeverity.Critical => CriticalBrush,
                _ => DefaultBrush
            };
        }
        return DefaultBrush;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
}

public class SeverityToBackgroundBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush CleanBg = new(Color.FromRgb(220, 252, 231));
    private static readonly SolidColorBrush LowBg = new(Color.FromRgb(224, 242, 254));
    private static readonly SolidColorBrush MediumBg = new(Color.FromRgb(254, 243, 199));
    private static readonly SolidColorBrush HighBg = new(Color.FromRgb(255, 237, 213));
    private static readonly SolidColorBrush CriticalBg = new(Color.FromRgb(254, 226, 226));
    private static readonly SolidColorBrush DefaultBg = new(Color.FromRgb(241, 245, 249));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is ThreatSeverity severity)
        {
            return severity switch
            {
                ThreatSeverity.Clean => CleanBg,
                ThreatSeverity.Low => LowBg,
                ThreatSeverity.Medium => MediumBg,
                ThreatSeverity.High => HighBg,
                ThreatSeverity.Critical => CriticalBg,
                _ => DefaultBg
            };
        }
        return DefaultBg;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => throw new NotImplementedException();
}
