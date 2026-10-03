using Microsoft.Win32;

namespace AntiStealer;

internal static class TxcTheme
{
    public static readonly Color Window = Color.FromArgb(7, 7, 7);
    public static readonly Color TitleBar = Color.FromArgb(4, 4, 4);
    public static readonly Color Sidebar = Color.FromArgb(14, 14, 14);
    public static readonly Color Surface = Color.FromArgb(16, 16, 16);
    public static readonly Color SurfaceRaised = Color.FromArgb(24, 23, 17);
    public static readonly Color Border = Color.FromArgb(55, 48, 24);
    public static readonly Color BorderSoft = Color.FromArgb(38, 38, 38);
    public static readonly Color Accent = Color.FromArgb(242, 205, 58);
    public static readonly Color AccentHover = Color.FromArgb(255, 220, 73);
    public static readonly Color Text = Color.FromArgb(246, 246, 246);
    public static readonly Color Muted = Color.FromArgb(145, 151, 165);
    public static readonly Color Green = Color.FromArgb(104, 213, 151);
    public static readonly Color Red = Color.FromArgb(230, 87, 87);
    public static readonly Color Amber = Color.FromArgb(228, 163, 67);
    public static readonly Color Blue = Color.FromArgb(111, 161, 220);

    public static bool SystemUsesDarkApps()
    {
        try
        {
            if (SystemInformation.HighContrast)
                return SystemColors.Window.GetBrightness() < 0.5f;
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            if (key?.GetValue("AppsUseLightTheme") is int appsTheme)
                return appsTheme == 0;
            if (key?.GetValue("SystemUsesLightTheme") is int systemTheme)
                return systemTheme == 0;
            return true;
        }
        catch
        {
            return true;
        }
    }

    public static Icon CreateApplicationIcon()
    {
        using var stream = typeof(TxcTheme).Assembly.GetManifestResourceStream("AntiStealer.AppIcon.ico")
            ?? throw new InvalidOperationException("Встроенная иконка AntiStealer не найдена.");
        using var source = new Icon(stream);
        return (Icon)source.Clone();
    }

    public static Bitmap CreateApplicationIconBitmap()
    {
        using var icon = CreateApplicationIcon();
        return icon.ToBitmap();
    }

    public static Bitmap CreateApplicationLogoBitmap(int size)
    {
        using var stream = typeof(TxcTheme).Assembly.GetManifestResourceStream("AntiStealer.AppLogo.png")
            ?? throw new InvalidOperationException("Встроенная эмблема AntiStealer не найдена.");
        using var source = Image.FromStream(stream);
        var bitmap = new Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.Clear(Color.Transparent);
        graphics.CompositingMode = System.Drawing.Drawing2D.CompositingMode.SourceCopy;
        graphics.CompositingQuality = System.Drawing.Drawing2D.CompositingQuality.HighQuality;
        graphics.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.HighQualityBicubic;
        graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.HighQuality;
        graphics.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.HighQuality;
        graphics.DrawImage(source, new Rectangle(0, 0, size, size));
        return bitmap;
    }
}

internal sealed class TxcToolStripColorTable(bool dark) : ProfessionalColorTable
{
    private readonly Color _background = dark ? Color.FromArgb(29, 29, 29) : Color.FromArgb(248, 248, 248);
    private readonly Color _selected = dark ? Color.FromArgb(50, 45, 25) : Color.FromArgb(255, 236, 151);
    private readonly Color _border = dark ? Color.FromArgb(72, 72, 72) : Color.FromArgb(196, 196, 196);

    public override Color ToolStripDropDownBackground => _background;
    public override Color ImageMarginGradientBegin => _background;
    public override Color ImageMarginGradientMiddle => _background;
    public override Color ImageMarginGradientEnd => _background;
    public override Color MenuBorder => _border;
    public override Color MenuItemBorder => TxcTheme.Accent;
    public override Color MenuItemSelected => _selected;
    public override Color MenuItemSelectedGradientBegin => _selected;
    public override Color MenuItemSelectedGradientEnd => _selected;
    public override Color SeparatorDark => _border;
    public override Color SeparatorLight => _border;
}

internal sealed class TxcToolStripRenderer : ToolStripProfessionalRenderer
{
    private readonly bool _dark;

    public TxcToolStripRenderer(bool dark) : base(new TxcToolStripColorTable(dark))
    {
        _dark = dark;
        RoundedEdges = false;
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = _dark ? Color.WhiteSmoke : Color.FromArgb(24, 24, 24);
        base.OnRenderItemText(e);
    }

    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
    {
        e.ArrowColor = _dark ? Color.WhiteSmoke : Color.FromArgb(24, 24, 24);
        base.OnRenderArrow(e);
    }
}
