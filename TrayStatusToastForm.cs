using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace AntiStealer;

internal sealed class TrayStatusToastForm : Form
{
    private readonly System.Windows.Forms.Timer _closeTimer = new() { Interval = 8000 };
    private readonly Action _onOpen;

    public TrayStatusToastForm(Action onOpen)
    {
        _onOpen = onOpen;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = Color.FromArgb(12, 11, 8);
        ForeColor = TxcTheme.Text;
        ClientSize = new Size(390, 96);
        Font = new Font("Segoe UI", 9f);

        var accentBar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 4,
            BackColor = TxcTheme.Accent
        };
        var emblem = new Panel
        {
            Location = new Point(17, 15),
            Size = new Size(64, 64),
            BackColor = Color.Transparent,
            Cursor = Cursors.Hand
        };
        var emblemImage = TxcTheme.CreateApplicationLogoBitmap(64);
        emblem.Paint += (_, e) =>
        {
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var shadow = new SolidBrush(Color.FromArgb(110, 0, 0, 0));
            e.Graphics.FillEllipse(shadow, 4, 6, 57, 57);
            e.Graphics.DrawImage(emblemImage, new Rectangle(0, 0, 64, 64));
        };
        var title = new Label
        {
            Text = "TXC / ANTISTEALER",
            Location = new Point(95, 15),
            Size = new Size(245, 22),
            Font = new Font("Segoe UI Semibold", 9.5f),
            ForeColor = TxcTheme.Accent,
            BackColor = Color.Transparent,
            Cursor = Cursors.Hand
        };
        var message = new Label
        {
            Text = "Приложение работает в трее.\r\nЗащита и уведомления остаются активными.",
            Location = new Point(95, 39),
            Size = new Size(270, 43),
            Font = new Font("Segoe UI", 9f),
            ForeColor = TxcTheme.Text,
            BackColor = Color.Transparent,
            Cursor = Cursors.Hand
        };
        var close = new Label
        {
            Text = "×",
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(357, 8),
            Size = new Size(24, 24),
            Font = new Font("Segoe UI", 12f),
            ForeColor = TxcTheme.Muted,
            BackColor = Color.FromArgb(23, 22, 17),
            Cursor = Cursors.Hand
        };
        close.Click += (_, _) => Close();
        close.MouseEnter += (_, _) => close.ForeColor = TxcTheme.Accent;
        close.MouseLeave += (_, _) => close.ForeColor = TxcTheme.Muted;
        close.Paint += (_, e) =>
        {
            using var pen = new Pen(Color.FromArgb(82, 68, 21));
            e.Graphics.DrawRectangle(pen, 0, 0, close.ClientSize.Width - 1, close.ClientSize.Height - 1);
        };

        Controls.Add(accentBar);
        Controls.Add(emblem);
        Controls.Add(title);
        Controls.Add(message);
        Controls.Add(close);

        foreach (Control control in new Control[] { this, emblem, title, message })
        {
            control.Cursor = Cursors.Hand;
            control.Click += (_, _) => OpenApplication();
            control.MouseEnter += (_, _) => _closeTimer.Stop();
            control.MouseLeave += (_, _) => _closeTimer.Start();
        }

        Shown += (_, _) =>
        {
            var area = Screen.PrimaryScreen?.WorkingArea ?? Screen.FromPoint(Cursor.Position).WorkingArea;
            Location = new Point(area.Right - Width - 18, area.Bottom - Height - 18);
            _closeTimer.Start();
        };
        _closeTimer.Tick += (_, _) => Close();
        FormClosed += (_, _) =>
        {
            _closeTimer.Dispose();
            emblemImage.Dispose();
        };
        Paint += (_, e) =>
        {
            using var stripe = new Pen(Color.FromArgb(14, 242, 205, 58));
            for (var x = -ClientSize.Height; x < ClientSize.Width; x += 14)
                e.Graphics.DrawLine(stripe, x, ClientSize.Height, x + ClientSize.Height, 0);
            using var pen = new Pen(Color.FromArgb(105, 83, 17));
            e.Graphics.DrawRectangle(pen, 0, 0, ClientSize.Width - 1, ClientSize.Height - 1);
        };
    }

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            const int CsDropShadow = 0x00020000;
            var parameters = base.CreateParams;
            parameters.ClassStyle |= CsDropShadow;
            return parameters;
        }
    }

    public void RenderPreview(string path)
    {
        Show();
        Application.DoEvents();
        using var bitmap = new Bitmap(ClientSize.Width, ClientSize.Height);
        DrawToBitmap(bitmap, ClientRectangle);
        bitmap.Save(path, ImageFormat.Png);
        Hide();
    }

    private void OpenApplication()
    {
        Close();
        _onOpen();
    }
}
