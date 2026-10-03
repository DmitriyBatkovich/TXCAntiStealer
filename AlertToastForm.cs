namespace AntiStealer;

internal sealed class AlertToastForm : Form
{
    private readonly System.Windows.Forms.Timer _closeTimer = new() { Interval = 9000 };
    private readonly Action _onOpen;

    public AlertToastForm(string title, string message, Color accent, Action onOpen)
    {
        _onOpen = onOpen;
        FormBorderStyle = FormBorderStyle.None;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = TxcTheme.Surface;
        ForeColor = TxcTheme.Text;
        ClientSize = new Size(410, 112);
        Font = new Font("Segoe UI", 9f);

        var accentBar = new Panel
        {
            Dock = DockStyle.Left,
            Width = 4,
            BackColor = accent
        };
        var brand = new Label
        {
            Text = "TXC  /  ANTISTEALER",
            Location = new Point(85, 10),
            Size = new Size(260, 18),
            Font = new Font("Consolas", 8f, FontStyle.Bold),
            ForeColor = TxcTheme.Accent,
            BackColor = Color.Transparent
        };
        var icon = new PictureBox
        {
            Image = TxcTheme.CreateApplicationLogoBitmap(48),
            SizeMode = PictureBoxSizeMode.Zoom,
            Location = new Point(20, 31),
            Size = new Size(48, 48),
            BackColor = Color.Transparent
        };
        var titleLabel = new Label
        {
            Text = title,
            Location = new Point(85, 31),
            Size = new Size(290, 25),
            Font = new Font("Segoe UI Semibold", 10f),
            ForeColor = TxcTheme.Text,
            AutoEllipsis = true
        };
        var messageLabel = new Label
        {
            Text = message,
            Location = new Point(85, 58),
            Size = new Size(300, 40),
            ForeColor = TxcTheme.Muted,
            AutoEllipsis = true
        };
        var close = new Label
        {
            Text = "×",
            TextAlign = ContentAlignment.MiddleCenter,
            Location = new Point(380, 5),
            Size = new Size(25, 25),
            Font = new Font("Segoe UI", 13f),
            ForeColor = TxcTheme.Muted,
            Cursor = Cursors.Hand
        };
        close.Click += (_, _) => Close();

        Controls.Add(accentBar);
        Controls.Add(brand);
        Controls.Add(icon);
        Controls.Add(titleLabel);
        Controls.Add(messageLabel);
        Controls.Add(close);

        foreach (Control control in new Control[] { this, brand, icon, titleLabel, messageLabel })
        {
            control.Cursor = Cursors.Hand;
            control.Click += (_, _) => OpenDetails();
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
            icon.Image?.Dispose();
        };
        Paint += (_, e) =>
        {
            using var pen = new Pen(TxcTheme.Border);
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

    private void OpenDetails()
    {
        Close();
        _onOpen();
    }
}
