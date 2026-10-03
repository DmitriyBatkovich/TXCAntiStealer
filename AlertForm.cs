namespace AntiStealer;

internal sealed class AlertForm : Form
{
    public AlertChoice Choice { get; private set; } = AlertChoice.KeepBlocked;

    public AlertForm(DetectionEvent detection)
    {
        Text = "AntiStealer — тревога";
        StartPosition = FormStartPosition.CenterScreen;
        TopMost = true;
        Width = 720;
        Height = 490;
        MinimumSize = new Size(620, 440);
        BackColor = Color.FromArgb(22, 25, 31);
        ForeColor = Color.WhiteSmoke;
        Font = new Font("Segoe UI", 10f);

        var title = new Label
        {
            Text = "Братан, похоже, тебя обносят",
            Dock = DockStyle.Top,
            Height = 70,
            Padding = new Padding(24, 22, 0, 0),
            Font = new Font("Segoe UI Semibold", 18f),
            ForeColor = Color.FromArgb(255, 105, 105)
        };

        var summary = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            BorderStyle = BorderStyle.None,
            BackColor = Color.FromArgb(30, 34, 42),
            ForeColor = Color.WhiteSmoke,
            Font = new Font("Consolas", 10f),
            Margin = new Padding(24),
            Text = $"Интернет для процесса уже заблокирован.\r\n\r\n" +
                   $"Процесс:  {detection.ProcessName}  (PID {detection.ProcessId})\r\n" +
                   $"Риск:     {detection.Risk}/100+\r\n" +
                   $"Файл:     {detection.FilePath}\r\n" +
                   $"Сеть:     {detection.RemoteEndpoints}\r\n\r\n" +
                   $"Почему:   {detection.Reasons}\r\n\r\n" +
                   "Если вы только что сами запустили эту программу и доверяете ей — нажмите «Разрешить»."
        };

        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 82,
            FlowDirection = FlowDirection.RightToLeft,
            Padding = new Padding(14),
            BackColor = Color.FromArgb(22, 25, 31)
        };

        buttons.Controls.Add(MakeButton("В карантин", Color.FromArgb(201, 63, 63), () => CloseWith(AlertChoice.Quarantine)));
        buttons.Controls.Add(MakeButton("Завершить", Color.FromArgb(181, 112, 45), () => CloseWith(AlertChoice.Terminate)));
        buttons.Controls.Add(MakeButton("Разрешить", Color.FromArgb(45, 125, 91), () => CloseWith(AlertChoice.Allow)));
        buttons.Controls.Add(MakeButton("Оставить блок", Color.FromArgb(70, 78, 92), () => CloseWith(AlertChoice.KeepBlocked)));

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(24, 0, 24, 12) };
        body.Controls.Add(summary);
        Controls.Add(body);
        Controls.Add(buttons);
        Controls.Add(title);
    }

    private Button MakeButton(string text, Color color, Action action)
    {
        var button = new Button
        {
            Text = text,
            Width = 135,
            Height = 42,
            FlatStyle = FlatStyle.Flat,
            BackColor = color,
            ForeColor = Color.White,
            Margin = new Padding(6),
            Cursor = Cursors.Hand
        };
        button.FlatAppearance.BorderSize = 0;
        button.Click += (_, _) => action();
        return button;
    }

    private void CloseWith(AlertChoice choice)
    {
        Choice = choice;
        DialogResult = DialogResult.OK;
        Close();
    }
}
