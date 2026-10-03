using System.ComponentModel;
using System.Drawing.Imaging;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace AntiStealer;

internal sealed class MainForm : Form
{
    private const int WmNcHitTest = 0x0084;
    private const int WmNcLButtonDown = 0x00A1;
    private const int HtCaption = 0x0002;

    private readonly ProtectionEngine? _engine;
    private readonly BindingList<DetectionEvent> _events = new();
    private readonly Label _status = new();
    private readonly Label _eventCount = new();
    private readonly Label _emptyState = new();
    private readonly DataGridView _grid = new();
    private readonly NotifyIcon _tray = new();
    private readonly ContextMenuStrip _trayMenu = new();
    private readonly Button _startupButton;
    private readonly ServiceNotificationMonitor _serviceNotifications;
    private readonly EventWaitHandle? _uiPresence;
    private AlertToastForm? _toast;
    private TrayStatusToastForm? _trayStatusToast;
    private bool _exitRequested;

    [DllImport("user32.dll")]
    private static extern bool ReleaseCapture();

    [DllImport("user32.dll")]
    private static extern IntPtr SendMessage(IntPtr window, int message, IntPtr wParam, IntPtr lParam);

    public MainForm(bool previewMode = false)
    {
        _engine = previewMode ? null : new ProtectionEngine();
        Text = "TXC / AntiStealer";
        Width = 1180;
        Height = 720;
        MinimumSize = new Size(920, 560);
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.None;
        Padding = new Padding(1);
        BackColor = TxcTheme.Border;
        ForeColor = TxcTheme.Text;
        Font = new Font("Segoe UI", 9.5f);
        Icon = TxcTheme.CreateApplicationIcon();

        _startupButton = MakeButton("АВТОЗАПУСК", TxcTheme.Surface, TxcTheme.Border, TxcTheme.Muted);
        BuildLayout();
        if (!previewMode)
        {
            ConfigureTray();
            SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;
        }

        try { _uiPresence = new EventWaitHandle(true, EventResetMode.ManualReset, @"Global\AntiStealerInteractiveUi"); }
        catch { }
        _serviceNotifications = new ServiceNotificationMonitor(notification =>
        {
            if (!IsDisposed && IsHandleCreated)
                BeginInvoke(() => HandleServiceNotification(notification));
        });

        if (_engine is not null)
        {
            _engine.Detected += detection => BeginInvoke(() => HandleDetection(detection));
            _engine.StatusChanged += text => BeginInvoke(() => _status.Text = text.ToUpperInvariant());
            _engine.TamperDetected += message => BeginInvoke(() => HandleTamper(message));
        }
        if (!previewMode)
            Shown += (_, _) => StartProtectionLayer();
        FormClosing += OnFormClosing;
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

    private void BuildLayout()
    {
        var titleBar = BuildTitleBar();
        var body = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            BackColor = TxcTheme.Window,
            ColumnCount = 2,
            RowCount = 1,
            Margin = Padding.Empty,
            Padding = Padding.Empty
        };
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230));
        body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        body.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        body.Controls.Add(BuildSidebar(), 0, 0);
        body.Controls.Add(BuildWorkspace(), 1, 0);

        Controls.Add(body);
        Controls.Add(titleBar);
    }

    private Panel BuildTitleBar()
    {
        var bar = new Panel
        {
            Dock = DockStyle.Top,
            Height = 39,
            BackColor = TxcTheme.TitleBar
        };
        var brand = new Label
        {
            Text = "TXC",
            AutoSize = true,
            Location = new Point(14, 10),
            Font = new Font("Segoe UI Semibold", 9f),
            ForeColor = TxcTheme.Accent
        };
        var product = new Label
        {
            Text = "/  ANTISTEALER",
            AutoSize = true,
            Location = new Point(44, 10),
            Font = new Font("Segoe UI Semibold", 9f),
            ForeColor = TxcTheme.Text
        };
        var minimize = MakeCaptionButton("—");
        var maximize = MakeCaptionButton("□");
        var close = MakeCaptionButton("×", closeButton: true);
        minimize.Click += (_, _) => WindowState = FormWindowState.Minimized;
        maximize.Click += (_, _) => ToggleMaximize();
        close.Click += (_, _) => Close();
        bar.Resize += (_, _) =>
        {
            close.Left = bar.ClientSize.Width - close.Width;
            maximize.Left = close.Left - maximize.Width;
            minimize.Left = maximize.Left - minimize.Width;
        };
        bar.DoubleClick += (_, _) => ToggleMaximize();
        foreach (var control in new Control[] { bar, brand, product })
            control.MouseDown += DragWindow;
        bar.Controls.Add(brand);
        bar.Controls.Add(product);
        bar.Controls.Add(minimize);
        bar.Controls.Add(maximize);
        bar.Controls.Add(close);
        return bar;
    }

    private Control BuildSidebar()
    {
        var sidebar = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = TxcTheme.Sidebar,
            Padding = new Padding(10, 20, 10, 12)
        };
        var brand = new Label
        {
            Text = "TXC SECURITY",
            AutoSize = true,
            Location = new Point(18, 22),
            Font = new Font("Segoe UI Semibold", 11f),
            ForeColor = TxcTheme.Accent
        };
        var product = new Label
        {
            Text = "ANTI STEALER",
            AutoSize = true,
            Location = new Point(18, 50),
            Font = new Font("Segoe UI Semibold", 18f),
            ForeColor = TxcTheme.Text
        };
        var section = new Label
        {
            Text = "ЗАЩИТА",
            AutoSize = true,
            Location = new Point(18, 112),
            Font = new Font("Segoe UI Semibold", 8f),
            ForeColor = TxcTheme.Muted
        };
        var overview = new Button
        {
            Text = "  ◆  ЦЕНТР ЗАЩИТЫ",
            TextAlign = ContentAlignment.MiddleLeft,
            Location = new Point(6, 137),
            Size = new Size(217, 40),
            FlatStyle = FlatStyle.Flat,
            BackColor = TxcTheme.SurfaceRaised,
            ForeColor = TxcTheme.Accent,
            Font = new Font("Segoe UI Semibold", 9f),
            Cursor = Cursors.Hand,
            TabStop = false
        };
        overview.FlatAppearance.BorderSize = 0;
        overview.Click += (_, _) => { Restore(); _grid.Focus(); };

        var telemetryTitle = new Label
        {
            Text = "СОСТОЯНИЕ",
            AutoSize = true,
            Location = new Point(18, 211),
            Font = new Font("Segoe UI Semibold", 8f),
            ForeColor = TxcTheme.Muted
        };
        var localOnly = new Label
        {
            Text = "●  ЛОКАЛЬНАЯ ЗАЩИТА\r\n    без облачной телеметрии",
            Location = new Point(18, 239),
            Size = new Size(190, 48),
            ForeColor = TxcTheme.Green,
            Font = new Font("Segoe UI", 8.5f)
        };

        var statusCard = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 86,
            BackColor = TxcTheme.Surface,
            Padding = new Padding(14, 12, 10, 8)
        };
        var statusCaption = new Label
        {
            Text = "●  СТАТУС СИСТЕМЫ",
            Dock = DockStyle.Top,
            Height = 24,
            ForeColor = TxcTheme.Green,
            Font = new Font("Segoe UI Semibold", 8.5f)
        };
        _status.Text = "ЗАПУСК ЗАЩИТЫ…";
        _status.Dock = DockStyle.Fill;
        _status.ForeColor = TxcTheme.Muted;
        _status.Font = new Font("Segoe UI", 8f);
        _status.AutoEllipsis = true;
        statusCard.Controls.Add(_status);
        statusCard.Controls.Add(statusCaption);

        var version = new Label
        {
            Text = "v0.3.3  /  WINDOWS x64",
            Dock = DockStyle.Bottom,
            Height = 28,
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(18, 0, 0, 0),
            ForeColor = Color.FromArgb(92, 96, 106),
            Font = new Font("Consolas", 7.5f)
        };
        sidebar.Controls.Add(brand);
        sidebar.Controls.Add(product);
        sidebar.Controls.Add(section);
        sidebar.Controls.Add(overview);
        sidebar.Controls.Add(telemetryTitle);
        sidebar.Controls.Add(localOnly);
        sidebar.Controls.Add(statusCard);
        sidebar.Controls.Add(version);
        return sidebar;
    }

    private Control BuildWorkspace()
    {
        var workspace = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = TxcTheme.Window
        };
        var header = BuildHeader();
        var listHeader = new Panel
        {
            Dock = DockStyle.Top,
            Height = 62,
            BackColor = TxcTheme.Window,
            Padding = new Padding(22, 18, 22, 8)
        };
        var heading = new Label
        {
            Text = "СОБЫТИЯ ЗАЩИТЫ",
            AutoSize = true,
            Location = new Point(22, 18),
            Font = new Font("Segoe UI Semibold", 11f),
            ForeColor = TxcTheme.Text
        };
        _eventCount.Text = "0 СОБЫТИЙ";
        _eventCount.AutoSize = true;
        _eventCount.Location = new Point(184, 20);
        _eventCount.Font = new Font("Consolas", 8f);
        _eventCount.ForeColor = TxcTheme.Muted;
        listHeader.Controls.Add(heading);
        listHeader.Controls.Add(_eventCount);

        ConfigureGrid();
        var gridFrame = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = TxcTheme.Border,
            Padding = new Padding(1),
            Margin = Padding.Empty
        };
        _emptyState.Text = "◆\r\n\r\nУГРОЗ НЕ ОБНАРУЖЕНО\r\nмониторинг активен";
        _emptyState.Dock = DockStyle.Fill;
        _emptyState.TextAlign = ContentAlignment.MiddleCenter;
        _emptyState.BackColor = TxcTheme.Surface;
        _emptyState.ForeColor = TxcTheme.Muted;
        _emptyState.Font = new Font("Segoe UI Semibold", 10f);
        gridFrame.Controls.Add(_grid);
        gridFrame.Controls.Add(_emptyState);
        _emptyState.BringToFront();

        var gridPadding = new Panel
        {
            Dock = DockStyle.Fill,
            BackColor = TxcTheme.Window,
            Padding = new Padding(22, 0, 22, 16)
        };
        gridPadding.Controls.Add(gridFrame);
        var actions = BuildActions();

        workspace.Controls.Add(gridPadding);
        workspace.Controls.Add(actions);
        workspace.Controls.Add(listHeader);
        workspace.Controls.Add(header);
        return workspace;
    }

    private Panel BuildHeader()
    {
        var header = new Panel
        {
            Dock = DockStyle.Top,
            Height = 132,
            BackColor = TxcTheme.Window,
            Padding = new Padding(22, 22, 22, 14)
        };
        var eyebrow = new Label
        {
            Text = "TXC  /  SECURITY CENTER",
            AutoSize = true,
            Location = new Point(22, 19),
            ForeColor = TxcTheme.Accent,
            Font = new Font("Consolas", 8.5f, FontStyle.Bold)
        };
        var title = new Label
        {
            Text = "КОНТРОЛЬ УТЕЧКИ ДАННЫХ",
            AutoSize = true,
            Location = new Point(22, 46),
            ForeColor = TxcTheme.Text,
            Font = new Font("Segoe UI Semibold", 19f)
        };
        var subtitle = new Label
        {
            Text = "Процессы, сеть и хранилища сессий под наблюдением",
            AutoSize = true,
            Location = new Point(25, 87),
            ForeColor = TxcTheme.Muted,
            Font = new Font("Segoe UI", 9f)
        };
        var scan = MakeButton("ПРОВЕРИТЬ СЕЙЧАС", TxcTheme.Accent, TxcTheme.Accent, Color.FromArgb(18, 18, 18));
        scan.Width = 174;
        scan.Click += (_, _) =>
        {
            if (ServiceStateProbe.IsRunning())
            {
                _status.Text = ServiceStateProbe.RequestRescan()
                    ? "КОМАНДА ПРОВЕРКИ ПЕРЕДАНА"
                    : "НЕ УДАЛОСЬ СВЯЗАТЬСЯ СО СЛУЖБОЙ";
            }
            else
            {
                Engine.RescanAll();
            }
        };
        _startupButton.Width = 174;
        _startupButton.Click += (_, _) => ToggleStartup();
        header.Resize += (_, _) =>
        {
            scan.Left = header.ClientSize.Width - scan.Width - 22;
            _startupButton.Left = scan.Left - _startupButton.Width - 10;
            scan.Top = 44;
            _startupButton.Top = 44;
        };
        header.Controls.Add(eyebrow);
        header.Controls.Add(title);
        header.Controls.Add(subtitle);
        header.Controls.Add(_startupButton);
        header.Controls.Add(scan);
        return header;
    }

    private Control BuildActions()
    {
        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 75,
            Padding = new Padding(16, 13, 16, 10),
            BackColor = TxcTheme.Sidebar,
            WrapContents = false
        };
        var quarantine = MakeButton("В КАРАНТИН", TxcTheme.Surface, TxcTheme.Red, TxcTheme.Red);
        quarantine.Click += (_, _) => WithSelected(detection => Engine.Quarantine(detection));
        var terminate = MakeButton("ЗАВЕРШИТЬ", TxcTheme.Surface, TxcTheme.Amber, TxcTheme.Amber);
        terminate.Click += (_, _) => WithSelected(detection => Engine.Terminate(detection));
        var allow = MakeButton("РАЗРЕШИТЬ", TxcTheme.Surface, TxcTheme.Green, TxcTheme.Green);
        allow.Click += (_, _) => WithSelected(detection => Engine.Allow(detection));
        var trustFile = MakeButton("ДОВЕРЯТЬ ФАЙЛУ…", TxcTheme.Surface, TxcTheme.Blue, TxcTheme.Blue);
        trustFile.Width = 172;
        trustFile.Click += (_, _) => TrustSelectedFile();
        actions.Controls.Add(quarantine);
        actions.Controls.Add(terminate);
        actions.Controls.Add(allow);
        actions.Controls.Add(trustFile);
        return actions;
    }

    private void ConfigureGrid()
    {
        _grid.Dock = DockStyle.Fill;
        _grid.BackgroundColor = TxcTheme.Surface;
        _grid.BorderStyle = BorderStyle.None;
        _grid.GridColor = TxcTheme.BorderSoft;
        _grid.AutoGenerateColumns = false;
        _grid.AllowUserToAddRows = false;
        _grid.AllowUserToDeleteRows = false;
        _grid.AllowUserToResizeRows = false;
        _grid.ReadOnly = true;
        _grid.MultiSelect = false;
        _grid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _grid.RowHeadersVisible = false;
        _grid.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
        _grid.ColumnHeadersBorderStyle = DataGridViewHeaderBorderStyle.None;
        _grid.ColumnHeadersHeight = 38;
        _grid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        _grid.RowTemplate.Height = 38;
        _grid.DefaultCellStyle.BackColor = TxcTheme.Surface;
        _grid.DefaultCellStyle.ForeColor = TxcTheme.Text;
        _grid.DefaultCellStyle.SelectionBackColor = TxcTheme.SurfaceRaised;
        _grid.DefaultCellStyle.SelectionForeColor = TxcTheme.Text;
        _grid.DefaultCellStyle.Padding = new Padding(8, 0, 4, 0);
        _grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(13, 13, 13);
        _grid.ColumnHeadersDefaultCellStyle.BackColor = TxcTheme.Sidebar;
        _grid.ColumnHeadersDefaultCellStyle.ForeColor = TxcTheme.Accent;
        _grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 8.5f);
        _grid.EnableHeadersVisualStyles = false;
        _grid.DataSource = _events;
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "ВРЕМЯ", DataPropertyName = "Time", Width = 130, DefaultCellStyle = new DataGridViewCellStyle { Format = "dd.MM  HH:mm:ss" } });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "РИСК", DataPropertyName = "Risk", Width = 70 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "ПРОЦЕСС", DataPropertyName = "ProcessName", Width = 145 });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "ФАЙЛ", DataPropertyName = "FilePath", AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill });
        _grid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = "СТАТУС", DataPropertyName = "Status", Width = 210 });
    }

    private void ConfigureTray()
    {
        _trayMenu.ShowImageMargin = false;
        _trayMenu.Padding = new Padding(4, 6, 4, 6);
        _trayMenu.Items.Add("Открыть TXC AntiStealer", null, (_, _) => Restore());
        _trayMenu.Items.Add(new ToolStripSeparator());
        _trayMenu.Items.Add("Проверить сейчас", null, (_, _) => RequestScan());
        _trayMenu.Items.Add(new ToolStripSeparator());
        _trayMenu.Items.Add("Выход", null, (_, _) => { _exitRequested = true; Close(); });
        ApplyTrayTheme();
        _tray.Icon = Icon;
        _tray.Text = "TXC AntiStealer — защита активна";
        _tray.ContextMenuStrip = _trayMenu;
        _tray.Visible = true;
        _tray.DoubleClick += (_, _) => Restore();
    }

    private void ApplyTrayTheme()
    {
        var dark = TxcTheme.SystemUsesDarkApps();
        _trayMenu.Renderer = new TxcToolStripRenderer(dark);
        _trayMenu.BackColor = dark ? Color.FromArgb(29, 29, 29) : Color.FromArgb(248, 248, 248);
        _trayMenu.ForeColor = dark ? Color.WhiteSmoke : Color.FromArgb(24, 24, 24);
        foreach (ToolStripItem item in _trayMenu.Items)
            item.ForeColor = _trayMenu.ForeColor;
    }

    private void OnUserPreferenceChanged(object sender, UserPreferenceChangedEventArgs e)
    {
        if (IsDisposed || !IsHandleCreated)
            return;
        try { BeginInvoke(ApplyTrayTheme); } catch { }
    }

    private void RequestScan()
    {
        if (ServiceStateProbe.IsRunning())
            ServiceStateProbe.RequestRescan();
        else
            Engine.RescanAll();
    }

    private void HandleDetection(DetectionEvent detection)
    {
        _events.Insert(0, detection);
        UpdateEventSummary();
        ShowToast(
            "УГРОЗА ЗАБЛОКИРОВАНА",
            $"{detection.ProcessName}: интернет отключён. Нажми, чтобы открыть подробности.",
            TxcTheme.Red);
        _grid.Refresh();
    }

    private void HandleTamper(string message)
    {
        _status.Text = "ПОПЫТКА ОСЛАБИТЬ ЗАЩИТУ ОСТАНОВЛЕНА";
        ShowToast("ЗАЩИТА ВОССТАНОВЛЕНА", message, TxcTheme.Amber);
    }

    private void HandleServiceNotification(UserNotification notification)
    {
        if (notification.Detection is { } detection)
        {
            var duplicate = _events.Any(item =>
                item.Time == detection.Time && item.ProcessId == detection.ProcessId &&
                string.Equals(item.FilePath, detection.FilePath, StringComparison.OrdinalIgnoreCase));
            if (!duplicate)
                _events.Insert(0, detection);
            UpdateEventSummary();
            _grid.Refresh();
        }

        var accent = notification.Kind.Equals("tamper", StringComparison.OrdinalIgnoreCase)
            ? TxcTheme.Amber
            : TxcTheme.Red;
        ShowToast(notification.Title.ToUpperInvariant(), notification.Message, accent);
    }

    private void UpdateEventSummary()
    {
        _eventCount.Text = $"{_events.Count} СОБЫТИЙ";
        _emptyState.Visible = _events.Count == 0;
    }

    private void ShowToast(string title, string message, Color accent)
    {
        _toast?.Close();
        _toast = new AlertToastForm(title, message, accent, () =>
        {
            Restore();
            if (_grid.Rows.Count > 0)
                _grid.Rows[0].Selected = true;
        });
        _toast.FormClosed += (_, _) => _toast = null;
        _toast.Show();
    }

    private void ShowTrayStatusToast()
    {
        _trayStatusToast?.Close();
        _trayStatusToast = new TrayStatusToastForm(Restore);
        _trayStatusToast.FormClosed += (_, _) => _trayStatusToast = null;
        _trayStatusToast.Show();
    }

    private void WithSelected(Action<DetectionEvent> action)
    {
        if (_grid.CurrentRow?.DataBoundItem is not DetectionEvent detection)
        {
            MessageBox.Show("Сначала выберите событие в таблице.", "TXC / AntiStealer", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        action(detection);
        _grid.Refresh();
    }

    private static Button MakeButton(string text, Color fill, Color border, Color foreground) => new()
    {
        Text = text,
        Width = 145,
        Height = 40,
        BackColor = fill,
        ForeColor = foreground,
        FlatStyle = FlatStyle.Flat,
        Cursor = Cursors.Hand,
        Margin = new Padding(6),
        Font = new Font("Segoe UI Semibold", 8.5f),
        FlatAppearance = { BorderColor = border, BorderSize = 1, MouseOverBackColor = TxcTheme.SurfaceRaised }
    };

    private static Button MakeCaptionButton(string text, bool closeButton = false)
    {
        var button = new Button
        {
            Text = text,
            Size = new Size(46, 39),
            Top = 0,
            FlatStyle = FlatStyle.Flat,
            BackColor = TxcTheme.TitleBar,
            ForeColor = TxcTheme.Muted,
            Font = new Font("Segoe UI", text == "×" ? 13f : 9f),
            TabStop = false
        };
        button.FlatAppearance.BorderSize = 0;
        button.FlatAppearance.MouseOverBackColor = closeButton ? Color.FromArgb(170, 45, 45) : Color.FromArgb(28, 28, 28);
        button.FlatAppearance.MouseDownBackColor = closeButton ? Color.FromArgb(140, 35, 35) : Color.FromArgb(42, 42, 42);
        return button;
    }

    private void Restore()
    {
        Show();
        if (WindowState == FormWindowState.Minimized)
            WindowState = FormWindowState.Normal;
        Activate();
    }

    private void TrustSelectedFile()
    {
        using var picker = new OpenFileDialog
        {
            Title = "Выберите конкретный EXE для доверия по SHA-256",
            Filter = "Программы Windows (*.exe)|*.exe|Все файлы (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false
        };
        if (picker.ShowDialog(this) != DialogResult.OK)
            return;

        try
        {
            var hash = Engine.TrustFile(picker.FileName);
            MessageBox.Show(
                $"Файл добавлен в исключения по его текущему SHA-256:\r\n{hash}\r\n\r\nПосле обновления файла потребуется подтвердить новую версию.",
                "TXC / AntiStealer — доверенный файл",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show("Не удалось добавить файл: " + ex.Message, "TXC / AntiStealer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void ToggleStartup()
    {
        try
        {
            if (StartupManager.IsEnabled())
                StartupManager.Disable();
            else
                StartupManager.Enable(Environment.ProcessPath ?? throw new InvalidOperationException("Не найден путь программы"));
            RefreshStartupButton();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Не удалось изменить автозапуск: " + ex.Message, "TXC / AntiStealer", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void RefreshStartupButton()
    {
        if (ServiceStateProbe.IsRunning())
        {
            _startupButton.Text = "СЛУЖБА АКТИВНА";
            StyleButton(_startupButton, TxcTheme.Surface, TxcTheme.Green, TxcTheme.Green);
            _startupButton.Enabled = false;
            return;
        }

        _startupButton.Enabled = true;
        var enabled = StartupManager.IsEnabled();
        _startupButton.Text = enabled ? "АВТОЗАПУСК ВКЛ" : "АВТОЗАПУСК ВЫКЛ";
        StyleButton(_startupButton, enabled ? TxcTheme.SurfaceRaised : TxcTheme.Surface,
            enabled ? TxcTheme.Accent : TxcTheme.Border,
            enabled ? TxcTheme.Accent : TxcTheme.Muted);
    }

    private static void StyleButton(Button button, Color fill, Color border, Color foreground)
    {
        button.BackColor = fill;
        button.ForeColor = foreground;
        button.FlatAppearance.BorderColor = border;
    }

    private void StartProtectionLayer()
    {
        if (ServiceStateProbe.IsRunning())
        {
            _status.Text = "СЛУЖБА ANTISTEALER АКТИВНА";
            _serviceNotifications.Start();
        }
        else
        {
            _status.Text = "ЛОКАЛЬНЫЙ РЕЖИМ ЗАЩИТЫ";
            Engine.Start();
        }
        RefreshStartupButton();
    }

    private void ToggleMaximize()
    {
        if (WindowState == FormWindowState.Maximized)
        {
            WindowState = FormWindowState.Normal;
            return;
        }
        MaximizedBounds = Screen.FromHandle(Handle).WorkingArea;
        WindowState = FormWindowState.Maximized;
    }

    private void DragWindow(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left)
            return;
        ReleaseCapture();
        SendMessage(Handle, WmNcLButtonDown, new IntPtr(HtCaption), IntPtr.Zero);
    }

    protected override void WndProc(ref Message message)
    {
        base.WndProc(ref message);
        if (message.Msg != WmNcHitTest || WindowState != FormWindowState.Normal || (int)message.Result != 1)
            return;

        const int border = 7;
        var packed = message.LParam.ToInt64();
        var point = PointToClient(new Point(unchecked((short)packed), unchecked((short)(packed >> 16))));
        var left = point.X <= border;
        var right = point.X >= ClientSize.Width - border;
        var top = point.Y <= border;
        var bottom = point.Y >= ClientSize.Height - border;
        message.Result = (left, right, top, bottom) switch
        {
            (true, _, true, _) => new IntPtr(13),
            (_, true, true, _) => new IntPtr(14),
            (true, _, _, true) => new IntPtr(16),
            (_, true, _, true) => new IntPtr(17),
            (true, _, _, _) => new IntPtr(10),
            (_, true, _, _) => new IntPtr(11),
            (_, _, true, _) => new IntPtr(12),
            (_, _, _, true) => new IntPtr(15),
            _ => message.Result
        };
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (!_exitRequested && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            ShowTrayStatusToast();
            return;
        }

        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        _tray.Visible = false;
        _tray.Dispose();
        _trayMenu.Dispose();
        _toast?.Close();
        _trayStatusToast?.Close();
        _serviceNotifications.Dispose();
        _uiPresence?.Dispose();
        _engine?.Dispose();
    }

    private ProtectionEngine Engine => _engine ?? throw new InvalidOperationException("Движок недоступен в режиме предварительного просмотра.");
}
