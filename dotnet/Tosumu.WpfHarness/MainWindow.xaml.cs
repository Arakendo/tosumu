using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using Tosumu.Cli;

namespace Tosumu.WpfHarness;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private const int MaxRecentDatabaseCount = 8;

    private string databasePath = string.Empty;
    private string executableStateText = "Packaged CLI will be resolved on first command.";
    private string pageNumberText = "1";
    private string pageSummaryText = "No page loaded yet.";
    private string statusText = "Choose a .tsm file, then inspect the header or run verification.";
    private string verifySummaryText = "No verification run yet.";
    private readonly string sessionStatePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Tosumu",
        "WpfHarness",
        "session.json");
    private TosumuCliTool? cli;

    public MainWindow()
    {
        InitializeComponent();
        Closing += MainWindow_OnClosing;
        DataContext = this;
        UnlockModeComboBox.SelectedIndex = 0;
        UpdateUnlockInputs();
        HeaderRows.Add(new HeaderFieldRow("State", "No header loaded yet."));
        VerifyIssues.Add(new VerifyIssueRow("-", "No verification run yet."));
        PageResults.Add(new PageVerifyRow("-", "-", "-", "No verification run yet."));
        PageRecords.Add(new PageRecordRow("-", "-", "-", "No page loaded yet.", "-", "-", "-"));
        ProtectorSlots.Add(new ProtectorSlotRow("-", "No protector data loaded yet.", "-"));
        LoadSessionState();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<HeaderFieldRow> HeaderRows { get; } = [];

    public ObservableCollection<VerifyIssueRow> VerifyIssues { get; } = [];

    public ObservableCollection<PageVerifyRow> PageResults { get; } = [];

    public ObservableCollection<PageRecordRow> PageRecords { get; } = [];

    public ObservableCollection<ProtectorSlotRow> ProtectorSlots { get; } = [];

    public ObservableCollection<string> RecentDatabasePaths { get; } = [];

    public string DatabasePath
    {
        get => databasePath;
        set => SetProperty(ref databasePath, value);
    }

    public string ExecutableStateText
    {
        get => executableStateText;
        set => SetProperty(ref executableStateText, value);
    }

    public string PageNumberText
    {
        get => pageNumberText;
        set => SetProperty(ref pageNumberText, value);
    }

    public string PageSummaryText
    {
        get => pageSummaryText;
        set => SetProperty(ref pageSummaryText, value);
    }

    public string StatusText
    {
        get => statusText;
        set => SetProperty(ref statusText, value);
    }

    public string VerifySummaryText
    {
        get => verifySummaryText;
        set => SetProperty(ref verifySummaryText, value);
    }

    private async void LoadHeaderButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        await RunBusyActionAsync(async () =>
        {
            StatusText = "Loading header...";
            AddRecentDatabasePath(path);
            await LoadHeaderAsync(path);

            StatusText = $"Loaded header for {System.IO.Path.GetFileName(path)}.";
        });
    }

    private async void VerifyButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        if (!TryGetUnlockSelection("verify the database", out var unlockSelection))
        {
            return;
        }

        await RunUnlockableInspectActionAsync(unlockSelection, async unlock =>
        {
            StatusText = "Running verification...";
            AddRecentDatabasePath(path);
            await LoadVerifyAsync(path, unlock);

            StatusText = $"Verification finished for {System.IO.Path.GetFileName(path)}.";
        });
    }

    private async void InspectPageButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path) || !TryGetPageNumber(out var pageNumber))
        {
            return;
        }

        if (!TryGetUnlockSelection("inspect the page", out var unlockSelection))
        {
            return;
        }

        await RunUnlockableInspectActionAsync(unlockSelection, async unlock =>
        {
            StatusText = $"Inspecting page {pageNumber}...";
            AddRecentDatabasePath(path);
            await LoadPageAsync(path, pageNumber, unlock);

            StatusText = $"Loaded page {pageNumber} from {System.IO.Path.GetFileName(path)}.";
        });
    }

    private async void InspectProtectorsButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        await RunBusyActionAsync(async () =>
        {
            StatusText = "Loading protectors...";
            AddRecentDatabasePath(path);
            await LoadProtectorsAsync(path);

            StatusText = $"Loaded protectors for {System.IO.Path.GetFileName(path)}.";
        });
    }

    private async void InspectRootPageButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        if (!TryGetUnlockSelection("inspect the root page", out var unlockSelection))
        {
            return;
        }

        await RunUnlockableInspectActionAsync(unlockSelection, async unlock =>
        {
            StatusText = "Loading header and root page...";
            AddRecentDatabasePath(path);

            var header = await LoadHeaderAsync(path);
            PageNumberText = header.RootPage.ToString();
            await LoadPageAsync(path, header.RootPage, unlock);

            StatusText = $"Loaded root page {header.RootPage} from {System.IO.Path.GetFileName(path)}.";
        });
    }

    private async void RefreshAllButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        if (!TryGetUnlockSelection("refresh inspect data", out var unlockSelection))
        {
            return;
        }

        var hasPageNumber = ulong.TryParse(PageNumberText.Trim(), out var pageNumber);

        await RunUnlockableInspectActionAsync(unlockSelection, async unlock =>
        {
            StatusText = "Refreshing header, verify, protectors, and page...";
            AddRecentDatabasePath(path);

            await LoadHeaderAsync(path);
            await LoadProtectorsAsync(path);
            await LoadVerifyAsync(path, unlock);

            if (hasPageNumber)
            {
                await LoadPageAsync(path, pageNumber, unlock);
                StatusText = $"Refreshed all views for {System.IO.Path.GetFileName(path)}.";
            }
            else
            {
                StatusText = $"Refreshed header, verify, and protectors for {System.IO.Path.GetFileName(path)}. Page refresh skipped because the page number is invalid.";
            }
        });
    }

    private void BrowseButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a Tosumu database",
            Filter = "Tosumu database (*.tsm)|*.tsm|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) == true)
        {
            DatabasePath = dialog.FileName;
            AddRecentDatabasePath(dialog.FileName);
            StatusText = $"Selected {System.IO.Path.GetFileName(dialog.FileName)}.";
        }
    }

    private void RecentDatabasesComboBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (RecentDatabasesComboBox.SelectedItem is not string path || string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        DatabasePath = path;
        StatusText = $"Selected recent database {System.IO.Path.GetFileName(path)}.";
    }

    private async Task RunUnlockableInspectActionAsync(
        HarnessUnlockSelection? unlockSelection,
        Func<TosumuInspectUnlockOptions?, Task> action)
    {
        SetBusy(true);

        try
        {
            while (true)
            {
                try
                {
                    await action(unlockSelection?.ToUnlockOptions());
                    return;
                }
                catch (TosumuInspectCommandException ex) when (string.Equals(ex.ErrorKind, "wrong_key", StringComparison.Ordinal))
                {
                    StatusText = "Unlock required or provided secret was rejected.";
                    SetBusy(false);

                    if (!TryPromptForUnlockRetry(out unlockSelection))
                    {
                        StatusText = "Unlock retry cancelled.";
                        return;
                    }

                    ApplyUnlockSelection(unlockSelection);
                    SetBusy(true);
                }
            }
        }
        catch (Exception ex)
        {
            StatusText = "Last command failed.";
            MessageBox.Show(this, ex.Message, "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void BrowseKeyfileButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose a Tosumu keyfile",
            Filter = "All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) == true)
        {
            KeyfilePathTextBox.Text = dialog.FileName;
        }
    }

    private void MainWindow_OnClosing(object? sender, CancelEventArgs e)
    {
        SaveSessionState();
    }

    private void UnlockModeComboBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateUnlockInputs();
    }

    private TosumuCliTool GetCli()
    {
        cli ??= new TosumuCliTool();
        ExecutableStateText = cli.ExecutablePath;
        return cli;
    }

    private async Task<TosumuInspectHeaderPayload> LoadHeaderAsync(string path)
    {
        var header = await GetCli().GetHeaderAsync(path);

        HeaderRows.Clear();
        HeaderRows.Add(new HeaderFieldRow("Format version", header.FormatVersion.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Page size", header.PageSize.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Min reader version", header.MinReaderVersion.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Flags", $"0x{header.Flags:X4}"));
        HeaderRows.Add(new HeaderFieldRow("Page count", header.PageCount.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Freelist head", header.FreelistHead.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Root page", header.RootPage.ToString()));
        HeaderRows.Add(new HeaderFieldRow("WAL checkpoint LSN", header.WalCheckpointLsn.ToString()));
        HeaderRows.Add(new HeaderFieldRow("DEK id", header.DekId.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Keyslot count", header.KeyslotCount.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Keyslot region pages", header.KeyslotRegionPages.ToString()));
        HeaderRows.Add(new HeaderFieldRow("Slot 0 kind", $"{header.Slot0.Kind} ({header.Slot0.KindByte})"));
        HeaderRows.Add(new HeaderFieldRow("Slot 0 version", header.Slot0.Version.ToString()));

        return header;
    }

    private async Task LoadVerifyAsync(string path, TosumuInspectUnlockOptions? unlock)
    {
        var verify = await GetCli().GetVerifyAsync(path, unlock);

        VerifySummaryText =
            $"Pages checked: {verify.PagesChecked}\n" +
            $"Pages ok: {verify.PagesOk}\n" +
            $"Issue count: {verify.IssueCount}\n" +
            $"B-tree checked: {verify.Btree.Checked}\n" +
            $"B-tree ok: {verify.Btree.Ok}\n" +
            $"B-tree message: {verify.Btree.Message ?? "(none)"}";

        VerifyIssues.Clear();
        if (verify.Issues.Count == 0)
        {
            VerifyIssues.Add(new VerifyIssueRow("-", "No issues reported."));
        }
        else
        {
            foreach (var issue in verify.Issues)
            {
                VerifyIssues.Add(new VerifyIssueRow(issue.Pgno.ToString(), issue.Description));
            }
        }

        PageResults.Clear();
        foreach (var result in verify.PageResults)
        {
            PageResults.Add(new PageVerifyRow(
                result.Pgno.ToString(),
                result.AuthOk ? "ok" : "fail",
                result.PageVersion?.ToString() ?? "-",
                string.IsNullOrWhiteSpace(result.Issue) ? "-" : result.Issue));
        }
    }

    private async Task LoadPageAsync(string path, ulong pageNumber, TosumuInspectUnlockOptions? unlock)
    {
        var page = await GetCli().GetPageAsync(path, pageNumber, unlock);

        PageSummaryText =
            $"Page {page.Pgno} · {page.PageTypeName} (0x{page.PageType:X2})\n" +
            $"Version: {page.PageVersion} · Slots: {page.SlotCount}\n" +
            $"Free start: {page.FreeStart} · Free end: {page.FreeEnd} · Free bytes: {Math.Max(0, page.FreeEnd - page.FreeStart)}";

        PageRecords.Clear();
        if (page.Records.Count == 0)
        {
            PageRecords.Add(new PageRecordRow("-", "-", "-", "No decoded records on this page.", "-", "-", "-"));
        }
        else
        {
            foreach (var record in page.Records)
            {
                var keyPreview = FormatAsciiPreview(record.KeyHex);
                var valuePreview = FormatAsciiPreview(record.ValueHex);
                PageRecords.Add(new PageRecordRow(
                    record.Kind,
                    record.Slot?.ToString() ?? "-",
                    record.RecordType is null ? "-" : $"0x{record.RecordType:X2}",
                    keyPreview,
                    record.KeyHex ?? "-",
                    valuePreview,
                    record.ValueHex ?? "-"));
            }
        }
    }

    private async Task LoadProtectorsAsync(string path)
    {
        var protectors = await GetCli().GetProtectorsAsync(path);

        ProtectorSlots.Clear();
        if (protectors.Slots.Count == 0)
        {
            ProtectorSlots.Add(new ProtectorSlotRow("-", "No protectors reported.", "-"));
        }
        else
        {
            foreach (var slot in protectors.Slots)
            {
                ProtectorSlots.Add(new ProtectorSlotRow(slot.Slot.ToString(), slot.Kind, slot.KindByte.ToString()));
            }
        }
    }

    private bool TryGetValidDatabasePath(out string path)
    {
        path = DatabasePath.Trim();

        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(this, "Choose a database file first.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
            return false;
        }

        if (!System.IO.File.Exists(path))
        {
            MessageBox.Show(this, $"Database file not found:\n{path}", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        return true;
    }

    private void LoadSessionState()
    {
        var sessionState = HarnessSessionState.Load(sessionStatePath);

        RecentDatabasePaths.Clear();
        foreach (var path in sessionState.RecentDatabasePaths.Where(path => !string.IsNullOrWhiteSpace(path)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            RecentDatabasePaths.Add(path);
        }

        if (!string.IsNullOrWhiteSpace(sessionState.LastDatabasePath))
        {
            DatabasePath = sessionState.LastDatabasePath;
            AddRecentDatabasePath(sessionState.LastDatabasePath);
            StatusText = $"Restored last database {System.IO.Path.GetFileName(sessionState.LastDatabasePath)}.";
        }

        if (!string.IsNullOrWhiteSpace(sessionState.LastPageNumber))
        {
            PageNumberText = sessionState.LastPageNumber;
        }

        if (!string.IsNullOrWhiteSpace(sessionState.UnlockMode))
        {
            SelectUnlockMode(sessionState.UnlockMode);
        }

        if (!string.IsNullOrWhiteSpace(sessionState.KeyfilePath))
        {
            KeyfilePathTextBox.Text = sessionState.KeyfilePath;
        }
    }

    private void SaveSessionState()
    {
        var sessionState = new HarnessSessionState
        {
            LastDatabasePath = string.IsNullOrWhiteSpace(DatabasePath) ? null : DatabasePath.Trim(),
            LastPageNumber = string.IsNullOrWhiteSpace(PageNumberText) ? null : PageNumberText.Trim(),
            UnlockMode = GetSelectedUnlockMode(),
            KeyfilePath = string.IsNullOrWhiteSpace(KeyfilePathTextBox.Text) ? null : KeyfilePathTextBox.Text.Trim(),
            RecentDatabasePaths = RecentDatabasePaths.ToList(),
        };

        HarnessSessionState.Save(sessionStatePath, sessionState);
    }

    private void AddRecentDatabasePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        var normalizedPath = path.Trim();
        var existingIndex = RecentDatabasePaths
            .Select((item, index) => new { item, index })
            .FirstOrDefault(entry => string.Equals(entry.item, normalizedPath, StringComparison.OrdinalIgnoreCase))
            ?.index;

        if (existingIndex is int index)
        {
            RecentDatabasePaths.RemoveAt(index);
        }

        RecentDatabasePaths.Insert(0, normalizedPath);
        while (RecentDatabasePaths.Count > MaxRecentDatabaseCount)
        {
            RecentDatabasePaths.RemoveAt(RecentDatabasePaths.Count - 1);
        }

        if (RecentDatabasesComboBox is not null)
        {
            RecentDatabasesComboBox.SelectedItem = normalizedPath;
        }
    }

    private bool TryGetPageNumber(out ulong pageNumber)
    {
        if (!ulong.TryParse(PageNumberText.Trim(), out pageNumber))
        {
            MessageBox.Show(this, "Enter a valid non-negative page number.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
            return false;
        }

        return true;
    }

    private async Task RunBusyActionAsync(Func<Task> action)
    {
        SetBusy(true);

        try
        {
            await action();
        }
        catch (Exception ex)
        {
            StatusText = "Last command failed.";
            MessageBox.Show(this, ex.Message, "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void SetBusy(bool isBusy)
    {
        BrowseButton.IsEnabled = !isBusy;
        BrowseKeyfileButton.IsEnabled = !isBusy;
        InspectProtectorsButton.IsEnabled = !isBusy;
        InspectRootPageButton.IsEnabled = !isBusy;
        RefreshAllButton.IsEnabled = !isBusy;
        InspectPageButton.IsEnabled = !isBusy;
        LoadHeaderButton.IsEnabled = !isBusy;
        VerifyButton.IsEnabled = !isBusy;
        DatabasePathTextBox.IsEnabled = !isBusy;
        UnlockModeComboBox.IsEnabled = !isBusy;
        KeyfilePathTextBox.IsEnabled = !isBusy;
        PageNumberTextBox.IsEnabled = !isBusy;
        SecretPasswordBox.IsEnabled = !isBusy;
    }

    private bool TryGetUnlockSelection(string operationText, out HarnessUnlockSelection? unlockSelection)
    {
        switch (GetSelectedUnlockMode())
        {
            case HarnessUnlockModes.Auto:
                unlockSelection = null;
                return true;
            case HarnessUnlockModes.Passphrase:
            case HarnessUnlockModes.RecoveryKey:
                var secret = SecretPasswordBox.Password;
                if (string.IsNullOrWhiteSpace(secret))
                {
                    MessageBox.Show(this, $"Enter the secret before trying to {operationText}.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
                    unlockSelection = null;
                    return false;
                }

                unlockSelection = new HarnessUnlockSelection(GetSelectedUnlockMode(), secret);
                return true;
            case HarnessUnlockModes.Keyfile:
                var keyfilePath = KeyfilePathTextBox.Text.Trim();
                if (string.IsNullOrWhiteSpace(keyfilePath))
                {
                    MessageBox.Show(this, $"Choose a keyfile path before trying to {operationText}.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
                    unlockSelection = null;
                    return false;
                }

                if (!System.IO.File.Exists(keyfilePath))
                {
                    MessageBox.Show(this, $"Keyfile not found:\n{keyfilePath}", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Warning);
                    unlockSelection = null;
                    return false;
                }

                unlockSelection = new HarnessUnlockSelection(HarnessUnlockModes.Keyfile, keyfilePath);
                return true;
            default:
                unlockSelection = null;
                return true;
        }
    }

    private bool TryPromptForUnlockRetry(out HarnessUnlockSelection? unlockSelection)
    {
        var prompt = new UnlockPromptWindow(
            "The last inspect request could not unlock the database. Choose credentials for an immediate retry.",
            GetSelectedUnlockMode(),
            KeyfilePathTextBox.Text.Trim())
        {
            Owner = this,
        };

        var accepted = prompt.ShowDialog() == true;
        unlockSelection = accepted ? prompt.UnlockSelection : null;
        return accepted && unlockSelection is not null;
    }

    private string GetSelectedUnlockMode()
    {
        return (UnlockModeComboBox.SelectedItem as ComboBoxItem)?.Tag as string ?? HarnessUnlockModes.Auto;
    }

    private void UpdateUnlockInputs()
    {
        if (SecretLabelTextBlock is null || SecretPasswordBox is null || KeyfilePathTextBox is null || BrowseKeyfileButton is null)
        {
            return;
        }

        var selectedMode = GetSelectedUnlockMode();
        var usesSecret = selectedMode is HarnessUnlockModes.Passphrase or HarnessUnlockModes.RecoveryKey;
        var usesKeyfile = selectedMode == HarnessUnlockModes.Keyfile;

        SecretLabelTextBlock.Visibility = usesSecret ? Visibility.Visible : Visibility.Collapsed;
        SecretPasswordBox.Visibility = usesSecret ? Visibility.Visible : Visibility.Collapsed;
        KeyfilePathTextBox.Visibility = usesKeyfile ? Visibility.Visible : Visibility.Collapsed;
        BrowseKeyfileButton.Visibility = usesKeyfile ? Visibility.Visible : Visibility.Collapsed;

        SecretLabelTextBlock.Text = selectedMode == HarnessUnlockModes.RecoveryKey ? "Recovery key" : "Passphrase";

        if (!usesSecret)
        {
            SecretPasswordBox.Password = string.Empty;
        }

        if (!usesKeyfile)
        {
            KeyfilePathTextBox.Text = string.Empty;
        }
    }

    private void ApplyUnlockSelection(HarnessUnlockSelection? unlockSelection)
    {
        SelectUnlockMode(unlockSelection?.Mode ?? HarnessUnlockModes.Auto);

        if (unlockSelection is null)
        {
            SecretPasswordBox.Password = string.Empty;
            KeyfilePathTextBox.Text = string.Empty;
            return;
        }

        switch (unlockSelection.Mode)
        {
            case HarnessUnlockModes.Passphrase:
            case HarnessUnlockModes.RecoveryKey:
                SecretPasswordBox.Password = unlockSelection.Value;
                break;
            case HarnessUnlockModes.Keyfile:
                KeyfilePathTextBox.Text = unlockSelection.Value;
                break;
        }
    }

    private void SelectUnlockMode(string mode)
    {
        foreach (var item in UnlockModeComboBox.Items)
        {
            if (item is ComboBoxItem comboBoxItem && string.Equals(comboBoxItem.Tag as string, mode, StringComparison.Ordinal))
            {
                UnlockModeComboBox.SelectedItem = comboBoxItem;
                return;
            }
        }

        UnlockModeComboBox.SelectedIndex = 0;
    }

    private static string FormatAsciiPreview(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex == "-")
        {
            return "-";
        }

        try
        {
            var bytes = Convert.FromHexString(hex);
            if (bytes.Length == 0)
            {
                return "(empty)";
            }

            foreach (var value in bytes)
            {
                if (value < 0x20 || value > 0x7E)
                {
                    return "(binary)";
                }
            }

            return string.Concat(bytes.Select(value => (char)value));
        }
        catch (FormatException)
        {
            return "(invalid)";
        }
    }

    private void SetProperty<T>(ref T field, T value, [CallerMemberName] string? propertyName = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return;
        }

        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

public sealed record HeaderFieldRow(string Label, string Value);

public sealed record VerifyIssueRow(string Pgno, string Description);

public sealed record PageVerifyRow(string Pgno, string AuthOkLabel, string PageVersionLabel, string Issue);

public sealed record PageRecordRow(string Kind, string Slot, string RecordType, string KeyPreview, string KeyHex, string ValuePreview, string ValueHex);

public sealed record ProtectorSlotRow(string Slot, string Kind, string KindByte);