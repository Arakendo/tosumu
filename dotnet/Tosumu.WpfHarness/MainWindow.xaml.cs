using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Web.WebView2.Core;
using Microsoft.Win32;
using Tosumu.Cli;

namespace Tosumu.WpfHarness;

public partial class MainWindow : Window, INotifyPropertyChanged
{
    private sealed record TreePageVisitState(ulong PageNumber, string PageTypeName);
    private static readonly JsonSerializerOptions TreeWebViewJsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private const int MaxRecentDatabaseCount = 8;
    private const int MaxDebugLogChars = 50_000;
    private const int MaxTreePageHistoryCount = 10;
    private const double KeyHexColumnVisibleWidth = 320;
    private const double ValueHexColumnVisibleWidth = 420;

    private string databasePath = string.Empty;
    private string currentDatabaseDetailText = "Browse to a .tsm file to enter inspection mode. The header will load automatically.";
    private string currentDatabaseTitleText = "No database selected";
    private string executableStateText = "Packaged CLI will be resolved on first command.";
    private bool isUpdatingRecentSelection;
    private string pageNumberText = "1";
    private string selectedRecordDetailText = "Select a non-placeholder record to inspect the current key/value payloads.";
    private string selectedRecordHeadlineText = "No record selected";
    private string pageSummaryText = "Select a page or inspect root to decode the current page.";
    private bool showHexColumns;
    private string statusText = "Activity updates appear here while you browse, verify, and inspect pages.";
    private ulong? treeFocusPageNumber;
    private string treeFocusPageTypeName = string.Empty;
    private string treeFocusText = "Focus page: inspect root or another page to begin tree navigation.";
    private ulong? treeRootPageNumber;
    private string treeRootText = "Root page: load a database header to discover the tree root.";
    private string treeTrustText = "Trust: verify pending";
    private string unlockModeHintText = "You will be prompted only if the current database actually requires credentials.";
    private Brush verifyIssueSummaryBrush = Brushes.Transparent;
    private string verifyIssueSummaryText = string.Empty;
    private Visibility verifyIssueSummaryVisibility = Visibility.Collapsed;
    private Brush verificationBadgeBrush = Brushes.Khaki;
    private string verificationBadgeText = "Verify pending";
    private string verifySummaryText = "Run verification to check page auth and B-tree integrity.";
    private TosumuInspectTreePayload? treeSnapshot;
    private readonly ConcurrentQueue<string> debugLogBuffer = new();
    private readonly List<TreePageVisitState> treePageVisitStates = [];
    private readonly string sessionStatePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Tosumu",
        "WpfHarness",
        "session.json");
    private DispatcherTimer? debugLogFlushTimer;
    private bool restoreDatabaseOnLoad;
    private Task? treeWebViewInitializationTask;
    private TosumuCliTool? cli;

    public MainWindow()
    {
        InitializeComponent();
        Closing += MainWindow_OnClosing;
        Loaded += MainWindow_OnLoaded;
        DataContext = this;
        UnlockModeComboBox.SelectedIndex = 0;
        debugLogFlushTimer = new DispatcherTimer(
            TimeSpan.FromMilliseconds(150),
            DispatcherPriority.Background,
            (_, _) => FlushDebugLog(),
            Dispatcher);
        debugLogFlushTimer.Start();
        UpdateUnlockInputs();
        UpdateHexColumnVisibility();
        ResetHeaderState("Open a database to load the header automatically.");
        ResetVerifyState();
        ResetPageState();
        ResetProtectorsState();
        LoadSessionState();
        LogDebug("Harness initialized. Browse to a .tsm file or open a recent database to begin.");
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<HeaderFieldRow> HeaderRows { get; } = [];

    public ObservableCollection<VerifyIssueRow> VerifyIssues { get; } = [];

    public ObservableCollection<PageVerifyRow> PageResults { get; } = [];

    public ObservableCollection<PageRecordRow> PageRecords { get; } = [];

    public ObservableCollection<ProtectorSlotRow> ProtectorSlots { get; } = [];

    public ObservableCollection<string> RecentDatabasePaths { get; } = [];

    public ObservableCollection<TreePageVisitRow> TreePageVisits { get; } = [];

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

    public string CurrentDatabaseTitleText
    {
        get => currentDatabaseTitleText;
        set => SetProperty(ref currentDatabaseTitleText, value);
    }

    public string CurrentDatabaseDetailText
    {
        get => currentDatabaseDetailText;
        set => SetProperty(ref currentDatabaseDetailText, value);
    }

    public string PageNumberText
    {
        get => pageNumberText;
        set => SetProperty(ref pageNumberText, value);
    }

    public string SelectedRecordDetailText
    {
        get => selectedRecordDetailText;
        set => SetProperty(ref selectedRecordDetailText, value);
    }

    public string SelectedRecordHeadlineText
    {
        get => selectedRecordHeadlineText;
        set => SetProperty(ref selectedRecordHeadlineText, value);
    }

    public string PageSummaryText
    {
        get => pageSummaryText;
        set => SetProperty(ref pageSummaryText, value);
    }

    public bool ShowHexColumns
    {
        get => showHexColumns;
        set => SetProperty(ref showHexColumns, value);
    }

    public string StatusText
    {
        get => statusText;
        set => SetProperty(ref statusText, value);
    }

    public string TreeFocusText
    {
        get => treeFocusText;
        set => SetProperty(ref treeFocusText, value);
    }

    public string TreeRootText
    {
        get => treeRootText;
        set => SetProperty(ref treeRootText, value);
    }

    public string TreeTrustText
    {
        get => treeTrustText;
        set => SetProperty(ref treeTrustText, value);
    }

    public string UnlockModeHintText
    {
        get => unlockModeHintText;
        set => SetProperty(ref unlockModeHintText, value);
    }

    public Brush VerifyIssueSummaryBrush
    {
        get => verifyIssueSummaryBrush;
        set => SetProperty(ref verifyIssueSummaryBrush, value);
    }

    public string VerifyIssueSummaryText
    {
        get => verifyIssueSummaryText;
        set => SetProperty(ref verifyIssueSummaryText, value);
    }

    public Visibility VerifyIssueSummaryVisibility
    {
        get => verifyIssueSummaryVisibility;
        set => SetProperty(ref verifyIssueSummaryVisibility, value);
    }

    public Brush VerificationBadgeBrush
    {
        get => verificationBadgeBrush;
        set => SetProperty(ref verificationBadgeBrush, value);
    }

    public string VerificationBadgeText
    {
        get => verificationBadgeText;
        set => SetProperty(ref verificationBadgeText, value);
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

        await RunBusyActionAsync("reload header", async () =>
        {
            StatusText = "Loading header...";
            AddRecentDatabasePath(path);
            var header = await LoadHeaderAsync(path);
            if (ShouldAutoLoadTreeWithoutUnlock(header))
            {
                await LoadTreeAsync(path, unlock: null);
            }

            StatusText = $"Loaded {System.IO.Path.GetFileName(path)}: {header.PageCount} pages, root page {header.RootPage}.";
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

        await RunUnlockableInspectActionAsync("verify database", unlockSelection, async unlock =>
        {
            StatusText = "Running verification...";
            AddRecentDatabasePath(path);
            var verify = await LoadVerifyAsync(path, unlock);
            await LoadTreeAsync(path, unlock);

            StatusText = BuildVerifyStatusText(path, verify);
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

        await RunUnlockableInspectActionAsync($"inspect page {pageNumber}", unlockSelection, async unlock =>
        {
            StatusText = $"Inspecting page {pageNumber}...";
            AddRecentDatabasePath(path);
            await LoadPageAsync(path, pageNumber, unlock);
            await LoadTreeAsync(path, unlock);

            StatusText = $"Loaded page {pageNumber} from {System.IO.Path.GetFileName(path)}.";
        });
    }

    private async void InspectProtectorsButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        await RunBusyActionAsync("load protectors", async () =>
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

        await RunUnlockableInspectActionAsync("inspect root page", unlockSelection, async unlock =>
        {
            StatusText = "Loading header and root page...";
            AddRecentDatabasePath(path);

            var header = await LoadHeaderAsync(path);
            PageNumberText = header.RootPage.ToString();
            await LoadPageAsync(path, header.RootPage, unlock);
            await LoadTreeAsync(path, unlock);

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

        await RunUnlockableInspectActionAsync("refresh all panes", unlockSelection, async unlock =>
        {
            StatusText = "Refreshing header, verify, protectors, and page...";
            AddRecentDatabasePath(path);

            await LoadHeaderAsync(path);
            await LoadProtectorsAsync(path);
            await LoadVerifyAsync(path, unlock);
            await LoadTreeAsync(path, unlock);

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
            LogDebug($"Selected database path: {dialog.FileName}");
            DatabasePath = dialog.FileName;
            AddRecentDatabasePath(dialog.FileName);
            _ = AutoLoadSelectedDatabaseAsync(dialog.FileName, "Opened database and loaded header.");
        }
    }

    private void RecentDatabasesComboBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (isUpdatingRecentSelection)
        {
            return;
        }

        if (RecentDatabasesComboBox.SelectedItem is not string path || string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        LogDebug($"Selected recent database: {path}");
        DatabasePath = path;
        _ = AutoLoadSelectedDatabaseAsync(path, "Loaded header from recent database.");
    }

    private void ShowHexColumnsCheckBox_OnChanged(object sender, RoutedEventArgs e)
    {
        ShowHexColumns = ShowHexColumnsCheckBox.IsChecked == true;
        UpdateHexColumnVisibility();
    }

    private void TreePagesListView_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ListView { SelectedItem: TreePageVisitRow row } && !row.IsPlaceholder)
        {
            SelectPageNumberFromRow(row.Page, "tree history");
        }
    }

    private async void TreePagesListView_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is ListView { SelectedItem: TreePageVisitRow row } && !row.IsPlaceholder)
        {
            await InspectSelectedPageFromRowAsync(row.Page, "tree history");
        }
    }

    private async void TreePagesListView_OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || sender is not ListView { SelectedItem: TreePageVisitRow row } || row.IsPlaceholder)
        {
            return;
        }

        await InspectSelectedPageFromRowAsync(row.Page, "tree history");
        e.Handled = true;
    }

    private void Window_OnPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.F5 || (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.R))
        {
            RefreshAllButton_OnClick(RefreshAllButton, e);
            e.Handled = true;
            return;
        }

        if (Keyboard.Modifiers == ModifierKeys.Control && e.Key == Key.Enter)
        {
            InspectRootPageButton_OnClick(InspectRootPageButton, e);
            e.Handled = true;
        }
    }

    private void PageNumberTextBox_OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter)
        {
            return;
        }

        InspectPageButton_OnClick(InspectPageButton, e);
        e.Handled = true;
    }

    private void VerifyIssuesListView_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (VerifyIssuesListView.SelectedItem is VerifyIssueRow row)
        {
            SelectPageNumberFromRow(row.Pgno, "issue");
        }
    }

    private async void VerifyIssuesListView_OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || VerifyIssuesListView.SelectedItem is not VerifyIssueRow row)
        {
            return;
        }

        await InspectSelectedPageFromRowAsync(row.Pgno, "verification issue");
        e.Handled = true;
    }

    private async void VerifyIssuesListView_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (VerifyIssuesListView.SelectedItem is VerifyIssueRow row)
        {
            await InspectSelectedPageFromRowAsync(row.Pgno, "verification issue");
        }
    }

    private void PageResultsListView_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (PageResultsListView.SelectedItem is PageVerifyRow row)
        {
            SelectPageNumberFromRow(row.Pgno, "page result");
        }
    }

    private async void PageResultsListView_OnKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key != Key.Enter || PageResultsListView.SelectedItem is not PageVerifyRow row)
        {
            return;
        }

        await InspectSelectedPageFromRowAsync(row.Pgno, "page result");
        e.Handled = true;
    }

    private async void PageResultsListView_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (PageResultsListView.SelectedItem is PageVerifyRow row)
        {
            await InspectSelectedPageFromRowAsync(row.Pgno, "page result");
        }
    }

    private void PageRecordsListView_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateSelectedRecordSummary(PageRecordsListView.SelectedItem as PageRecordRow);
    }

    private async void MainWindow_OnLoaded(object sender, RoutedEventArgs e)
    {
        await EnsureTreeWebViewInitializedAsync();

        if (!restoreDatabaseOnLoad)
        {
            return;
        }

        restoreDatabaseOnLoad = false;
        await AutoLoadSelectedDatabaseAsync(DatabasePath.Trim(), "Restored last database and loaded header.");
    }

    private async Task RunUnlockableInspectActionAsync(
        string operationName,
        HarnessUnlockSelection? unlockSelection,
        Func<TosumuInspectUnlockOptions?, Task> action)
    {
        SetBusy(true);
        LogDebug($"Starting {operationName} (unlock={DescribeUnlockSelection(unlockSelection)}).");

        try
        {
            while (true)
            {
                try
                {
                    await action(unlockSelection?.ToUnlockOptions());
                    LogDebug($"Completed {operationName}.");
                    return;
                }
                catch (TosumuInspectCommandException ex) when (string.Equals(ex.ErrorKind, "wrong_key", StringComparison.Ordinal))
                {
                    StatusText = "Unlock required or provided secret was rejected.";
                    LogInspectFailure(operationName, ex);
                    SetBusy(false);

                    if (!TryPromptForUnlockRetry(out unlockSelection))
                    {
                        StatusText = "Unlock retry cancelled.";
                        LogDebug($"Cancelled {operationName} after unlock retry prompt.");
                        return;
                    }

                    ApplyUnlockSelection(unlockSelection);
                    LogDebug($"Retrying {operationName} with unlock={DescribeUnlockSelection(unlockSelection)}.");
                    SetBusy(true);
                }
            }
        }
        catch (TosumuInspectCommandException ex)
        {
            StatusText = "Last command failed.";
            LogInspectFailure(operationName, ex);
            MessageBox.Show(this, ex.Message, "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            StatusText = "Last command failed.";
            LogException(operationName, ex);
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
            LogDebug($"Selected keyfile path: {dialog.FileName}");
        }
    }

    private void MainWindow_OnClosing(object? sender, CancelEventArgs e)
    {
        debugLogFlushTimer?.Stop();
        SaveSessionState();
    }

    private void ClearDebugConsoleButton_OnClick(object sender, RoutedEventArgs e)
    {
        DebugLogTextBox.Clear();
        while (debugLogBuffer.TryDequeue(out _))
        {
        }

        LogDebug("Debug console cleared.");
    }

    private void UnlockModeComboBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateUnlockInputs();
    }

    private TosumuCliTool GetCli()
    {
        cli ??= new TosumuCliTool();
        ExecutableStateText = cli.ExecutablePath;
        LogDebug($"CLI resolved to {cli.ExecutablePath}");
        return cli;
    }

    private async Task<TosumuInspectHeaderPayload> LoadHeaderAsync(string path)
    {
        var header = await GetCli().GetHeaderAsync(path);
        var fileName = Path.GetFileName(path);
        treeRootPageNumber = header.RootPage;

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

        CurrentDatabaseTitleText = fileName;
        CurrentDatabaseDetailText = $"{header.PageCount} pages | root {header.RootPage} | format v{header.FormatVersion} | page size {header.PageSize}";
        UpdateTreeSummaryText();
        RebuildTreePageVisits();
        LogDebug($"Loaded header for {fileName}: pages={header.PageCount}, root={header.RootPage}, format=v{header.FormatVersion}, page_size={header.PageSize}.");

        return header;
    }

    private async Task<TosumuInspectTreePayload> LoadTreeAsync(string path, TosumuInspectUnlockOptions? unlock)
    {
        treeSnapshot = await GetCli().GetTreeAsync(path, unlock);
        treeRootPageNumber = treeSnapshot.RootPgno;
        QueueTreeWebViewRender();
        LogDebug($"Loaded tree snapshot rooted at page {treeSnapshot.RootPgno}.");
        return treeSnapshot;
    }

    private async Task<TosumuInspectVerifyPayload> LoadVerifyAsync(string path, TosumuInspectUnlockOptions? unlock)
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
            VerifyIssues.Add(new VerifyIssueRow("-", "Verification passed. No integrity or auth issues were reported.", HasIssue: false, IsPlaceholder: true));
        }
        else
        {
            foreach (var issue in verify.Issues)
            {
                VerifyIssues.Add(new VerifyIssueRow(issue.Pgno.ToString(), issue.Description, HasIssue: true, IsPlaceholder: false));
            }
        }

        PageResults.Clear();
        foreach (var result in verify.PageResults)
        {
            var hasIssue = !result.AuthOk || !string.IsNullOrWhiteSpace(result.Issue);
            PageResults.Add(new PageVerifyRow(
                result.Pgno.ToString(),
                result.AuthOk ? "ok" : "fail",
                result.PageVersion?.ToString() ?? "-",
                string.IsNullOrWhiteSpace(result.Issue) ? "-" : result.Issue,
                HasIssue: hasIssue,
                IsPlaceholder: false));
        }

        if (verify.IssueCount == 0 && verify.Btree.Ok)
        {
            VerificationBadgeText = "Verified clean";
            VerificationBadgeBrush = ResolveThemeBrush("SuccessBrush", Brushes.Honeydew);
            VerifyIssueSummaryVisibility = Visibility.Visible;
            VerifyIssueSummaryBrush = ResolveThemeBrush("SuccessSoftBrush", Brushes.Honeydew);
            VerifyIssueSummaryText = $"Verified clean across {verify.PagesChecked} pages. No integrity or auth failures were reported.";
            TreeTrustText = $"Trust: verified clean across {verify.PagesChecked} pages.";
        }
        else
        {
            VerificationBadgeText = verify.IssueCount == 1 ? "1 issue found" : $"{verify.IssueCount} issues found";
            VerificationBadgeBrush = ResolveThemeBrush("DangerBrush", Brushes.MistyRose);
            VerifyIssueSummaryVisibility = Visibility.Visible;
            VerifyIssueSummaryBrush = ResolveThemeBrush("DangerSoftBrush", Brushes.MistyRose);

            var firstIssue = verify.Issues.FirstOrDefault();
            VerifyIssueSummaryText = firstIssue is null
                ? $"Verification reported {verify.IssueCount} issue(s). Review the page results below for detail."
                : $"First issue on page {firstIssue.Pgno}: {firstIssue.Description}";
            TreeTrustText = verify.IssueCount == 1
                ? "Trust: verification found 1 issue."
                : $"Trust: verification found {verify.IssueCount} issues.";
        }

        LogDebug($"Verification completed: pages_checked={verify.PagesChecked}, pages_ok={verify.PagesOk}, issues={verify.IssueCount}, btree_ok={verify.Btree.Ok}.");

        return verify;
    }

    private async Task LoadPageAsync(string path, ulong pageNumber, TosumuInspectUnlockOptions? unlock)
    {
        var page = await GetCli().GetPageAsync(path, pageNumber, unlock);
        treeFocusPageNumber = page.Pgno;
        treeFocusPageTypeName = page.PageTypeName;
        TrackTreePageVisit(page.Pgno, page.PageTypeName);

        PageSummaryText =
            $"Page {page.Pgno} · {page.PageTypeName} (0x{page.PageType:X2})\n" +
            $"Version: {page.PageVersion} · Slots: {page.SlotCount}\n" +
            $"Free start: {page.FreeStart} · Free end: {page.FreeEnd} · Free bytes: {Math.Max(0, page.FreeEnd - page.FreeStart)}";

        PageRecords.Clear();
        if (page.Records.Count == 0)
        {
            PageRecords.Add(new PageRecordRow("-", "-", "-", "No decoded records on this page.", "-", "Inspect a different page if you expected payload bytes.", "-", IsPlaceholder: true));
            SelectPageRecord(PageRecords[0]);
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
                    record.ValueHex ?? "-",
                    IsPlaceholder: false));
            }

            SelectPageRecord(PageRecords.FirstOrDefault(record => !record.IsPlaceholder));
        }

        LogDebug($"Loaded page {page.Pgno}: type={page.PageTypeName}, version={page.PageVersion}, slots={page.SlotCount}, records={page.Records.Count}.");
    }

    private async Task LoadProtectorsAsync(string path)
    {
        var protectors = await GetCli().GetProtectorsAsync(path);

        ProtectorSlots.Clear();
        if (protectors.Slots.Count == 0)
        {
            ProtectorSlots.Add(new ProtectorSlotRow("-", "No user-visible protectors reported.", "-"));
        }
        else
        {
            foreach (var slot in protectors.Slots)
            {
                ProtectorSlots.Add(new ProtectorSlotRow(slot.Slot.ToString(), slot.Kind, slot.KindByte.ToString()));
            }
        }

        LogDebug($"Loaded protectors: slots={protectors.SlotCount}.");
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
            CurrentDatabaseTitleText = Path.GetFileName(sessionState.LastDatabasePath);
            CurrentDatabaseDetailText = "Restored from the last session. Loading header on startup...";
            restoreDatabaseOnLoad = File.Exists(sessionState.LastDatabasePath);
            StatusText = restoreDatabaseOnLoad
                ? $"Restored {Path.GetFileName(sessionState.LastDatabasePath)} from the last session."
                : $"Restored last database path {Path.GetFileName(sessionState.LastDatabasePath)}, but the file is no longer present.";
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
            isUpdatingRecentSelection = true;
            try
            {
                RecentDatabasesComboBox.SelectedItem = normalizedPath;
            }
            finally
            {
                isUpdatingRecentSelection = false;
            }
        }
    }

    private async Task AutoLoadSelectedDatabaseAsync(string path, string completionStatus)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        PrepareForDatabaseSelection(path);

        await RunBusyActionAsync("open selected database", async () =>
        {
            StatusText = $"Opening {Path.GetFileName(path)}...";
            AddRecentDatabasePath(path);
            var header = await LoadHeaderAsync(path);
            if (ShouldAutoLoadTreeWithoutUnlock(header))
            {
                await LoadTreeAsync(path, unlock: null);
            }
            StatusText = completionStatus;
        });
    }

    private void PrepareForDatabaseSelection(string path)
    {
        DatabasePath = path;
        CurrentDatabaseTitleText = Path.GetFileName(path);
        CurrentDatabaseDetailText = "Loading header and resetting stale pane state for the selected database...";
        VerificationBadgeText = "Verify pending";
        VerificationBadgeBrush = ResolveThemeBrush("WarningBrush", Brushes.Khaki);
        VerifyIssueSummaryVisibility = Visibility.Collapsed;
        VerifyIssueSummaryText = string.Empty;
        VerifyIssueSummaryBrush = Brushes.Transparent;
        ResetHeaderState("Loading header for the selected database...");
        ResetVerifyState();
        ResetPageState();
        ResetProtectorsState();
        ResetTreeInspectorState();
    }

    private void ResetHeaderState(string message)
    {
        HeaderRows.Clear();
        HeaderRows.Add(new HeaderFieldRow("State", message));
    }

    private void ResetVerifyState()
    {
        VerifySummaryText = "Run verification to check page auth and B-tree integrity.";
        VerifyIssueSummaryVisibility = Visibility.Visible;
        VerifyIssueSummaryBrush = ResolveThemeBrush("WarningSoftBrush", Brushes.Khaki);
        VerifyIssueSummaryText = "Verification has not run yet. You will be prompted only if credentials are required, then the first auth or integrity problem will surface here.";
        TreeTrustText = "Trust: verify pending.";
        VerifyIssues.Clear();
        VerifyIssues.Add(new VerifyIssueRow("-", "Run verification to surface integrity or auth problems.", HasIssue: false, IsPlaceholder: true));
        PageResults.Clear();
        PageResults.Add(new PageVerifyRow("-", "-", "-", "Run verification to populate per-page auth results.", HasIssue: false, IsPlaceholder: true));
    }

    private void ResetPageState()
    {
        PageSummaryText = "Select a page or inspect root to decode the current page.";
        PageRecords.Clear();
        PageRecords.Add(new PageRecordRow("-", "-", "-", "Select a page or inspect root to decode records.", "-", "Turn to a different page to compare record payloads.", "-", IsPlaceholder: true));
        SelectPageRecord(null);
    }

    private void ResetTreeInspectorState()
    {
        treeSnapshot = null;
        treeRootPageNumber = null;
        treeFocusPageNumber = null;
        treeFocusPageTypeName = string.Empty;
        treePageVisitStates.Clear();

        TreeRootText = "Root page: load a database header to discover the tree root.";
        TreeFocusText = "Focus page: inspect root or another page to begin tree navigation.";
        TreeTrustText = "Trust: verify pending.";

        RebuildTreePageVisits();
    }

    private void SelectPageNumberFromRow(string pgnoText, string sourceLabel)
    {
        if (!ulong.TryParse(pgnoText, out var pageNumber))
        {
            return;
        }

        PageNumberText = pageNumber.ToString();
        StatusText = $"Selected page {pageNumber} from {sourceLabel}. Double-click to inspect it.";
        LogDebug($"Selected page {pageNumber} from {sourceLabel}.");
    }

    private async Task InspectSelectedPageFromRowAsync(string pgnoText, string sourceLabel)
    {
        if (!ulong.TryParse(pgnoText, out var pageNumber))
        {
            return;
        }

        if (!TryGetValidDatabasePath(out var path))
        {
            return;
        }

        if (!TryGetUnlockSelection($"inspect page {pageNumber} from the {sourceLabel}", out var unlockSelection))
        {
            return;
        }

        PageNumberText = pageNumber.ToString();

        await RunUnlockableInspectActionAsync($"inspect page {pageNumber} from {sourceLabel}", unlockSelection, async unlock =>
        {
            StatusText = $"Inspecting page {pageNumber} from the {sourceLabel}...";
            AddRecentDatabasePath(path);
            await LoadPageAsync(path, pageNumber, unlock);
            StatusText = $"Loaded page {pageNumber} from the {sourceLabel}.";
        });
    }

    private void UpdateHexColumnVisibility()
    {
        if (KeyHexColumn is null || ValueHexColumn is null)
        {
            return;
        }

        KeyHexColumn.Width = ShowHexColumns ? KeyHexColumnVisibleWidth : 0;
        ValueHexColumn.Width = ShowHexColumns ? ValueHexColumnVisibleWidth : 0;
    }

    private void TrackTreePageVisit(ulong pageNumber, string pageTypeName)
    {
        treePageVisitStates.RemoveAll(entry => entry.PageNumber == pageNumber);
        treePageVisitStates.Insert(0, new TreePageVisitState(pageNumber, pageTypeName));

        while (treePageVisitStates.Count > MaxTreePageHistoryCount)
        {
            treePageVisitStates.RemoveAt(treePageVisitStates.Count - 1);
        }

        UpdateTreeSummaryText();
        RebuildTreePageVisits();
    }

    private void UpdateTreeSummaryText()
    {
        TreeRootText = treeRootPageNumber is ulong rootPage
            ? $"Root page {rootPage} · {DescribeTreeNode(rootPage, rootPage == treeFocusPageNumber ? treeFocusPageTypeName : null)}"
            : "Root page: load a database header to discover the tree root.";

        if (treeFocusPageNumber is ulong focusPage)
        {
            TreeFocusText = $"Focus page {focusPage} · {DescribeTreeNode(focusPage, treeFocusPageTypeName)}";
        }
        else if (treeRootPageNumber is ulong root)
        {
            TreeFocusText = $"Focus page: inspect root {root} or another page to begin tree navigation.";
        }
        else
        {
            TreeFocusText = "Focus page: inspect root or another page to begin tree navigation.";
        }
    }

    private void RebuildTreePageVisits()
    {
        TreePageVisits.Clear();

        if (treePageVisitStates.Count == 0)
        {
            TreePageVisits.Add(new TreePageVisitRow("-", "No tree pages inspected yet.", "Inspect root to begin.", true));
            return;
        }

        foreach (var entry in treePageVisitStates)
        {
            var relation = entry.PageNumber == treeFocusPageNumber
                ? entry.PageNumber == treeRootPageNumber ? "Root focus" : "Focus"
                : entry.PageNumber == treeRootPageNumber ? "Root" : "Visited";

            TreePageVisits.Add(new TreePageVisitRow(
                entry.PageNumber.ToString(),
                DescribeTreeNode(entry.PageNumber, entry.PageTypeName),
                relation,
                false));
        }

        QueueTreeWebViewRender();
    }

    private void QueueTreeWebViewRender()
    {
        _ = RenderTreeWebViewAsync();
    }

    private async Task EnsureTreeWebViewInitializedAsync()
    {
        if (TreeWebView is null)
        {
            return;
        }

        treeWebViewInitializationTask ??= InitializeTreeWebViewCoreAsync();
        await treeWebViewInitializationTask;
    }

    private async Task InitializeTreeWebViewCoreAsync()
    {
        if (TreeWebView is null)
        {
            return;
        }

        var htmlPath = Path.Combine(AppContext.BaseDirectory, "Assets", "TreeView", "tree-view.html");
        if (!File.Exists(htmlPath))
        {
            LogDebug($"Tree view asset missing: {htmlPath}");
            return;
        }

        await TreeWebView.EnsureCoreWebView2Async();

        if (TreeWebView.CoreWebView2 is null)
        {
            LogDebug("Tree WebView2 runtime was not available.");
            return;
        }

        TreeWebView.CoreWebView2.Settings.AreDefaultContextMenusEnabled = false;
        TreeWebView.CoreWebView2.Settings.AreDevToolsEnabled = false;
        TreeWebView.CoreWebView2.Settings.IsStatusBarEnabled = false;
        TreeWebView.CoreWebView2.WebMessageReceived += TreeWebView_OnWebMessageReceived;

        var navigationCompletion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

        void HandleNavigationCompleted(object? _, CoreWebView2NavigationCompletedEventArgs args)
        {
            TreeWebView.NavigationCompleted -= HandleNavigationCompleted;
            navigationCompletion.TrySetResult(args.IsSuccess);
        }

        TreeWebView.NavigationCompleted += HandleNavigationCompleted;
        TreeWebView.Source = new Uri(htmlPath);

        var navigationSucceeded = await navigationCompletion.Task;
        LogDebug(navigationSucceeded
            ? $"Initialized D3 tree view from {htmlPath}."
            : $"Tree view navigation reported failure for {htmlPath}.");
    }

    private async Task RenderTreeWebViewAsync()
    {
        try
        {
            await EnsureTreeWebViewInitializedAsync();

            if (TreeWebView?.CoreWebView2 is null)
            {
                return;
            }

            var payload = BuildTreeWebViewPayload();
            var json = JsonSerializer.Serialize(payload, TreeWebViewJsonOptions);
            await TreeWebView.ExecuteScriptAsync($"window.renderTree({json});");
        }
        catch (Exception ex)
        {
            LogException("render D3 tree view", ex);
        }
    }

    private TreeWebViewPayload BuildTreeWebViewPayload()
    {
        if (treeSnapshot is not null)
        {
            return new TreeWebViewPayload(
                treeSnapshot.RootPgno,
                treeFocusPageNumber,
                TreeTrustText,
                BuildTreeWebViewNode(treeSnapshot.Root, relationLabel: null, separatorKeyHex: null));
        }

        var rootNode = treeRootPageNumber is ulong rootPage
            ? new TreeWebViewNode(
                $"Page {rootPage}",
                DescribeTreeNode(rootPage, rootPage == treeFocusPageNumber ? treeFocusPageTypeName : null),
                rootPage == treeFocusPageNumber ? "root-focus" : "root",
                rootPage,
                [])
            : new TreeWebViewNode(
                "Root pending",
                "Load a header to discover the root page.",
                "synthetic",
                null,
                []);

        var observedNodes = treePageVisitStates
            .Where(entry => entry.PageNumber != treeRootPageNumber)
            .Select(entry => new TreeWebViewNode(
                $"Page {entry.PageNumber}",
                $"{GetTreeRelationLabel(entry.PageNumber)} · {DescribeTreeNode(entry.PageNumber, entry.PageTypeName)}",
                entry.PageNumber == treeFocusPageNumber ? "focus" : "visited",
                entry.PageNumber,
                []))
            .ToList();

        var topLevelNodes = new List<TreeWebViewNode> { rootNode };
        if (observedNodes.Count > 0)
        {
            topLevelNodes.Add(new TreeWebViewNode(
                "Observed pages",
                $"{observedNodes.Count} inspected page{(observedNodes.Count == 1 ? string.Empty : "s")}",
                "synthetic",
                null,
                observedNodes));
        }

        return new TreeWebViewPayload(
            treeRootPageNumber,
            treeFocusPageNumber,
            TreeTrustText,
            new TreeWebViewNode(
                "Tree Inspector",
                "Observed root, focus, and inspected pages",
                "synthetic",
                null,
                topLevelNodes));
    }

    private TreeWebViewNode BuildTreeWebViewNode(
        TosumuInspectTreeNodePayload node,
        string? relationLabel,
        string? separatorKeyHex)
    {
        var relationPrefix = string.IsNullOrWhiteSpace(relationLabel) ? string.Empty : relationLabel + " · ";
        var separatorSuffix = string.IsNullOrWhiteSpace(separatorKeyHex) ? string.Empty : $" · sep {ShortHex(separatorKeyHex)}";
        var nextLeafSuffix = node.NextLeaf is ulong nextLeaf ? $" · next {nextLeaf}" : string.Empty;
        var meta = $"{relationPrefix}{node.PageTypeName} · slots {node.SlotCount}{separatorSuffix}{nextLeafSuffix}";

        return new TreeWebViewNode(
            $"Page {node.Pgno}",
            meta,
            GetTreeVisualKind(node.Pgno, node.PageTypeName),
            node.Pgno,
            node.Children.Select(child => BuildTreeWebViewNode(
                child.Child,
                child.Relation,
                child.SeparatorKeyHex)).ToList());
    }

    private string GetTreeVisualKind(ulong pgno, string pageTypeName)
    {
        if (pgno == treeRootPageNumber && pgno == treeFocusPageNumber)
        {
            return "root-focus";
        }

        if (pgno == treeRootPageNumber)
        {
            return "root";
        }

        if (pgno == treeFocusPageNumber)
        {
            return "focus";
        }

        return "visited";
    }

    private static string ShortHex(string hex)
    {
        return hex.Length <= 12 ? hex : hex[..12] + "...";
    }

    private string GetTreeRelationLabel(ulong pageNumber)
    {
        return pageNumber == treeFocusPageNumber
            ? pageNumber == treeRootPageNumber ? "Root focus" : "Focus"
            : pageNumber == treeRootPageNumber ? "Root" : "Visited";
    }

    private void TreeWebView_OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        try
        {
            using var document = JsonDocument.Parse(e.WebMessageAsJson);
            var root = document.RootElement;
            if (!root.TryGetProperty("type", out var typeElement) || typeElement.GetString() != "selectPage")
            {
                return;
            }

            if (!root.TryGetProperty("pageNumber", out var pageElement) || pageElement.ValueKind != JsonValueKind.Number)
            {
                return;
            }

            if (!pageElement.TryGetUInt64(out var pageNumber))
            {
                return;
            }

            PageNumberText = pageNumber.ToString();
            StatusText = $"Selected page {pageNumber} from the D3 tree view. Inspect page to decode it.";
            LogDebug($"Selected page {pageNumber} from the D3 tree view.");
        }
        catch (Exception ex)
        {
            LogException("handle D3 tree selection", ex);
        }
    }

    private string DescribeTreeNode(ulong pageNumber, string? pageTypeName)
    {
        var label = pageTypeName switch
        {
            "Leaf" => "leaf node",
            "Internal" => "internal node",
            "Overflow" => "overflow page",
            "Free" => "free page",
            null or "" => pageNumber == treeRootPageNumber ? "root page" : "page",
            _ => $"{pageTypeName.ToLowerInvariant()} page",
        };

        if (pageNumber != treeRootPageNumber)
        {
            return char.ToUpperInvariant(label[0]) + label[1..];
        }

        return label switch
        {
            "leaf node" => "Root leaf node",
            "internal node" => "Root internal node",
            "overflow page" => "Root overflow page",
            "free page" => "Root free page",
            _ => "Root page",
        };
    }

    private Brush ResolveThemeBrush(string resourceKey, Brush fallback)
    {
        return TryFindResource(resourceKey) as Brush ?? fallback;
    }

    private void SelectPageRecord(PageRecordRow? record)
    {
        if (PageRecordsListView is null)
        {
            UpdateSelectedRecordSummary(record);
            return;
        }

        PageRecordsListView.SelectedItem = record;
        UpdateSelectedRecordSummary(record);
    }

    private void UpdateSelectedRecordSummary(PageRecordRow? record)
    {
        if (record is null)
        {
            SelectedRecordHeadlineText = "No record selected";
            SelectedRecordDetailText = "Select a non-placeholder record to inspect the current key/value payloads.";
            return;
        }

        if (record.IsPlaceholder)
        {
            SelectedRecordHeadlineText = "Waiting for decoded record data";
            SelectedRecordDetailText = record.KeyPreview;
            return;
        }

        SelectedRecordHeadlineText = $"{record.Kind} · slot {record.Slot} · type {record.RecordType}";
        SelectedRecordDetailText =
            $"Key: {DescribePayload(record.KeyPreview, record.KeyHex)}\n" +
            $"Value: {DescribePayload(record.ValuePreview, record.ValueHex)}";
    }

    private static string DescribePayload(string preview, string hex)
    {
        var byteCount = TryGetHexByteCount(hex);
        var sizeLabel = byteCount is null ? "size unavailable" : byteCount == 1 ? "1 byte" : $"{byteCount} bytes";

        return preview switch
        {
            "-" => $"not present ({sizeLabel})",
            "(empty)" => $"empty payload ({sizeLabel})",
            "(binary)" => $"binary payload ({sizeLabel})",
            "(invalid)" => "invalid hex preview",
            _ => $"text \"{preview}\" ({sizeLabel})",
        };
    }

    private static int? TryGetHexByteCount(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex == "-" || (hex.Length % 2) != 0)
        {
            return null;
        }

        return hex.All(Uri.IsHexDigit) ? hex.Length / 2 : null;
    }

    private void ResetProtectorsState()
    {
        ProtectorSlots.Clear();
        ProtectorSlots.Add(new ProtectorSlotRow("-", "Load protectors to inspect user-visible keyslots.", "-"));
    }

    private static string BuildVerifyStatusText(string path, TosumuInspectVerifyPayload verify)
    {
        var fileName = Path.GetFileName(path);

        if (verify.IssueCount == 0 && verify.Btree.Ok)
        {
            return $"{fileName} verified clean across {verify.PagesChecked} pages.";
        }

        var firstIssue = verify.Issues.FirstOrDefault();
        if (firstIssue is not null)
        {
            return $"{fileName} verification found {verify.IssueCount} issue(s); first issue on page {firstIssue.Pgno}.";
        }

        return $"{fileName} verification completed with {verify.IssueCount} reported issue(s).";
    }

    private static bool ShouldAutoLoadTreeWithoutUnlock(TosumuInspectHeaderPayload header)
    {
        return string.Equals(header.Slot0.Kind, "Sentinel", StringComparison.Ordinal);
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

    private async Task RunBusyActionAsync(string operationName, Func<Task> action)
    {
        SetBusy(true);
        LogDebug($"Starting {operationName}.");

        try
        {
            await action();
            LogDebug($"Completed {operationName}.");
        }
        catch (TosumuInspectCommandException ex)
        {
            StatusText = "Last command failed.";
            LogInspectFailure(operationName, ex);
            MessageBox.Show(this, ex.Message, "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch (Exception ex)
        {
            StatusText = "Last command failed.";
            LogException(operationName, ex);
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
        UnlockModeHintText = selectedMode switch
        {
            HarnessUnlockModes.Auto => "You will be prompted only if the current inspect action actually requires credentials.",
            HarnessUnlockModes.Passphrase => "Use this when the database should unlock with a passphrase piped to the CLI.",
            HarnessUnlockModes.RecoveryKey => "Use this when you need the recovery key instead of a passphrase.",
            HarnessUnlockModes.Keyfile => "Use this when the database should unlock from a keyfile path instead of typed secret input.",
            _ => "Choose how inspect commands should unlock the current database."
        };

        if (!usesSecret)
        {
            SecretPasswordBox.Password = string.Empty;
        }

        if (!usesKeyfile)
        {
            KeyfilePathTextBox.Text = string.Empty;
        }
    }


    private void LogDebug(string message)
    {
        debugLogBuffer.Enqueue($"{DateTime.Now:HH:mm:ss.fff}  {message}");
    }

    private void FlushDebugLog()
    {
        if (DebugLogTextBox is null || DebugLogScrollViewer is null || debugLogBuffer.IsEmpty)
        {
            return;
        }

        var text = new StringBuilder();
        while (debugLogBuffer.TryDequeue(out var line))
        {
            text.AppendLine(line);
        }

        if (DebugLogTextBox.Text.Length > MaxDebugLogChars)
        {
            DebugLogTextBox.Clear();
            DebugLogTextBox.AppendText($"{DateTime.Now:HH:mm:ss.fff}  [debug] Cleared previous output after reaching {MaxDebugLogChars} characters.{Environment.NewLine}");
        }

        DebugLogTextBox.AppendText(text.ToString());
        DebugLogScrollViewer.ScrollToEnd();
    }

    private void LogInspectFailure(string operationName, TosumuInspectCommandException ex)
    {
        var pgnoText = ex.Pgno is ulong pgno ? $", pgno={pgno}" : string.Empty;
        LogDebug($"{operationName} failed: command={ex.Command}, kind={ex.ErrorKind ?? "unknown"}, exit={ex.ExitCode}{pgnoText}, message={FlattenForLog(ex.Message)}");

        if (!string.IsNullOrWhiteSpace(ex.StandardError))
        {
            LogDebug($"stderr: {FlattenForLog(ex.StandardError)}");
        }

        if (!string.IsNullOrWhiteSpace(ex.StandardOutput))
        {
            LogDebug($"stdout: {FlattenForLog(ex.StandardOutput)}");
        }
    }

    private void LogException(string operationName, Exception ex)
    {
        LogDebug($"{operationName} failed with {ex.GetType().Name}: {FlattenForLog(ex.Message)}");
    }

    private static string DescribeUnlockSelection(HarnessUnlockSelection? unlockSelection)
    {
        return unlockSelection?.Mode switch
        {
            HarnessUnlockModes.Passphrase => "passphrase",
            HarnessUnlockModes.RecoveryKey => "recovery-key",
            HarnessUnlockModes.Keyfile => "keyfile",
            _ => "auto",
        };
    }

    private static string FlattenForLog(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return "(empty)";
        }

        var flattened = text.Replace("\r", string.Empty).Replace("\n", " | ").Trim();
        return flattened.Length <= 800 ? flattened : flattened[..800] + "...";
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

public sealed record VerifyIssueRow(string Pgno, string Description, bool HasIssue, bool IsPlaceholder);

public sealed record PageVerifyRow(string Pgno, string AuthOkLabel, string PageVersionLabel, string Issue, bool HasIssue, bool IsPlaceholder);

public sealed record PageRecordRow(string Kind, string Slot, string RecordType, string KeyPreview, string KeyHex, string ValuePreview, string ValueHex, bool IsPlaceholder);

public sealed record ProtectorSlotRow(string Slot, string Kind, string KindByte);

public sealed record TreePageVisitRow(string Page, string Node, string Relation, bool IsPlaceholder);

public sealed record TreeWebViewPayload(
    ulong? RootPageNumber,
    ulong? FocusPageNumber,
    string TrustText,
    TreeWebViewNode Hierarchy);

public sealed record TreeWebViewNode(
    string Label,
    string Meta,
    string VisualKind,
    ulong? PageNumber,
    IReadOnlyList<TreeWebViewNode> Children);