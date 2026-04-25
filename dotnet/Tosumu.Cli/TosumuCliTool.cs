using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Tosumu.Cli;

public enum TosumuInspectUnlockKind
{
    Passphrase,
    RecoveryKey,
    Keyfile,
}

public sealed record TosumuInspectUnlockOptions
{
    private TosumuInspectUnlockOptions(TosumuInspectUnlockKind kind, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("Unlock value must not be empty.", nameof(value));
        }

        Kind = kind;
        Value = value;
    }

    public TosumuInspectUnlockKind Kind { get; }

    internal string Value { get; }

    public static TosumuInspectUnlockOptions Passphrase(string passphrase) =>
        new(TosumuInspectUnlockKind.Passphrase, passphrase);

    public static TosumuInspectUnlockOptions RecoveryKey(string recoveryKey) =>
        new(TosumuInspectUnlockKind.RecoveryKey, recoveryKey);

    public static TosumuInspectUnlockOptions Keyfile(string keyfilePath) =>
        new(TosumuInspectUnlockKind.Keyfile, keyfilePath);
}

public sealed class TosumuInspectCommandException : InvalidOperationException
{
    public TosumuInspectCommandException(
        string command,
        int exitCode,
        string? errorKind,
        string message,
        ulong? pgno,
        string standardOutput,
        string standardError)
        : base($"{command} failed with kind '{errorKind ?? "unknown"}': {message}")
    {
        Command = command;
        ExitCode = exitCode;
        ErrorKind = errorKind;
        Pgno = pgno;
        StandardOutput = standardOutput;
        StandardError = standardError;
    }

    public string Command { get; }

    public int ExitCode { get; }

    public string? ErrorKind { get; }

    public ulong? Pgno { get; }

    public string StandardOutput { get; }

    public string StandardError { get; }
}

public sealed class TosumuCliTool
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
    };
    public TosumuCliTool(string? executablePath = null)
    {
        ExecutablePath = executablePath ?? ResolveExecutablePath();
    }

    public string ExecutablePath { get; }

    public static string ResolveExecutablePath()
    {
        string[] candidates =
        {
            Path.Combine(AppContext.BaseDirectory, "tosumu.exe"),
            Path.Combine(Path.GetDirectoryName(typeof(TosumuCliTool).Assembly.Location) ?? AppContext.BaseDirectory, "tosumu.exe"),
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new FileNotFoundException(
            "Could not locate tosumu.exe next to the consuming application's output. Pack Tosumu.Cli and ensure the package build targets ran.",
            candidates[0]);
    }

    public async Task<TosumuCommandResult> RunAsync(IEnumerable<string> arguments, CancellationToken cancellationToken = default)
    {
        return await RunProcessAsync(arguments, standardInput: null, cancellationToken).ConfigureAwait(false);
    }

    public Task<TosumuCommandResult> RunWithStandardInputAsync(string standardInput, IEnumerable<string> arguments, CancellationToken cancellationToken = default) =>
        RunProcessAsync(arguments, standardInput, cancellationToken);

    public Task<TosumuCommandResult> RunWithStandardInputAsync(string standardInput, CancellationToken cancellationToken = default, params string[] arguments) =>
        RunProcessAsync((IEnumerable<string>)arguments, standardInput, cancellationToken);

    public async Task<TosumuInspectHeaderPayload> GetHeaderAsync(string path, CancellationToken cancellationToken = default)
    {
        var result = await RunAsync(new[] { "inspect", "header", "--json", path }, cancellationToken).ConfigureAwait(false);
        var envelope = DeserializeEnvelope<TosumuInspectHeaderPayload>(result, "inspect.header");

        if (result.ExitCode != 0)
        {
            throw CreateInspectCommandException("inspect.header", result, envelope.Error);
        }

        if (!envelope.Ok || envelope.Payload is null)
        {
            throw new InvalidOperationException(
                $"tosumu inspect header returned no payload. stderr:{Environment.NewLine}{result.StandardError}");
        }

        return envelope.Payload;
    }

    public async Task<TosumuInspectVerifyPayload> GetVerifyAsync(
        string path,
        TosumuInspectUnlockOptions? unlock = null,
        CancellationToken cancellationToken = default)
    {
        var result = await RunInspectCommandAsync(new[] { "inspect", "verify", "--json", path }, unlock, cancellationToken).ConfigureAwait(false);
        var envelope = DeserializeEnvelope<TosumuInspectVerifyPayload>(result, "inspect.verify");

        if (result.ExitCode != 0)
        {
            throw CreateInspectCommandException("inspect.verify", result, envelope.Error);
        }

        if (envelope.Payload is null)
        {
            throw new InvalidOperationException(
                $"tosumu inspect verify returned no payload. stderr:{Environment.NewLine}{result.StandardError}");
        }

        return envelope.Payload;
    }

    public async Task<TosumuInspectPagePayload> GetPageAsync(
        string path,
        ulong page,
        TosumuInspectUnlockOptions? unlock = null,
        CancellationToken cancellationToken = default)
    {
        var result = await RunInspectCommandAsync(new[] { "inspect", "page", "--page", page.ToString(), "--json", path }, unlock, cancellationToken).ConfigureAwait(false);
        var envelope = DeserializeEnvelope<TosumuInspectPagePayload>(result, "inspect.page");

        if (result.ExitCode != 0)
        {
            throw CreateInspectCommandException("inspect.page", result, envelope.Error);
        }

        if (envelope.Payload is null)
        {
            throw new InvalidOperationException(
                $"tosumu inspect page returned no payload. stderr:{Environment.NewLine}{result.StandardError}");
        }

        return envelope.Payload;
    }

    public Task<TosumuCommandResult> RunAsync(params string[] arguments) =>
        RunAsync((IEnumerable<string>)arguments, CancellationToken.None);

    public Task<TosumuCommandResult> RunAsync(CancellationToken cancellationToken = default, params string[] arguments) =>
        RunAsync((IEnumerable<string>)arguments, cancellationToken);

    private async Task<TosumuCommandResult> RunProcessAsync(
        IEnumerable<string> arguments,
        string? standardInput,
        CancellationToken cancellationToken)
    {
        using var process = new Process
        {
            StartInfo = BuildStartInfo(arguments, redirectStandardInput: standardInput is not null),
        };

        process.Start();

        if (standardInput is not null)
        {
            await process.StandardInput.WriteAsync(standardInput.AsMemory(), cancellationToken).ConfigureAwait(false);
            await process.StandardInput.FlushAsync().ConfigureAwait(false);
            process.StandardInput.Close();
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);

        var stdout = await stdoutTask.ConfigureAwait(false);
        var stderr = await stderrTask.ConfigureAwait(false);

        return new TosumuCommandResult(process.ExitCode, stdout, stderr);
    }

    private async Task<TosumuCommandResult> RunInspectCommandAsync(
        IEnumerable<string> arguments,
        TosumuInspectUnlockOptions? unlock,
        CancellationToken cancellationToken)
    {
        var finalArguments = new List<string>(arguments)
        {
            "--no-prompt",
        };

        string? standardInput = null;
        if (unlock is not null)
        {
            switch (unlock.Kind)
            {
                case TosumuInspectUnlockKind.Passphrase:
                    finalArguments.Add("--stdin-passphrase");
                    standardInput = unlock.Value;
                    break;
                case TosumuInspectUnlockKind.RecoveryKey:
                    finalArguments.Add("--stdin-recovery-key");
                    standardInput = unlock.Value;
                    break;
                case TosumuInspectUnlockKind.Keyfile:
                    finalArguments.Add("--keyfile");
                    finalArguments.Add(unlock.Value);
                    break;
                default:
                    throw new InvalidOperationException($"Unsupported unlock kind: {unlock.Kind}");
            }
        }

        return await RunProcessAsync(finalArguments, standardInput, cancellationToken).ConfigureAwait(false);
    }

    private ProcessStartInfo BuildStartInfo(IEnumerable<string> arguments, bool redirectStandardInput)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = ExecutablePath,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = redirectStandardInput,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static TosumuInspectEnvelope<TPayload> DeserializeEnvelope<TPayload>(TosumuCommandResult result, string expectedCommand)
    {
        try
        {
            var envelope = JsonSerializer.Deserialize<TosumuInspectEnvelope<TPayload>>(result.StandardOutput, JsonOptions)
                ?? throw new InvalidOperationException("tosumu returned empty JSON output");

            if (!string.Equals(envelope.Command, expectedCommand, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(
                    $"expected command '{expectedCommand}' but received '{envelope.Command}'");
            }

            return envelope;
        }
        catch (Exception ex) when (ex is JsonException or NotSupportedException or InvalidOperationException)
        {
            throw new InvalidOperationException(
                $"failed to deserialize tosumu JSON response.{Environment.NewLine}stdout:{Environment.NewLine}{result.StandardOutput}{Environment.NewLine}stderr:{Environment.NewLine}{result.StandardError}",
                ex);
        }
    }

    private static TosumuInspectCommandException CreateInspectCommandException(
        string command,
        TosumuCommandResult result,
        TosumuInspectErrorPayload? error)
    {
        return new TosumuInspectCommandException(
            command,
            result.ExitCode,
            error?.Kind,
            error?.Message ?? result.StandardError,
            error?.Pgno,
            result.StandardOutput,
            result.StandardError);
    }
}

public sealed record TosumuCommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public void EnsureSuccess()
    {
        if (ExitCode == 0)
        {
            return;
        }

        throw new InvalidOperationException(
            $"tosumu exited with code {ExitCode}{Environment.NewLine}stdout:{Environment.NewLine}{StandardOutput}{Environment.NewLine}stderr:{Environment.NewLine}{StandardError}");
    }
}

public sealed record TosumuInspectHeaderPayload(
    [property: JsonPropertyName("format_version")] ushort FormatVersion,
    [property: JsonPropertyName("page_size")] ushort PageSize,
    [property: JsonPropertyName("min_reader_version")] ushort MinReaderVersion,
    [property: JsonPropertyName("flags")] ushort Flags,
    [property: JsonPropertyName("page_count")] ulong PageCount,
    [property: JsonPropertyName("freelist_head")] ulong FreelistHead,
    [property: JsonPropertyName("root_page")] ulong RootPage,
    [property: JsonPropertyName("wal_checkpoint_lsn")] ulong WalCheckpointLsn,
    [property: JsonPropertyName("dek_id")] ulong DekId,
    [property: JsonPropertyName("keyslot_count")] ushort KeyslotCount,
    [property: JsonPropertyName("keyslot_region_pages")] ushort KeyslotRegionPages,
    [property: JsonPropertyName("slot0")] TosumuInspectKeyslotPayload Slot0);

public sealed record TosumuInspectKeyslotPayload(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("kind_byte")] byte KindByte,
    [property: JsonPropertyName("version")] byte Version);

public sealed record TosumuInspectVerifyPayload(
    [property: JsonPropertyName("pages_checked")] ulong PagesChecked,
    [property: JsonPropertyName("pages_ok")] ulong PagesOk,
    [property: JsonPropertyName("issue_count")] int IssueCount,
    [property: JsonPropertyName("issues")] IReadOnlyList<TosumuInspectVerifyIssuePayload> Issues,
    [property: JsonPropertyName("page_results")] IReadOnlyList<TosumuInspectPageVerifyPayload> PageResults,
    [property: JsonPropertyName("btree")] TosumuInspectBtreeVerifyPayload Btree);

public sealed record TosumuInspectVerifyIssuePayload(
    [property: JsonPropertyName("pgno")] ulong Pgno,
    [property: JsonPropertyName("description")] string Description);

public sealed record TosumuInspectPageVerifyPayload(
    [property: JsonPropertyName("pgno")] ulong Pgno,
    [property: JsonPropertyName("page_version")] ulong? PageVersion,
    [property: JsonPropertyName("auth_ok")] bool AuthOk,
    [property: JsonPropertyName("issue")] string? Issue);

public sealed record TosumuInspectBtreeVerifyPayload(
    [property: JsonPropertyName("checked")] bool Checked,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("message")] string? Message);

public sealed record TosumuInspectPagePayload(
    [property: JsonPropertyName("pgno")] ulong Pgno,
    [property: JsonPropertyName("page_version")] ulong PageVersion,
    [property: JsonPropertyName("page_type")] byte PageType,
    [property: JsonPropertyName("page_type_name")] string PageTypeName,
    [property: JsonPropertyName("slot_count")] ushort SlotCount,
    [property: JsonPropertyName("free_start")] ushort FreeStart,
    [property: JsonPropertyName("free_end")] ushort FreeEnd,
    [property: JsonPropertyName("records")] IReadOnlyList<TosumuInspectRecordPayload> Records);

public sealed record TosumuInspectRecordPayload(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("key_hex")] string? KeyHex,
    [property: JsonPropertyName("value_hex")] string? ValueHex,
    [property: JsonPropertyName("slot")] ushort? Slot,
    [property: JsonPropertyName("record_type")] byte? RecordType);

internal sealed record TosumuInspectEnvelope<TPayload>(
    [property: JsonPropertyName("schema_version")] int SchemaVersion,
    [property: JsonPropertyName("command")] string Command,
    [property: JsonPropertyName("ok")] bool Ok,
    [property: JsonPropertyName("payload")] TPayload? Payload,
    [property: JsonPropertyName("error")] TosumuInspectErrorPayload? Error);

internal sealed record TosumuInspectErrorPayload(
    [property: JsonPropertyName("kind")] string Kind,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("pgno")] ulong? Pgno);