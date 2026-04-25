using Tosumu.Cli;

namespace Tosumu.WpfHarness;

internal static class HarnessUnlockModes
{
    public const string Auto = "Auto";
    public const string Passphrase = "Passphrase";
    public const string RecoveryKey = "RecoveryKey";
    public const string Keyfile = "Keyfile";
}

internal sealed record HarnessUnlockSelection(string Mode, string Value)
{
    public TosumuInspectUnlockOptions ToUnlockOptions()
    {
        return Mode switch
        {
            HarnessUnlockModes.Passphrase => TosumuInspectUnlockOptions.Passphrase(Value),
            HarnessUnlockModes.RecoveryKey => TosumuInspectUnlockOptions.RecoveryKey(Value),
            HarnessUnlockModes.Keyfile => TosumuInspectUnlockOptions.Keyfile(Value),
            _ => throw new InvalidOperationException($"Unsupported unlock mode: {Mode}"),
        };
    }
}