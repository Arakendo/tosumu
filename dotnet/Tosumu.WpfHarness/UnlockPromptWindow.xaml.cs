using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace Tosumu.WpfHarness;

public partial class UnlockPromptWindow : Window
{
    public UnlockPromptWindow(string promptMessage, string initialMode, string initialKeyfilePath)
    {
        InitializeComponent();
        PromptTextBlock.Text = promptMessage;
        SelectUnlockMode(initialMode);
        KeyfilePathTextBox.Text = initialKeyfilePath;
        UpdateModeInputs();
    }

    internal HarnessUnlockSelection? UnlockSelection { get; private set; }

    private void UnlockModeComboBox_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        UpdateModeInputs();
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

    private void CancelButton_OnClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
    }

    private void RetryButton_OnClick(object sender, RoutedEventArgs e)
    {
        switch (GetSelectedUnlockMode())
        {
            case HarnessUnlockModes.Passphrase:
            case HarnessUnlockModes.RecoveryKey:
                var secret = SecretPasswordBox.Password;
                if (string.IsNullOrWhiteSpace(secret))
                {
                    MessageBox.Show(this, "Enter the secret before retrying.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                UnlockSelection = new HarnessUnlockSelection(GetSelectedUnlockMode(), secret);
                DialogResult = true;
                return;
            case HarnessUnlockModes.Keyfile:
                var keyfilePath = KeyfilePathTextBox.Text.Trim();
                if (string.IsNullOrWhiteSpace(keyfilePath))
                {
                    MessageBox.Show(this, "Choose a keyfile path before retrying.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                if (!System.IO.File.Exists(keyfilePath))
                {
                    MessageBox.Show(this, $"Keyfile not found:\n{keyfilePath}", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                UnlockSelection = new HarnessUnlockSelection(HarnessUnlockModes.Keyfile, keyfilePath);
                DialogResult = true;
                return;
            default:
                MessageBox.Show(this, "Choose an unlock mode before retrying.", "Tosumu Harness", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
        }
    }

    private string GetSelectedUnlockMode()
    {
        return (UnlockModeComboBox.SelectedItem as ComboBoxItem)?.Tag as string ?? HarnessUnlockModes.Passphrase;
    }

    private void SelectUnlockMode(string mode)
    {
        var desiredMode = mode == HarnessUnlockModes.Auto ? HarnessUnlockModes.Passphrase : mode;
        foreach (var item in UnlockModeComboBox.Items)
        {
            if (item is ComboBoxItem comboBoxItem && string.Equals(comboBoxItem.Tag as string, desiredMode, StringComparison.Ordinal))
            {
                UnlockModeComboBox.SelectedItem = comboBoxItem;
                return;
            }
        }

        UnlockModeComboBox.SelectedIndex = 0;
    }

    private void UpdateModeInputs()
    {
        var selectedMode = GetSelectedUnlockMode();
        var usesSecret = selectedMode is HarnessUnlockModes.Passphrase or HarnessUnlockModes.RecoveryKey;
        var usesKeyfile = selectedMode == HarnessUnlockModes.Keyfile;

        SecretLabelTextBlock.Text = selectedMode == HarnessUnlockModes.RecoveryKey ? "Recovery key" : "Passphrase";
        SecretLabelTextBlock.Visibility = Visibility.Visible;
        SecretPasswordBox.Visibility = usesSecret ? Visibility.Visible : Visibility.Collapsed;
        KeyfilePathTextBox.Visibility = usesKeyfile ? Visibility.Visible : Visibility.Collapsed;
        BrowseKeyfileButton.Visibility = usesKeyfile ? Visibility.Visible : Visibility.Collapsed;

        if (usesKeyfile)
        {
            SecretPasswordBox.Password = string.Empty;
            SecretLabelTextBlock.Text = "Keyfile path";
        }
    }
}