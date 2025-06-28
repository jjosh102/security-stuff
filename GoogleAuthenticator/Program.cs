using OtpNet;
using QRCoder;
using System.Diagnostics;
using Spectre.Console;

class Program
{
 private  static string SecretFilePath => Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
    ".google_auth_secret"
  );

  static void Main()
  {
    while (true)
    {
      Console.Clear();
      AnsiConsole.Write(
        new FigletText("Google Authenticator SAMPLE")
          .Centered()
          .Color(Color.Cyan1)
      );
      AnsiConsole.MarkupLine("[bold yellow]Google Authenticator Demo[/]");

      var choice = AnsiConsole.Prompt(
        new SelectionPrompt<string>()
          .Title("What do you want to do?")
          .AddChoices("Register Authenticator", "Verify Code", "Exit")
      );

      if (choice == "Register Authenticator")
      {
        RegisterAuthenticator();
      }
      else if (choice == "Verify Code")
      {
        VerifyCode();
      }
      else if (choice == "Exit")
      {
        AnsiConsole.MarkupLine("[grey]Goodbye![/]");
        break;
      }

      AnsiConsole.MarkupLine("\n[grey]Press any key to return to the menu...[/]");
      Console.ReadKey(true);
    }
  }

  static void RegisterAuthenticator()
  {
    // 1. Generate secret
    byte[] secretKey = KeyGeneration.GenerateRandomKey(20);
    string base32Secret = Base32Encoding.ToString(secretKey);

    File.WriteAllText(SecretFilePath, base32Secret);

    AnsiConsole.MarkupLine($"[green]Shared Secret (Base32):[/] [bold]{base32Secret}[/]");

    // 2. Create TOTP URI
    string issuer = "MyApp";
    string user = "user@example.com";
    string otpAuthUri = $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(user)}" +
          $"?secret={base32Secret}&issuer={Uri.EscapeDataString(issuer)}";

    AnsiConsole.MarkupLine($"\n[blue]Scan this URI in Google Authenticator:[/]\n[italic]{otpAuthUri}[/]");

    // 3. Generate and save QR code
    SaveQrCodeToFile(otpAuthUri, "qrcode.png");
    AnsiConsole.MarkupLine("[green]QR Code saved to your Downloads folder as qrcode.png.[/]");
    AnsiConsole.MarkupLine("[yellow]Open and scan it in Google Authenticator.[/]");
  }

  static void VerifyCode()
  {
    if (!File.Exists(SecretFilePath))
    {
      AnsiConsole.MarkupLine("[red]No secret found. Please register the authenticator first.[/]");
      return;
    }

    string base32Secret = File.ReadAllText(SecretFilePath).Trim();
    byte[] secretKey = Base32Encoding.ToBytes(base32Secret);
    var totp = new Totp(secretKey);

    string currentCode = totp.ComputeTotp();
    AnsiConsole.MarkupLine($"\n[grey]Current TOTP Code (for demo): {currentCode}[/]");

    string inputCode = AnsiConsole.Ask<string>("[bold]Enter the code from your Google Authenticator app:[/]").Trim();

    bool isValid = totp.VerifyTotp(inputCode, out _);
    if (isValid)
      AnsiConsole.MarkupLine("[bold green]✅ Code is valid![/]");
    else
      AnsiConsole.MarkupLine("[bold red]❌ Invalid code.[/]");
  }

  static void SaveQrCodeToFile(string uri, string filename)
  {
    string downloadsPath = Path.Combine(
      Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
      "Downloads"
    );
    Directory.CreateDirectory(downloadsPath);
    string fullPath = Path.Combine(downloadsPath, filename);

    QRCodeGenerator qrGenerator = new QRCodeGenerator();
    QRCodeData qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
    PngByteQRCode qrCode = new(qrCodeData);
    byte[] qrCodeAsPngByteArr = qrCode.GetGraphic(20);

    File.WriteAllBytes(fullPath, qrCodeAsPngByteArr);

    try { Process.Start(new ProcessStartInfo(fullPath) { UseShellExecute = true }); } catch { }
  }
}
