using System.Security.Cryptography;
using System.Text;
using System.Threading.RateLimiting;
using Microsoft.Data.SqlClient;
using Dapper;

// 🚀 KEMBALI MENGGUNAKAN MAILKIT (Terbukti lolos dari Client Host Rejected Bizmail)
using MimeKit;
using MailKit.Net.Smtp;

var builder = WebApplication.CreateBuilder(args);

// Register baseline API Explorer services for OpenAPI testing
builder.Services.AddOpenApi();

// Register the Email infrastructure service into the Dependency Injection container
builder.Services.AddTransient<IEmailService, MailKitSmtpService>();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Dynamically fetch the connection string from appsettings.json
string connectionString = app.Configuration.GetConnectionString("DefaultConnection")!;


// =========================================================================
// API : PLAIN TEXT OTP GENERATION - DEVELOPMENT
// =========================================================================
app.MapPost("/api/2fa/sendplain", async (SendOtpRequest request, IEmailService emailService) =>
{
    if (string.IsNullOrEmpty(request.Email))
        return Results.BadRequest(new { error = "Email is required." });

    string plainOtp = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
    string referenceCode = $"REF-{RandomNumberGenerator.GetInt32(1000, 9999)}";

    using var db = new SqlConnection(connectionString);
    try
    {
        string spQuery = "EXEC sp_GenerateAndSendOTP @Email, @TokenCode, @ReferenceCode";
        var dbResult = await db.QueryFirstOrDefaultAsync<dynamic>(spQuery, new { Email = request.Email, TokenCode = plainOtp, ReferenceCode = referenceCode });

        int state = dbResult.ResultState;
        string feedbackMessage = dbResult.Message;

        if (state == 1)
        {
            return Results.Json(new { error = feedbackMessage }, statusCode: 429);
        }

        // Send Email via MailKit Pipeline
        try
        {
            await emailService.SendEmailAsync(request.Email, plainOtp, referenceCode);
        }
        catch (Exception mailEx)
        {
            return Results.Ok(new
            {
                message = "OTP generated successfully in Database, but email dispatch failed.",
                refCode = referenceCode,
                systemWarning = mailEx.Message
            });
        }

        return Results.Ok(new { message = "Plain-text OTP sent successfully.", refCode = referenceCode });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Database processing infrastructure failure: {ex.Message}");
    }
});

// =========================================================================
// API : HASHED OTP GENERATION - PRODUCTION 
// =========================================================================
app.MapPost("/api/2fa/send", async (SendOtpRequest request, IEmailService emailService) =>
{
    if (string.IsNullOrEmpty(request.Email))
        return Results.BadRequest(new { error = "Email is required." });

    string plainOtp = RandomNumberGenerator.GetInt32(100000, 999999).ToString();
    string referenceCode = $"REF-{RandomNumberGenerator.GetInt32(1000, 9999)}";
    string hashedOtp = SecurityExtensions.ComputeSha256Hash(plainOtp);

    using var db = new SqlConnection(connectionString);
    try
    {
        string spQuery = "EXEC sp_GenerateAndSendOTP @Email, @TokenCode, @ReferenceCode";
        var dbResult = await db.QueryFirstOrDefaultAsync<dynamic>(spQuery, new { Email = request.Email, TokenCode = hashedOtp, ReferenceCode = referenceCode });

        int state = dbResult.ResultState;
        string feedbackMessage = dbResult.Message;

        if (state == 1)
        {
            return Results.Json(new { error = feedbackMessage }, statusCode: 429);
        }

        // Send Email via MailKit Pipeline
        try
        {
            await emailService.SendEmailAsync(request.Email, plainOtp, referenceCode);
        }
        catch (Exception mailEx)
        {
            return Results.Ok(new
            {
                message = "OTP generated successfully in Database, but email dispatch failed.",
                refCode = referenceCode,
                systemWarning = mailEx.Message
            });
        }

        return Results.Ok(new { message = "OTP sent successfully.", refCode = referenceCode });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Database processing infrastructure failure: {ex.Message}");
    }
});


// =========================================================================
// API : PLAIN TEXT OTP VERIFICATION - DEVELOPMENT
// =========================================================================
app.MapPost("/api/2fa/verifyplain", async (VerifyOtpRequest request) =>
{
    if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.TokenCode))
        return Results.BadRequest(new { error = "Email and verification code are required." });

    using var db = new SqlConnection(connectionString);
    try
    {
        var result = await db.QueryFirstOrDefaultAsync<dynamic>(
            "EXEC sp_VerifyOTP @Email, @InputCode",
            new { Email = request.Email, InputCode = request.TokenCode }
        );

        int state = result.ResultState;
        string feedbackMessage = result.Message;

        if (state == 0) return Results.Ok(new { message = feedbackMessage });
        if (state == 2) return Results.BadRequest(new { error = $"{feedbackMessage} You have {result.AttemptsRemaining} attempts remaining." });

        return Results.BadRequest(new { error = feedbackMessage });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Database processing infrastructure failure: {ex.Message}");
    }
});

// =========================================================================
// API : HASHED OTP VERIFICATION - PRODUCTION 
// =========================================================================
app.MapPost("/api/2fa/verify", async (VerifyOtpRequest request) =>
{
    if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.TokenCode))
        return Results.BadRequest(new { error = "Email and verification code are required." });

    string inputHash = SecurityExtensions.ComputeSha256Hash(request.TokenCode);

    using var db = new SqlConnection(connectionString);
    try
    {
        var result = await db.QueryFirstOrDefaultAsync<dynamic>(
            "EXEC sp_VerifyOTP @Email, @InputCode",
            new { Email = request.Email, InputCode = inputHash }
        );

        int state = result.ResultState;
        string feedbackMessage = result.Message;

        if (state == 0) return Results.Ok(new { message = feedbackMessage });
        if (state == 2) return Results.BadRequest(new { error = $"{feedbackMessage} You have {result.AttemptsRemaining} attempts remaining." });

        return Results.BadRequest(new { error = feedbackMessage });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Database processing infrastructure failure: {ex.Message}");
    }
});

app.UseMiddleware<HttpTransactionLoggerMiddleware>();

app.Run();

public record SendOtpRequest(string Email);
public record VerifyOtpRequest(string Email, string TokenCode);


// =========================================================================
// NOTIFICATION UTILITY INTERFACE
// =========================================================================
public interface IEmailService
{
    Task SendEmailAsync(string targetEmail, string otpCode, string referenceCode);
}

public class MailKitSmtpService : IEmailService
{
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;

    public MailKitSmtpService(IConfiguration config, IWebHostEnvironment env)
    {
        _config = config;
        _env = env;
    }

    public async Task SendEmailAsync(string targetEmail, string otpCode, string referenceCode)
    {
        var settings = _config.GetSection("SmtpSettings");

        string relativePath = settings["TemplatePath"] ?? "Templates/EmailTemplate.html";
        string absolutePath = Path.Combine(_env.ContentRootPath, relativePath);

        if (!File.Exists(absolutePath))
        {
            throw new FileNotFoundException($"Template HTML tidak ditemukan: {absolutePath}");
        }

        string htmlBody = await File.ReadAllTextAsync(absolutePath, Encoding.UTF8);
        htmlBody = htmlBody.Replace("{{SenderName}}", settings["SenderName"])
                           .Replace("{{OtpCode}}", otpCode)
                           .Replace("{{ReferenceCode}}", referenceCode);

        var message = new MimeMessage();
        message.From.Add(new MailboxAddress(settings["SenderName"], settings["SenderEmail"]));
        message.To.Add(new MailboxAddress("", targetEmail));
        message.Subject = $"Your 2FA Security Code [{referenceCode}]";

        message.Body = new TextPart("html") { Text = htmlBody };

        using var client = new SmtpClient();
        client.Timeout = 15000;  // Batas toleransi jabat tangan 15 detik

        int port = int.Parse(settings["Port"]!);
        var secureOption = port == 465
            ? MailKit.Security.SecureSocketOptions.SslOnConnect
            : MailKit.Security.SecureSocketOptions.StartTls;

        await client.ConnectAsync(settings["Server"], port, secureOption);

        // 🔒 KUNCI SAKTI: Hapus semua metode penyerahan password bawaan MailKit
        client.AuthenticationMechanisms.Clear();

        // 🚀 PAKSA HANYA PAKAI "LOGIN" (Sama 1-to-1 dengan metode yang dipakai PowerShell)
        client.AuthenticationMechanisms.Add("LOGIN");

        await client.AuthenticateAsync(settings["SenderEmail"], settings["Password"]);
        await client.SendAsync(message);
        await client.DisconnectAsync(true);
    }
}

// =========================================================================
// CRYPTOGRAPHIC EXTENSIONS ENGINE
// =========================================================================
public static partial class SecurityExtensions
{
    public static string ComputeSha256Hash(string rawData)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(rawData));
        StringBuilder builder = new();
        for (int i = 0; i < bytes.Length; i++)
        {
            builder.Append(bytes[i].ToString("X2"));
        }
        return builder.ToString();
    }
}

// =========================================================================
// ENTERPRISE INTERCEPTOR MIDDLEWARE (Boxed Output Log Engine)
// =========================================================================
public class HttpTransactionLoggerMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _config;
    private static readonly object _fileLock = new();

    public HttpTransactionLoggerMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;
        _config = config;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        context.Request.EnableBuffering();
        string requestBody = string.Empty;

        using (var reader = new StreamReader(context.Request.Body, Encoding.UTF8, leaveOpen: true))
        {
            requestBody = await reader.ReadToEndAsync();
            context.Request.Body.Position = 0;
        }

        var originalResponseStream = context.Response.Body;
        using var memStream = new MemoryStream();
        context.Response.Body = memStream;

        await _next(context);

        memStream.Position = 0;
        string responseBody = await new StreamReader(memStream).ReadToEndAsync();
        memStream.Position = 0;
        await memStream.CopyToAsync(originalResponseStream);

        var headerBuilder = new StringBuilder();
        foreach (var header in context.Response.Headers)
        {
            headerBuilder.AppendLine($"║   {header.Key}: {header.Value}");
        }

        var logBuilder = new StringBuilder();
        logBuilder.AppendLine("╔══════════════════════════════════════════════════════════════");
        logBuilder.AppendLine($"║ TIMESTAMP       : {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}");
        logBuilder.AppendLine("╠═══ REQUEST ══════════════════════════════════════════════════");
        logBuilder.AppendLine($"║ URL             : {context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}");
        logBuilder.AppendLine($"║ HTTP METHOD     : {context.Request.Method}");
        logBuilder.AppendLine($"║ CONTENT-TYPE    : {context.Request.ContentType ?? "N/A"}");
        logBuilder.AppendLine($"║ BODY            : {(!string.IsNullOrEmpty(requestBody) ? requestBody : "{}")}");
        logBuilder.AppendLine("╠═══ RESPONSE ═════════════════════════════════════════════════");
        logBuilder.AppendLine($"║ STATUS CODE     : {context.Response.StatusCode}");
        logBuilder.AppendLine($"║ CONTENT-TYPE    : {context.Response.ContentType ?? "N/A"}");
        logBuilder.AppendLine("║ HEADERS         :");
        logBuilder.Append(headerBuilder.ToString());
        logBuilder.AppendLine($"║ BODY            : {(!string.IsNullOrEmpty(responseBody) ? responseBody : "{}")}");
        logBuilder.AppendLine("╚══════════════════════════════════════════════════════════════");
        logBuilder.AppendLine();

        ExecuteRollingWrite(logBuilder.ToString());
    }

    private void ExecuteRollingWrite(string logContent)
    {
        var settings = _config.GetSection("FileLogSettings");
        string filePath = settings["LogFilePath"] ?? "log.txt";
        long maxSizeBytes = long.Parse(settings["MaxFileSizeBytes"] ?? "5242880");

        lock (_fileLock)
        {
            var fileInfo = new FileInfo(filePath);
            if (fileInfo.Exists && fileInfo.Length >= maxSizeBytes)
            {
                string backupPath = $"log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                File.Move(filePath, backupPath, overwrite: true);
            }
            File.AppendAllText(filePath, logContent, Encoding.UTF8);
        }
    }
}