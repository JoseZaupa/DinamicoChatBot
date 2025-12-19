using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();
var app = builder.Build();

// ============================
// ENV (launchSettings.json / SO)
// ============================
var verifyToken = Environment.GetEnvironmentVariable("WA_VERIFY_TOKEN") ?? "";
var accessToken = Environment.GetEnvironmentVariable("WA_ACCESS_TOKEN") ?? "";
var phoneNumberId = Environment.GetEnvironmentVariable("WA_PHONE_NUMBER_ID") ?? "";
var appSecret = Environment.GetEnvironmentVariable("WA_APP_SECRET") ?? ""; // opcional
var groqApiKey = Environment.GetEnvironmentVariable("GROQ_API_KEY") ?? "";

// ============================
// Log em arquivo (bem simples)
// ============================
var logDir = Path.Combine(Environment.GetEnvironmentVariable("HOME") ?? "/home", "LogFiles");
Directory.CreateDirectory(logDir);

var logFile = Path.Combine(logDir, "webhook.log");
var logLock = new SemaphoreSlim(1, 1);

async Task LogAsync(string text)
{
    try
    {
        await logLock.WaitAsync();
        await File.AppendAllTextAsync(logFile, text);
    }
    catch
    {
        // não derruba a API se log falhar
    }
    finally
    {
        if (logLock.CurrentCount == 0)
            logLock.Release();
    }
}

app.Use(async (ctx, next) =>
{
    await LogAsync($"{DateTime.Now:O} {ctx.Request.Method} {ctx.Request.Path}{ctx.Request.QueryString}{Environment.NewLine}");
    await next();
});

app.MapGet("/", () => "DinamicoChatBot rodando!");

// ============================
// Estado: histórico por número
// (sem record/class, só tupla)
// ============================
var historyByFrom = new ConcurrentDictionary<string, List<(string role, string content)>>();

// ============================
// Webhook GET (verificação Meta)
// ============================
app.MapGet("/webhook", (HttpRequest req) =>
{
    var mode = req.Query["hub.mode"].ToString();
    var token = req.Query["hub.verify_token"].ToString();
    var challenge = req.Query["hub.challenge"].ToString();

    if (mode == "subscribe" && token == verifyToken)
        return Results.Text(challenge, "text/plain", Encoding.UTF8);

    return Results.Ok("ok");
});

// ============================
// Webhook POST (eventos)
// ============================
app.MapPost("/webhook", async (HttpRequest req, IHttpClientFactory httpFactory) =>
{
    using var ms = new MemoryStream();
    await req.Body.CopyToAsync(ms);
    var bodyBytes = ms.ToArray();
    var body = Encoding.UTF8.GetString(bodyBytes);

    await LogAsync($"{DateTime.Now:O} POST BODY:\n{body}\n\n");

    // assinatura (opcional)
    if (!string.IsNullOrWhiteSpace(appSecret))
    {
        if (!req.Headers.TryGetValue("X-Hub-Signature-256", out var sigHeader) ||
            !IsValidMetaSignature(sigHeader.ToString(), bodyBytes, appSecret))
        {
            await LogAsync($"{DateTime.Now:O} SIGNATURE INVALID\n\n");
            return Results.Unauthorized();
        }
    }

    // inbound text
    if (!TryExtractIncomingText(body, out var from, out var text))
        return Results.Ok(); // ACK

    // responde async (pra devolver ACK rápido)
    _ = Task.Run(async () =>
    {
        try
        {
            var reply = string.IsNullOrWhiteSpace(text)
                ? "Recebi sua mensagem ✅"
                : await GetGroqReplyAsync(httpFactory, groqApiKey, historyByFrom, from, text);

            if (string.IsNullOrWhiteSpace(accessToken) || string.IsNullOrWhiteSpace(phoneNumberId))
            {
                await LogAsync($"{DateTime.Now:O} ERRO: WA_ACCESS_TOKEN ou WA_PHONE_NUMBER_ID não configurado.\n\n");
                return;
            }

            var url = $"https://graph.facebook.com/v22.0/{phoneNumberId}/messages";
            var payload = new
            {
                messaging_product = "whatsapp",
                to = from,
                type = "text",
                text = new { body = reply }
            };

            var client = httpFactory.CreateClient();
            client.Timeout = TimeSpan.FromSeconds(15);

            var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            request.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

            var resp = await client.SendAsync(request);
            var respText = await resp.Content.ReadAsStringAsync();

            await LogAsync($"{DateTime.Now:O} SEND RESP: {(int)resp.StatusCode} {resp.StatusCode}\n{respText}\n\n");
        }
        catch (Exception ex)
        {
            await LogAsync($"{DateTime.Now:O} SEND EX: {ex}\n\n");
        }
    });

    return Results.Ok();
});

app.Run();


// ============================
// Helpers
// ============================
static bool TryExtractIncomingText(string json, out string from, out string text)
{
    from = "";
    text = "";

    try
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        if (!root.TryGetProperty("entry", out var entryArr) || entryArr.GetArrayLength() == 0) return false;
        var entry0 = entryArr[0];

        if (!entry0.TryGetProperty("changes", out var changesArr) || changesArr.GetArrayLength() == 0) return false;
        var change0 = changesArr[0];

        if (!change0.TryGetProperty("value", out var value)) return false;

        if (!value.TryGetProperty("messages", out var messages) || messages.GetArrayLength() == 0) return false;
        var msg0 = messages[0];

        from = msg0.TryGetProperty("from", out var fromEl) ? (fromEl.GetString() ?? "") : "";
        if (string.IsNullOrWhiteSpace(from)) return false;

        var type = msg0.TryGetProperty("type", out var typeEl) ? (typeEl.GetString() ?? "") : "";
        if (!string.Equals(type, "text", StringComparison.OrdinalIgnoreCase)) return false;

        if (msg0.TryGetProperty("text", out var t) && t.TryGetProperty("body", out var bodyEl))
            text = bodyEl.GetString() ?? "";

        return true;
    }
    catch
    {
        return false;
    }
}

static bool IsValidMetaSignature(string headerValue, byte[] body, string appSecret)
{
    if (string.IsNullOrWhiteSpace(headerValue)) return false;
    if (!headerValue.StartsWith("sha256=", StringComparison.OrdinalIgnoreCase)) return false;

    var sigHex = headerValue.Substring("sha256=".Length).Trim();
    if (sigHex.Length == 0) return false;

    using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(appSecret));
    var hash = hmac.ComputeHash(body);
    var computedHex = Convert.ToHexString(hash).ToLowerInvariant();

    return CryptographicOperations.FixedTimeEquals(
        Encoding.UTF8.GetBytes(computedHex),
        Encoding.UTF8.GetBytes(sigHex.ToLowerInvariant())
    );
}

static async Task<string> GetGroqReplyAsync(
    IHttpClientFactory httpFactory,
    string groqApiKey,
    ConcurrentDictionary<string, List<(string role, string content)>> historyByFrom,
    string from,
    string userText,
    CancellationToken ct = default)
{
    if (string.IsNullOrWhiteSpace(groqApiKey))
        return "⚠️ GROQ_API_KEY não configurada.";

    var history = historyByFrom.GetOrAdd(from, _ => new List<(string role, string content)>());

    lock (history)
    {
        history.Add(("user", userText));
        if (history.Count > 10) history.RemoveRange(0, history.Count - 10);
    }

    var messages = new List<object>
    {
        new { role = "system", content = "Você é um atendente de WhatsApp educado e objetivo.Seu nome é Beatriz. Você é envolvente. Responda em PT-BR e curto." }
    };

    lock (history)
    {
        foreach (var (role, content) in history)
            messages.Add(new { role, content });
    }

    var payload = new
    {
        model = "llama-3.1-8b-instant",
        messages = messages,
        temperature = 0.7
    };

    var client = httpFactory.CreateClient();
    client.Timeout = TimeSpan.FromSeconds(20);

    using var req = new HttpRequestMessage(HttpMethod.Post, "https://api.groq.com/openai/v1/chat/completions");
    req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", groqApiKey);
    req.Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    using var resp = await client.SendAsync(req, ct);
    var respText = await resp.Content.ReadAsStringAsync(ct);

    if (!resp.IsSuccessStatusCode)
        return $"⚠️ Falha na IA: {(int)resp.StatusCode} {resp.ReasonPhrase}\n{respText}";

    string reply;
    try
    {
        using var doc = JsonDocument.Parse(respText);
        reply = doc.RootElement.GetProperty("choices")[0].GetProperty("message").GetProperty("content").GetString() ?? "";
    }
    catch
    {
        reply = "";
    }

    reply = string.IsNullOrWhiteSpace(reply) ? "Desculpe, não consegui responder agora." : reply.Trim();

    lock (history)
    {
        history.Add(("assistant", reply));
        if (history.Count > 10) history.RemoveRange(0, history.Count - 10);
    }

    return reply;
}
