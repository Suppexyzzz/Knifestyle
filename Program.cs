using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();

string dataPath = Environment.GetEnvironmentVariable("KNIFESTYLE_DATA_DIR")
    ?? Path.Combine(AppContext.BaseDirectory, "data");
string releasePath = Path.Combine(AppContext.BaseDirectory, "releases");
Directory.CreateDirectory(dataPath);
Directory.CreateDirectory(releasePath);
var store = new JsonStore(Path.Combine(dataPath, "license-data.json"));
var sessions = new ConcurrentDictionary<string, LoginSession>();
var attempts = new ConcurrentDictionary<string, AttemptWindow>();
var registrationAttempts = new ConcurrentDictionary<string, AttemptWindow>();
string setupKey = Environment.GetEnvironmentVariable("KNIFESTYLE_SETUP_KEY") ?? "";
await store.Mutate(state =>
{
    if (state.Release is null)
    {
        string? seedJar = Directory.GetFiles(releasePath, "knifestyle-*.jar").FirstOrDefault();
        if (seedJar is not null)
        {
            string name = Path.GetFileName(seedJar);
            string version = Regex.Match(name, @"^knifestyle-(.+)\.jar$", RegexOptions.IgnoreCase).Groups[1].Value;
            if (version.Length > 0)
                state.Release = new ReleaseInfo(version, name, Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(seedJar))), File.GetLastWriteTimeUtc(seedJar));
        }
    }
    return true;
});

app.MapGet("/api/status", async () =>
{
    var status = await store.Read(s => new
    {
        setupAvailable = !string.IsNullOrWhiteSpace(setupKey) && !s.Accounts.Any(a => a.IsOwner),
        release = s.Release is null ? null : new { s.Release.Version, s.Release.FileName, s.Release.Sha256, s.Release.UpdatedUtc }
    });
    return Results.Json(status);
});

app.MapPost("/api/admin/setup", async (HttpContext context, SetupRequest req) =>
{
    if (string.IsNullOrWhiteSpace(setupKey) || !FixedEquals(req.SetupKey ?? "", setupKey))
        return Results.Json(new { error = "Setup-Schlüssel ungültig." }, statusCode: 403);
    if (!ValidCredentials(req.Username, req.Password, out string error))
        return Results.Json(new { error }, statusCode: 400);
    var result = await store.Mutate(state =>
    {
        if (state.Accounts.Any(a => a.IsOwner)) return false;
        state.Accounts.Add(NewAccount(req.Username!, req.Password!, isAdmin: true, expiry: null, isOwner: true));
        return true;
    });
    return result ? Results.Ok(new { created = true }) : Results.Conflict(new { error = "Admin wurde bereits eingerichtet." });
});

app.MapPost("/api/auth/register", async (HttpContext context, RegisterRequest req) =>
{
    string remote = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (!AllowAttempt(remote, registrationAttempts)) return Results.Json(new { error = "Zu viele Registrierungen. Bitte warte einige Minuten." }, statusCode: 429);
    if (!ValidCredentials(req.Username, req.Password, out string error)) return Results.BadRequest(new { error });
    if (string.IsNullOrWhiteSpace(req.LicenseKey)) return Results.BadRequest(new { error = "Lizenzschlüssel erforderlich." });
    string result = await store.Mutate(state =>
    {
        if (state.Accounts.Any(a => a.Username.Equals(req.Username, StringComparison.OrdinalIgnoreCase))) return "username";
        string keyHash = Hash(req.LicenseKey.Trim().ToUpperInvariant());
        var licenseKey = state.LicenseKeys.FirstOrDefault(k => k.KeyHash == keyHash && k.RedeemedUtc is null);
        if (licenseKey is null) return "key";
        DateTimeOffset redeemedAt = DateTimeOffset.UtcNow;
        DateTimeOffset? expiry = licenseKey.DurationCode switch
        {
            "month_1" => redeemedAt.AddMonths(1),
            "months_3" => redeemedAt.AddMonths(3),
            "year_1" => redeemedAt.AddYears(1),
            "lifetime" => null,
            _ => DateTimeOffset.MinValue
        };
        if (expiry == DateTimeOffset.MinValue) return "key";
        state.Accounts.Add(NewAccount(req.Username!, req.Password!, isAdmin: false, expiry));
        licenseKey.RedeemedUtc = redeemedAt;
        licenseKey.RedeemedBy = req.Username!.Trim();
        return "created";
    });
    return result switch
    {
        "created" => Results.Created("/register.html", new { created = true, message = "Konto erstellt. Du kannst dich jetzt im Loader anmelden." }),
        "username" => Results.Conflict(new { error = "Dieser Username ist bereits vergeben." }),
        _ => Results.BadRequest(new { error = "Lizenzschlüssel ungültig oder bereits verwendet." })
    };
});

app.MapPost("/api/auth/login", async (HttpContext context, LoginRequest req) =>
{
    string remote = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    if (!AllowAttempt(remote, attempts)) return Results.Json(new { error = "Zu viele Login-Versuche. Warte einige Minuten." }, statusCode: 429);
    var account = await store.Read(s => s.Accounts.FirstOrDefault(a => a.Username.Equals(req.Username ?? "", StringComparison.OrdinalIgnoreCase)));
    if (account is null || !VerifyPassword(req.Password ?? "", account))
        return Results.Json(new { error = "Login ungültig oder Lizenz nicht aktiv." }, statusCode: 401);
    if (!IsLicenseActive(account)) return Results.Json(new { error = "Login ungültig oder Lizenz nicht aktiv." }, statusCode: 401);

    string token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    string tokenHash = Hash(token);
    sessions[tokenHash] = new LoginSession(account.Username, DateTimeOffset.UtcNow.AddHours(8));
    attempts.TryRemove(remote, out _);
    return Results.Json(new { accessToken = token, username = account.Username, role = account.IsAdmin ? "admin" : "user", isOwner = account.IsOwner, expiresUtc = DateTimeOffset.UtcNow.AddHours(8) });
});

app.MapPost("/api/loader/authorize", async (HttpContext context, DeviceRequest req) =>
{
    var account = await GetAuthorizedAccount(context, sessions, store, adminOnly: false);
    if (account is null) return Results.Json(new { error = "Login erforderlich." }, statusCode: 401);
    if (!IsLicenseActive(account)) return Results.Json(new { error = "Lizenz inaktiv oder abgelaufen." }, statusCode: 403);
    if (!ValidDeviceId(req.DeviceId)) return Results.Json(new { error = "Geräte-ID ungültig." }, statusCode: 400);

    string result = await store.Mutate(state =>
    {
        var current = state.Accounts.FirstOrDefault(a => a.Username.Equals(account.Username, StringComparison.OrdinalIgnoreCase));
        if (current is null || !IsLicenseActive(current)) return "inactive";
        if (current.DeviceId is null) current.DeviceId = req.DeviceId;
        if (!FixedEquals(current.DeviceId ?? "", req.DeviceId ?? "")) return "device";
        current.LastSeenUtc = DateTimeOffset.UtcNow;
        current.LastDeviceId = req.DeviceId;
        return "ok";
    });
    return result switch
    {
        "ok" => Results.Ok(new { authorized = true, account = account.Username }),
        "device" => Results.Json(new { error = "Dieses Konto ist bereits an ein anderes Gerät gebunden. Bitte Admin um Geräte-Reset bitten." }, statusCode: 403),
        _ => Results.Json(new { error = "Lizenz inaktiv oder abgelaufen." }, statusCode: 403)
    };
});

app.MapGet("/api/loader/mod", async (HttpContext context) =>
{
    var account = await GetAuthorizedAccount(context, sessions, store, adminOnly: false);
    if (account is null) return Results.Json(new { error = "Login erforderlich." }, statusCode: 401);
    string deviceId = context.Request.Headers["X-Device-ID"].ToString();
    if (!ValidDeviceId(deviceId)) return Results.Json(new { error = "Geräte-ID ungültig." }, statusCode: 400);
    var data = await store.Read(s =>
    {
        var current = s.Accounts.FirstOrDefault(a => a.Username.Equals(account.Username, StringComparison.OrdinalIgnoreCase));
        return (Account: current, Release: s.Release);
    });
    if (data.Account is null || !IsLicenseActive(data.Account)) return Results.Json(new { error = "Lizenz abgelaufen." }, statusCode: 403);
    if (data.Account.DeviceId is null || !FixedEquals(data.Account.DeviceId, deviceId))
        return Results.Json(new { error = "Gerät wurde noch nicht autorisiert." }, statusCode: 403);
    if (data.Release is null) return Results.NotFound(new { error = "Noch keine Mod-Version veröffentlicht." });
    string file = Path.Combine(releasePath, Path.GetFileName(data.Release.FileName));
    if (!File.Exists(file)) return Results.NotFound(new { error = "Mod-Datei fehlt auf dem Server." });
    context.Response.Headers["X-KnifeStyle-Version"] = data.Release.Version;
    context.Response.Headers["X-KnifeStyle-SHA256"] = data.Release.Sha256;
    return Results.File(file, "application/java-archive", data.Release.FileName, enableRangeProcessing: false);
});

app.MapGet("/api/admin/accounts", async (HttpContext ctx) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    var accounts = await store.Read(s => s.Accounts.OrderBy(a => a.Username).Select(a => new
    {
        a.Username, a.IsAdmin, a.IsOwner, a.Enabled, a.ExpiresUtc, deviceBound = a.DeviceId is not null,
        a.LastSeenUtc, a.CreatedUtc
    }).ToList());
    return Results.Json(accounts);
});

app.MapPost("/api/admin/license-keys", async (HttpContext ctx, CreateLicenseKeyRequest req) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    string? durationLabel = LicenseDurationLabel(req.DurationCode);
    if (durationLabel is null) return Results.BadRequest(new { error = "Ungültige Laufzeit." });
    string key = "KS-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    var licenseKey = new LicenseKey
    {
        Id = Guid.NewGuid().ToString("N"),
        KeyHash = Hash(key),
        DurationCode = req.DurationCode,
        CreatedUtc = DateTimeOffset.UtcNow
    };
    await store.Mutate(state => { state.LicenseKeys.Add(licenseKey); return true; });
    return Results.Created("/api/admin/license-keys", new { licenseKey = key, durationCode = req.DurationCode, durationLabel, licenseKey.CreatedUtc });
});

app.MapGet("/api/admin/license-keys", async (HttpContext ctx) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    var keys = await store.Read(s => s.LicenseKeys.OrderByDescending(k => k.CreatedUtc)
        .Select(k => new { k.Id, k.DurationCode, k.CreatedUtc, k.RedeemedUtc, k.RedeemedBy }).ToList());
    return Results.Json(keys);
});

app.MapDelete("/api/admin/license-keys/{id}", async (HttpContext ctx, string id) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    bool deleted = await store.Mutate(state =>
    {
        var key = state.LicenseKeys.FirstOrDefault(k => k.Id == id && k.RedeemedUtc is null);
        return key is not null && state.LicenseKeys.Remove(key);
    });
    return deleted ? Results.Ok(new { deleted = true }) : Results.NotFound(new { error = "Unbenutzter Lizenzschlüssel nicht gefunden." });
});

app.MapPatch("/api/admin/accounts/{username}/role", async (HttpContext ctx, string username, RoleRequest req) =>
{
    var actor = await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true);
    if (actor is null) return Results.Unauthorized();
    if (!actor.IsOwner) return Results.Json(new { error = "Nur das Besitzerkonto kann Adminrollen vergeben oder entziehen." }, statusCode: 403);
    if (!req.IsAdmin.HasValue) return Results.BadRequest(new { error = "Neue Rolle fehlt." });
    string result = await store.Mutate(state =>
    {
        var account = state.Accounts.FirstOrDefault(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (account is null) return "missing";
        if (account.IsOwner) return "owner";
        account.IsAdmin = req.IsAdmin.Value;
        return "ok";
    });
    return result switch
    {
        "ok" => Results.Ok(new { updated = true, isAdmin = req.IsAdmin.Value }),
        "owner" => Results.Json(new { error = "Das Besitzerkonto kann nicht herabgestuft werden." }, statusCode: 403),
        _ => Results.NotFound(new { error = "Konto nicht gefunden." })
    };
});

app.MapPatch("/api/admin/accounts/{username}/license", async (HttpContext ctx, string username, LicenseRequest req) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    bool changed = await store.Mutate(state =>
    {
        var account = state.Accounts.FirstOrDefault(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && !a.IsOwner);
        if (account is null) return false;
        if (req.Enabled.HasValue) account.Enabled = req.Enabled.Value;
        if (req.ExpiresUtc.HasValue) account.ExpiresUtc = req.ExpiresUtc.Value;
        return true;
    });
    return changed ? Results.Ok(new { updated = true }) : Results.NotFound(new { error = "Konto nicht gefunden." });
});

app.MapPost("/api/admin/accounts/{username}/reset-device", async (HttpContext ctx, string username) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    bool changed = await store.Mutate(state =>
    {
        var account = state.Accounts.FirstOrDefault(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && !a.IsOwner);
        if (account is null) return false;
        account.DeviceId = null; account.LastDeviceId = null;
        return true;
    });
    return changed ? Results.Ok(new { reset = true }) : Results.NotFound(new { error = "Konto nicht gefunden." });
});

app.MapPost("/api/admin/accounts/{username}/password", async (HttpContext ctx, string username, PasswordRequest req) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    if (string.IsNullOrWhiteSpace(req.Password) || req.Password.Length < 10) return Results.BadRequest(new { error = "Passwort muss mindestens 10 Zeichen haben." });
    bool changed = await store.Mutate(state =>
    {
        var account = state.Accounts.FirstOrDefault(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && !a.IsOwner);
        if (account is null) return false;
        SetPassword(account, req.Password);
        return true;
    });
    return changed ? Results.Ok(new { updated = true }) : Results.NotFound(new { error = "Konto nicht gefunden." });
});

app.MapDelete("/api/admin/accounts/{username}", async (HttpContext ctx, string username) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    bool deleted = await store.Mutate(state =>
    {
        var account = state.Accounts.FirstOrDefault(a => a.Username.Equals(username, StringComparison.OrdinalIgnoreCase) && !a.IsOwner);
        return account != null && state.Accounts.Remove(account);
    });
    return deleted ? Results.Ok(new { deleted = true }) : Results.NotFound(new { error = "Konto nicht gefunden." });
});

app.MapPost("/api/admin/release", async (HttpContext ctx) =>
{
    if (await GetAuthorizedAccount(ctx, sessions, store, adminOnly: true) is null) return Results.Unauthorized();
    if (!ctx.Request.HasFormContentType) return Results.BadRequest(new { error = "Upload muss multipart/form-data sein." });
    var form = await ctx.Request.ReadFormAsync();
    var file = form.Files.GetFile("file");
    string version = form["version"].ToString().Trim();
    if (file is null || !file.FileName.EndsWith(".jar", StringComparison.OrdinalIgnoreCase) || file.Length < 1024 || file.Length > 30_000_000)
        return Results.BadRequest(new { error = "Eine gültige JAR-Datei bis 30 MB auswählen." });
    if (!Regex.IsMatch(version, @"^[0-9A-Za-z][0-9A-Za-z._+-]{0,39}$")) return Results.BadRequest(new { error = "Versionsname ungültig." });
    string filename = $"knifestyle-{version}.jar";
    string destination = Path.Combine(releasePath, filename);
    string temporary = destination + ".upload";
    await using (var output = File.Create(temporary)) await file.CopyToAsync(output);
    string sha;
    await using (var input = File.OpenRead(temporary)) sha = Convert.ToHexString(await SHA256.HashDataAsync(input));
    File.Move(temporary, destination, true);
    var release = new ReleaseInfo(version, filename, sha, DateTimeOffset.UtcNow);
    await store.Mutate(state => { state.Release = release; return true; });
    return Results.Ok(new { release.Version, release.FileName, release.Sha256, release.UpdatedUtc });
});

app.Run();

static Account NewAccount(string username, string password, bool isAdmin, DateTimeOffset? expiry, bool isOwner = false)
{
    var account = new Account { Username = username.Trim(), IsAdmin = isAdmin, IsOwner = isOwner, Enabled = true, CreatedUtc = DateTimeOffset.UtcNow, ExpiresUtc = expiry };
    SetPassword(account, password);
    return account;
}

static void SetPassword(Account account, string password)
{
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 310_000, HashAlgorithmName.SHA256, 32);
    account.PasswordSalt = Convert.ToBase64String(salt);
    account.PasswordHash = Convert.ToBase64String(hash);
}

static bool VerifyPassword(string password, Account account)
{
    try
    {
        byte[] salt = Convert.FromBase64String(account.PasswordSalt);
        byte[] expected = Convert.FromBase64String(account.PasswordHash);
        byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 310_000, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
    catch { return false; }
}

static bool IsLicenseActive(Account account) => account.Enabled && (account.ExpiresUtc is null || account.ExpiresUtc > DateTimeOffset.UtcNow);
static string? LicenseDurationLabel(string code) => code switch
{
    "month_1" => "1 Monat",
    "months_3" => "3 Monate",
    "year_1" => "1 Jahr",
    "lifetime" => "Lifetime",
    _ => null
};
static bool ValidDeviceId(string? id) => id is { Length: 64 } && id.All(Uri.IsHexDigit);
static string Hash(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
static bool FixedEquals(string left, string right)
{
    byte[] a = Encoding.UTF8.GetBytes(left), b = Encoding.UTF8.GetBytes(right);
    return a.Length == b.Length && CryptographicOperations.FixedTimeEquals(a, b);
}
static bool ValidCredentials(string? username, string? password, out string error)
{
    if (username is null || !Regex.IsMatch(username, @"^[A-Za-z0-9_.-]{3,32}$")) { error = "Username: 3–32 Zeichen, Buchstaben/Zahlen/._-"; return false; }
    if (password is null || password.Length < 10 || password.Length > 128) { error = "Passwort muss 10–128 Zeichen haben."; return false; }
    error = ""; return true;
}
static bool AllowAttempt(string remote, ConcurrentDictionary<string, AttemptWindow> attempts)
{
    var now = DateTimeOffset.UtcNow;
    var window = attempts.AddOrUpdate(remote, _ => new AttemptWindow(now, 1), (_, old) =>
        now - old.StartedUtc > TimeSpan.FromMinutes(5) ? new AttemptWindow(now, 1) : old with { Count = old.Count + 1 });
    return window.Count <= 8;
}

static async Task<Account?> GetAuthorizedAccount(HttpContext context, ConcurrentDictionary<string, LoginSession> sessions,
    JsonStore store, bool adminOnly)
{
    string header = context.Request.Headers.Authorization.ToString();
    if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
    string hash = Hash(header[7..].Trim());
    if (!sessions.TryGetValue(hash, out var session) || session.ExpiresUtc <= DateTimeOffset.UtcNow)
    { sessions.TryRemove(hash, out _); return null; }
    return await store.Read(state => state.Accounts.FirstOrDefault(a =>
        a.Username.Equals(session.Username, StringComparison.OrdinalIgnoreCase)
        && IsLicenseActive(a) && (!adminOnly || a.IsAdmin)));
}

sealed record AttemptWindow(DateTimeOffset StartedUtc, int Count);
sealed record LoginSession(string Username, DateTimeOffset ExpiresUtc);
sealed record SetupRequest(string? SetupKey, string? Username, string? Password);
sealed record LoginRequest(string? Username, string? Password);
sealed record RegisterRequest(string? Username, string? Password, string? LicenseKey);
sealed record DeviceRequest(string? DeviceId);
sealed record CreateLicenseKeyRequest(string DurationCode);
sealed record LicenseRequest(bool? Enabled, DateTimeOffset? ExpiresUtc);
sealed record PasswordRequest(string? Password);
sealed record RoleRequest(bool? IsAdmin);
sealed record ReleaseInfo(string Version, string FileName, string Sha256, DateTimeOffset UpdatedUtc);

sealed class Account
{
    public string Username { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public bool IsAdmin { get; set; }
    public bool IsOwner { get; set; }
    public bool Enabled { get; set; }
    public DateTimeOffset? ExpiresUtc { get; set; }
    public DateTimeOffset CreatedUtc { get; set; }
    public string? DeviceId { get; set; }
    public string? LastDeviceId { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
}

sealed class LicenseState
{
    public List<Account> Accounts { get; set; } = [];
    public List<LicenseKey> LicenseKeys { get; set; } = [];
    public ReleaseInfo? Release { get; set; }
}

sealed class LicenseKey
{
    public string Id { get; set; } = "";
    public string KeyHash { get; set; } = "";
    public string DurationCode { get; set; } = "month_1";
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? RedeemedUtc { get; set; }
    public string? RedeemedBy { get; set; }
}

sealed class JsonStore(string filePath)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };

    public async Task<T> Read<T>(Func<LicenseState, T> read)
    {
        await gate.WaitAsync();
        try { return read(Load()); }
        finally { gate.Release(); }
    }

    public async Task<T> Mutate<T>(Func<LicenseState, T> mutate)
    {
        await gate.WaitAsync();
        try
        {
            var state = Load();
            T result = mutate(state);
            string temp = filePath + ".tmp";
            await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(state, JsonOptions));
            File.Move(temp, filePath, true);
            return result;
        }
        finally { gate.Release(); }
    }

    private LicenseState Load()
    {
        if (!File.Exists(filePath)) return new LicenseState();
        try { return JsonSerializer.Deserialize<LicenseState>(File.ReadAllText(filePath), JsonOptions) ?? throw new InvalidDataException("Lizenzdatenbank ist leer oder ungültig."); }
        catch (JsonException ex) { throw new InvalidDataException("Lizenzdatenbank kann nicht gelesen werden; Datei wurde nicht zurückgesetzt.", ex); }
    }
}

