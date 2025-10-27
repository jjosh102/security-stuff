
using System.Text.Json;
using Fido2NetLib;
using Fido2NetLib.Objects;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddFido2(o =>
{
    o.ServerDomain = "localhost";
    o.ServerName = "LocalPasskeyServer";
    o.Origins = new HashSet<string> { "https://localhost:5001" };
});
builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

var app = builder.Build();
app.UseCors();
app.UseHttpsRedirection();
app.UseStaticFiles();

var fido2 = app.Services.GetRequiredService<IFido2>();

var users = new Dictionary<string, Fido2User>();
var credentials = new Dictionary<string, List<StoredCredential>>();
var registerChallenges = new Dictionary<string, CredentialCreateOptions>();
var assertChallenges = new Dictionary<string, AssertionOptions>();

// ========== REGISTRATION ==========

// 1. Generate registration options
app.MapPost("/register/options", async (HttpContext ctx) =>
{
    var req = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(ctx.Request.Body);
    var username = req?["username"] ?? "user";

    if (!users.ContainsKey(username))
    {
        users[username] = new Fido2User
        {
            Id = Guid.NewGuid().ToByteArray(),
            Name = username,
            DisplayName = username
        };
    }

    var excludeCreds = credentials.GetValueOrDefault(username, new())
        .Select(c => c.Descriptor)
        .ToList();

    var options = fido2.RequestNewCredential(new RequestNewCredentialParams
    {
        User = users[username],
        AttestationPreference = AttestationConveyancePreference.None,
        AuthenticatorSelection = new AuthenticatorSelection
        {
            ResidentKey = ResidentKeyRequirement.Preferred,
            UserVerification = UserVerificationRequirement.Preferred
        },
        ExcludeCredentials = excludeCreds
    });

    registerChallenges[username] = options;
    return Results.Json(options);
});

// 2. Verify registration (attestation) result
app.MapPost("/register/verify", async (HttpContext ctx) =>
{
    var reqJson = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
    var attResp = JsonSerializer.Deserialize<AuthenticatorAttestationRawResponse>(reqJson);

    var username = reqJson.TryGetProperty("username", out var nameProp)
        ? nameProp.GetString() ?? "user"
        : "user";

    if (!registerChallenges.TryGetValue(username, out var origOptions))
        return Results.BadRequest("Missing registration challenge");

    registerChallenges.Remove(username);

    var res = await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
    {
        AttestationResponse = attResp!,
        OriginalOptions = origOptions,
        IsCredentialIdUniqueToUserCallback = async (args, _) =>
        {
            return !credentials.Values.SelectMany(c => c)
                .Any(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
        }
    });

    if (!credentials.ContainsKey(username))
        credentials[username] =[];

    credentials[username].Add(new StoredCredential
    {
        Descriptor = new PublicKeyCredentialDescriptor(res.Id),
        PublicKey = res.PublicKey,
        SignatureCounter = res.SignCount,
        UserHandle = users[username].Id
    });

    return Results.Json(new
    {
        Status = "ok",
        CredentialId = Convert.ToBase64String(res.Id)
    });
});


// ========== AUTHENTICATION (ASSERTION) ==========

// 1. Generate assertion options
app.MapPost("/assertion/options", async (HttpContext ctx) =>
{
    var req = await JsonSerializer.DeserializeAsync<Dictionary<string, string>>(ctx.Request.Body);
    var username = req?["username"];

    var allowedCreds = new List<PublicKeyCredentialDescriptor>();
    if (username != null && credentials.TryGetValue(username, out var userCreds))
        allowedCreds = userCreds.Select(c => c.Descriptor).ToList();

    var options = fido2.GetAssertionOptions(new GetAssertionOptionsParams
    {
        UserVerification = UserVerificationRequirement.Preferred,
        AllowedCredentials = allowedCreds
    });

    assertChallenges[username ?? "anonymous"] = options;
    return Results.Json(options);
});

// 2. Verify assertion (login)
app.MapPost("/assertion/verify", async (HttpContext ctx) =>
{
    var reqJson = await JsonSerializer.DeserializeAsync<JsonElement>(ctx.Request.Body);
    var clientResponse = JsonSerializer.Deserialize<AuthenticatorAssertionRawResponse>(reqJson);

    if (clientResponse == null)
        return Results.BadRequest("Invalid client response");

    var username = reqJson.TryGetProperty("username", out var nameProp)
        ? nameProp.GetString() ?? "anonymous"
        : "anonymous";

    if (!assertChallenges.TryGetValue(username, out var assertionOptions))
        return Results.BadRequest("Missing or expired challenge");

    assertChallenges.Remove(username);

    // Find the stored credential
    var cred = credentials.Values
        .SelectMany(v => v)
        .FirstOrDefault(c => c.Descriptor.Id.SequenceEqual(clientResponse.RawId));

    if (cred == null)
        return Results.BadRequest("Unknown credential");

    // Verify user handle owns credential
    IsUserHandleOwnerOfCredentialIdAsync ownershipCheck = async (args, cancellationToken) =>
    {
        var storedCreds = credentials.Values.SelectMany(v => v)
            .Where(c => c.UserHandle.SequenceEqual(args.UserHandle))
            .ToList();

        return storedCreds.Any(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
    };

    // Verify assertion
    var result = await fido2.MakeAssertionAsync(new MakeAssertionParams
    {
        AssertionResponse = clientResponse!,
        OriginalOptions = assertionOptions,
        StoredPublicKey = cred.PublicKey,
        StoredSignatureCounter = cred.SignatureCounter,
        IsUserHandleOwnerOfCredentialIdCallback = ownershipCheck
    });


    cred.SignatureCounter = result.SignCount;

    return Results.Json(new
    {
        Status = "ok",
        Username = username,
        Counter = result.SignCount,
        Verified = true
    });
});

app.Run("https://localhost:5001");


record StoredCredential
{
    public PublicKeyCredentialDescriptor Descriptor { get; init; } = default!;
    public byte[] PublicKey { get; init; } = default!;
    public uint SignatureCounter { get; set; }
    public byte[] UserHandle { get; init; } = default!;
}
