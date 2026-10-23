# Emergency access PoC

Emergency support is disabled by default. This implementation belongs to the OIDC example. It shares no source, project, browser bundle, or implementation package with the SAML example. It uses public Fido2 4.1.0 and .NET 8. Identify keeps Safewhere.Fido2. The current key-protection baseline is Windows.

The [local setup record](README-emergency-setup-record.md) records the actual configuration steps, code correction, verification, and remaining browser actions for the dev520 deployment.

## Configure an isolated deployment

There are two different JSON formats. Identify reads its own external issuer settings file, which has top-level `Issuer`, `StorageDirectory`, and `Clients`. This OIDC application binds an `EmergencyCredential` section from ASP.NET Core configuration. Do not point Identify at this sample's `emergency-settings.example.json`.

The sample does **not** automatically load a file named `emergency-settings.json`. Copying that file outside the application is preparation only. Step 5 below shows how to apply its section to an IIS deployment.

### 1. Verify normal login and record the identifiers

Use a separate HTTPS host for each UserSystem. The RP ID is the exact host name, without a scheme, path, or port. Different ports on one host do not give separate RP IDs.

For example, this local deployment uses:

| Setting | Value |
|---|---|
| Identify tenant | `https://dev520.safewhere.local` |
| Identify Runtime API base | `https://dev520.safewhere.local/runtime/` |
| Normal OIDC issuer | `https://dev520.safewhere.local/runtime/oauth2` |
| Emergency issuer | `https://dev520.safewhere.local/runtime/emergency` |
| UserSystem origin | `https://kombitoidc.safewhere.local` |
| UserSystem RP ID | `kombitoidc.safewhere.local` |
| Sample deployment | `C:\inetpub\wwwroot\kombitoidc` |
| Emergency audience | `urn:emergency:oidc-example` |

Read the normal client ID and issuer from the deployed application's `OpenIdConnectOptions`. Get the protocol connection GUID from that connection in Identify Admin. The GUID and the OIDC client ID are different values. Verify the normal issuer against the tenant's OIDC discovery document. Normal login must already work.

### 2. Create the encryption key once

Run the key tool with PowerShell 7.2 or later. Use a **new absolute local directory outside all repositories and web roots**. Include the actual application-pool identity:

```powershell
./New-EmergencyKey.ps1 -OutputDirectory C:\ProgramData\SafewhereSamples\OidcEmergency -Audience urn:emergency:oidc-example -ApplicationIdentity 'IIS APPPOOL\kombitoidc.safewhere.local'
```

The tool restricts the directory ACL and creates `decryption-key.bin` and `encryption-public.jwk.json`. If these already exist, continue with them; do not regenerate the key. Keep the same audience: it is part of the DPAPI protection purpose. The script does not enable the feature or create TLS credentials.

### 3. Configure Identify's issuer

Create a separate external directory for Identify, for example `C:\ProgramData\Safewhere\EmergencyIssuer\dev520`. Give the Identify Runtime application-pool identity read access to its settings and modify access to a `state` subdirectory. Do not grant Identify access to the sample's private decryption key.

Use Identify's `docs/features/US39805/issuer-settings.example.json` as the template. Configure one OIDC client with these mappings:

| Identify field | Source |
|---|---|
| `Issuer` | Emergency issuer from step 1 |
| `StorageDirectory` | Identify's external `state` directory |
| `ClientId` | A unique emergency-client identifier, such as `oidc-example` |
| `NormalProtocol` | `oidc` |
| `NormalProtocolIdentifier` | The deployed sample's normal OIDC client ID |
| `ProtocolConnectionId` | The corresponding Identify connection GUID |
| `NormalLoginIssuer` | Normal issuer from step 1 |
| `EmergencyAudience` | Audience used by the key tool |
| `Origin`, `RelyingPartyId` | UserSystem origin and RP ID from step 1 |
| `EncryptionKeyId`, `EncryptionModulus`, `EncryptionExponent` | `kid`, `n`, and `e` from `encryption-public.jwk.json` |
| `ApiKeyEnvironmentVariable` | `OIDC_EMERGENCY_ISSUER_KEY` in the Identify Runtime process |
| `IssuanceEnabled` | `true` |
| `AllowedClaimTypes` | The approved types present in the normal ID token |
| `PreserveNormalClaims` | `true`, so every claim in the normal ID token is signed into the emergency credential |

Remove unused example clients. Every listed client is validated, even if its issuance switch is false. Each client needs a distinct encryption key, audience, RP ID, and backend secret.

Set these entries in Identify Runtime's effective `<appSettings>` configuration. Update an existing entry instead of adding a duplicate:

```xml
<add key="EmergencyIssuer.Enabled" value="true" />
<add key="EmergencyIssuer.SettingsFile"
     value="C:\ProgramData\Safewhere\EmergencyIssuer\dev520\issuer-settings.json" />
```

For an installed tenant, this is the Runtime configuration under that tenant, not the source repository's Web.config. Check external configuration overrides. Identify supplies `TenantId` from its own tenant configuration.

### 4. Provision process secrets

Use a random backend secret of 32–512 characters. Short placeholders do not work, even when the environment variable exists. Generate the value from a cryptographic random-number generator, not a memorable password. The value must be the same in Identify and the sample. It is not the normal OIDC client secret.

The example variable name is `OIDC_EMERGENCY_ISSUER_KEY`; make it available to both application processes.

Use your secret store or IIS application-pool environment variables. An interactive PowerShell variable is not inherited by an already running IIS worker. A machine environment variable being present also does not prove that an existing worker has received it. Configure the intended pools and restart them. Keep secret values out of JSON templates, source control, command output, and browser code.

### 5. Apply the sample settings

Copy [emergency-settings.example.json](emergency-settings.example.json) outside the repository. Replace every placeholder. `IssuerBaseUrl` is the Runtime API base and must end in `/`. `Issuer` is the exact EC issuer, while `NormalIssuer` is the normal OIDC issuer. Set the origin without a trailing slash. Use the `kid` from the generated public JWK as `EncryptionKeyId`.

Keep these sample paths under the restricted directory created in step 2:

```text
StorageDirectory:       C:\ProgramData\SafewhereSamples\OidcEmergency\state
ProtectionKeysDirectory: C:\ProgramData\SafewhereSamples\OidcEmergency\protection
EncryptionPrivateKeyFile: C:\ProgramData\SafewhereSamples\OidcEmergency\decryption-key.bin
TrustedSigningKeysFile: C:\ProgramData\SafewhereSamples\OidcEmergency\issuer-signing-keys.json
```

For IIS, merge the external file's `EmergencyCredential` object into the **deployed** `appsettings.json`, preserving every other section. For example, run this in an elevated PowerShell session after selecting your paths:

```powershell
$externalSettings = 'C:\ProgramData\SafewhereSamples\OidcEmergency\dev520\emergency-settings.json'
$deployedSettings = 'C:\inetpub\wwwroot\kombitoidc\appsettings.json'
$backupDirectory = 'C:\ProgramData\SafewhereSamples\OidcEmergency\backups'
New-Item -ItemType Directory -Force -Path $backupDirectory | Out-Null
Copy-Item -LiteralPath $deployedSettings -Destination (Join-Path $backupDirectory ('appsettings-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json'))
$external = Get-Content -LiteralPath $externalSettings -Raw | ConvertFrom-Json
$deployed = Get-Content -LiteralPath $deployedSettings -Raw | ConvertFrom-Json
$external.EmergencyCredential.Enabled = $false
$deployed | Add-Member -MemberType NoteProperty -Name EmergencyCredential -Value $external.EmergencyCredential -Force
[IO.File]::WriteAllText($deployedSettings, ($deployed | ConvertTo-Json -Depth 32), [Text.UTF8Encoding]::new($false))
```

This initially keeps support disabled. Do not print the whole deployed JSON: other sections may contain normal-login secrets. Keep the backup outside the web root and repository. Check `appsettings.Production.json`, IIS environment variables, and other configured providers for overrides. Preserve the emergency section in future deployments.

For local Development only, the alternative is user secrets:

```powershell
Get-Content -Raw <external-settings-file> | dotnet user-secrets set --project WebAppNetCore.csproj
```

User secrets configured for your interactive account are not a substitute for configuration of a deployed IIS application.

### 6. Restart Identify and establish signing-key trust

Stop the Identify Runtime pool, wait for its old worker to exit, and start it. Do not replace this with an overlapping recycle when the issuer owns its state file.

Download the emergency public signing keys over certificate-validated HTTPS to the sample's configured `TrustedSigningKeysFile`:

```powershell
Invoke-WebRequest -Uri 'https://dev520.safewhere.local/runtime/emergency/signing-keys' `
    -OutFile 'C:\ProgramData\SafewhereSamples\OidcEmergency\issuer-signing-keys.json'
```

The response must be HTTP 200 with a `keys` array containing the emergency signing key. This is a different key from both the sample's RSA encryption key and Identify's normal OIDC signing keys. A 503 response means issuer configuration or state is unavailable; check the Runtime Error log. Do not save an error response as the trust file or bypass certificate validation. The emergency HTTP client does not use the normal demo's debug certificate-validation bypass.

### 7. Enable sample support

After the issuer, trust file, directory permissions, and process secrets are ready, set the deployed `EmergencyCredential.Enabled` value to `true`. Stop and start the sample pool. Keep `state` and `protection` persistent and run one worker process for this PoC.

Open `/emergency/login` to check the local setup. Emergency login is available as soon as support is enabled; there is no separate acceptance switch. A browser can log in once it has completed preparation. Log out and perform a fresh normal login after enabling the issuer: old login sessions have no newly captured preparation record.

Private JWE keys use machine-bound DPAPI with an audience-specific purpose. The emergency Data Protection key ring also uses DPAPI on Windows. Retain the key, state, and protection directories and their ACLs. Copying them to another machine is not a supported recovery procedure. No secret or private key belongs in source control.

### Troubleshooting

| Symptom | Check |
|---|---|
| Normal login works, emergency feature is unavailable | Normal login has separate configuration. Confirm the full `EmergencyCredential` section is loaded, not only `Enabled`. |
| Identify returns `503 issuer_unavailable` | Check `EmergencyIssuer.SettingsFile`, the top-level Identify JSON format, all client placeholders, process secret availability, storage permissions, and the Runtime Error log. |
| Sample returns `503 emergency_unavailable` | Check required options, DPAPI audience/machine, key and trust files, directory permissions, and process secrets. Restart after correcting initialization failures. |
| Enrollment needs a new login | Perform a new normal login after issuer setup. Its ID token must contain `iss`, `sub`, `jti`, and `iat`; the record expires after ten minutes. |
| No eligible security key | Use an authenticator with user verification and without backup eligibility. A synced passkey can be rejected by this PoC policy. |
| Client configuration changed after state was created | Follow Identify's documented client-recovery procedure. Do not delete state files to force a settings change. |

## Use the feature

- After normal login, open **Prepare emergency access**. The accepted ID token needs `iss`, `sub`, `jti`, and `iat`. Preparation evidence lasts ten minutes. Userinfo-only claims do not become emergency authorization.
- Choose **Prepare this browser**. Finish registration, IndexedDB storage/read-back, and the separate possession check. Readiness requires all three. Use a key with user verification and without passkey backup.
- During an outage, use `/emergency/login`. A prepared browser can log in immediately; no operator approval is needed. Emergency sessions end within eight hours and before EC expiry. Login, home, and local logout use no Identify request, OP iframe, or normal token operation.
- Preparation and renewal synchronize issuer state and signing trust while online. A changed issuer `state_id` blocks old credentials and sessions and requires new preparation. Failed trust refresh remains blocked across restart. Offline login does not perform this synchronization.
- Renew after a newer normal login. The old EC stays active until its replacement is stored and confirmed. Pending entries can be confirmed later. Failed delivery can leave an issuer binding that needs recovery.
- Remove keys locally first. Failed issuer reports remain queued. The next preparation or renewal refreshes trust, applies revocations, and retries removals. There is no automatic network polling in the emergency flow.
- Removing a key, or an issuer revocation applied during synchronization, also ends current sessions for that key.

To disable support, set only `EmergencyCredential.Enabled=false` and restart while retaining the external storage-path configuration. Startup marks existing state so that current emergency sessions end, without loading private keys. Removing the path configuration is not the supported disable procedure.

## Build and check

From `src/CSharp/WebAppNetCore`:

```powershell
dotnet build ./WebAppNetCore/WebAppNetCore.csproj --disable-build-servers /m:1 /p:UseSharedCompilation=false /p:UseRazorBuildServer=false
dotnet test ./WebAppNetCore.Emergency.Tests/WebAppNetCore.Emergency.Tests.csproj --disable-build-servers /m:1 /p:UseSharedCompilation=false /p:UseRazorBuildServer=false
dotnet build-server shutdown
```

The current emergency suite passes 57 tests, including issuer-state changes, legacy state recovery, failed trust refresh across restart, and concurrent trust-refresh races. Tests generate disposable keys outside the repository. They cover credential profiles, both WebAuthn algorithms, replay/counters, lifecycle state, expiry, renewal, offline removal, restart, HTTP guards, and OIDC callback isolation. Browser checks used the actual app at a virtual base path and a virtual authenticator. Preparation used synthetic accepted-login evidence with credentials issued by the actual Identify implementation. This is not a completed normal federation run against a configured Identify tenant.

## PoC limits

This is one process with bounded local state. Protection does not prevent a trusted host administrator from restoring old state. There is no trusted hardware-attestation policy, multi-node coordination, automated encryption-key rotation, or rollback-proof recovery. Issuer-state recovery blocks previous credentials and requires new preparation. Offline authorization can be stale. Browser data deletion loses preparation.

Every claim from the normal ID token is kept, including all roles. Normal assurance, tokens, session IDs, and reserved markers are excluded. The OIDC example grants no basic privilege XML. Existing normal-demo token diagnostics remain outside emergency behavior. Real normal SSO/logout, physical authenticators, other deployment combinations, and production dependency review still need evidence.

## PoC: inspect Identify endpoint results

Expand **Identify endpoint results (PoC)** on any emergency page. Perform preparation, renewal, or key removal to see the backend calls made by that action. Each entry shows the HTTP method, endpoint template, HTTP status, elapsed milliseconds, and a redacted result summary. Network failures and rejected response bodies are distinguished from HTTP failures. A successful issuer response is not proof that local credential validation or preparation completed.

Local operations such as authenticator possession checks, emergency login, and local logout show **no Identify endpoint called** when their backend request makes no issuer call. Viewing the panel never contacts Identify or repeats an operation.

The panel keeps the latest 40 entries in this tab's session storage, including across redirects to the emergency home page. Each action includes at most its latest 8 issuer calls (synchronization may paginate). **Clear displayed history** removes only this display history; it does not remove credentials or revoke keys. If session storage is unavailable, the panel works until navigation. Existing calls from before this version was loaded are not reconstructed.

Results contain no request/response bodies, API keys, token references, emergency credential values, enrollment IDs, binding IDs, subjects, or personal claims. HTTP statuses and fixed summaries are returned only on the originating request via the bounded `X-Emergency-Issuer-Calls` response header. This is a demonstration aid, not a durable audit log.

## Claims from normal login

The emergency session gets the claims from the normal login's ID token. Identify captures the claims it issued in the normal OIDC ID token and signs them into the emergency credential's `claims_snapshot`; set `PreserveNormalClaims: true` on the matching Identify issuer client so that all of them are included. The browser never supplies a claims list. The sample has no claim-type or role allowlist: it projects every snapshot claim into the emergency principal, preserving claim types, values, value types, and repeated claims. It does not fetch current claims during offline login.

Token metadata, raw tokens, and emergency-reserved claims are still excluded, as are normal assurance claims such as `acr`, `amr`, `auth_time`, and LoA claims. `emergency=true`, `local_assurance=emergency-possession`, and local session expiry remain authoritative. A `name` or standard name claim replaces the generic Prepared user display. Original claim names are preserved rather than automatically applying OIDC inbound claim-name mapping.

Claims are fixed when the credential is issued. Role or attribute changes after preparation are not reflected until renewal. Attributes that were never present in the ID token cannot be invented. Access-token and UserInfo claims are not used.
