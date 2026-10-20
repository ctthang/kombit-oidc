# Local emergency-access setup record

Date: 20 October 2026. This records the setup performed for the local OIDC example and Identify tenant. For reusable instructions, see [README-emergency.md](README-emergency.md).

## Deployment and identifiers

| Item | Value |
|---|---|
| Identify tenant | `https://dev520.safewhere.local` |
| Identify Runtime | `C:\Program Files\Safewhere\Identify\Tenants\dev520\runtime` |
| Identify pool | `Identify dev520` |
| OIDC application | `https://kombitoidc.safewhere.local` |
| OIDC deployment | `C:\inetpub\wwwroot\kombitoidc` |
| OIDC pool | `kombitoidc.safewhere.local` |
| Normal issuer | `https://dev520.safewhere.local/runtime/oauth2` |
| Emergency issuer | `https://dev520.safewhere.local/runtime/emergency` |
| Issuer API base | `https://dev520.safewhere.local/runtime/` |
| Emergency audience | `urn:emergency:oidc-example` |
| Protocol connection GUID | `01be44ed-814f-4db9-a3a6-8b1f28b3d6a5` |

The normal OIDC client ID was read from the deployed `OpenIdConnectOptions.ClientId`. The user supplied the connection GUID. Identify uses that GUID to match normal-token capture to the configured protocol connection; it is distinct from the OIDC client ID.

## Initial findings

Normal login was already working, as confirmed by the user. The OIDC discovery document returned HTTP 200 with the expected normal issuer.

The encryption-key tool had already created `decryption-key.bin` and `encryption-public.jwk.json` under `C:\ProgramData\SafewhereSamples\OidcEmergency`. The directory already allowed the OIDC application-pool identity to modify its contents. These keys were reused.

Three configuration gaps prevented emergency setup:

1. The deployed sample had only `EmergencyCredential.Enabled=true`. Its complete settings existed in an external JSON file, but this application does not automatically load that file.
2. Identify had `EmergencyIssuer.Enabled=true` but no `EmergencyIssuer.SettingsFile`. Its public emergency signing-key endpoint returned HTTP 503.
3. Both existing machine environment variables for the backend and operator secrets were shorter than 32 characters. The application requires 32–512 characters.

The sample also needed compatibility with Identify's new `state_id` field. That code correction was completed before deployment.

## Code correction and verification

The sample now persists the issuer state ID. Online preparation, renewal, and operator synchronization check that identity. A changed ID, or legacy state without an ID, blocks old credentials and sessions, disables acceptance, clears pending login/enrollment/possession evidence, and resets the revocation cursor. Old queued removals are discarded because the new issuer state cannot identify those bindings.

Signing-key refresh is bracketed by matching state-ID observations. Synchronizations are serialized, and generation checks reject stale credential responses. If recovery interrupts trust refresh, the blocked state and pending-refresh marker survive restart. Acceptance cannot be enabled until a stable refresh succeeds. Retained revocation events may have sequence gaps, but duplicate or decreasing sequences are rejected. Offline login does not call Identify.

The baseline emergency suite passed 49 tests. The updated suite passed all 57 tests, including reset, legacy migration, retention, missing-ID rejection, concurrent refresh, and refresh failure across restart. An independent AI source review found a trust-refresh race during development; it was corrected and the final review reported no remaining blockers. This is source review and local test evidence, not human approval or production certification.

Commands used from the solution directory:

```powershell
dotnet test ./WebAppNetCore.Emergency.Tests/WebAppNetCore.Emergency.Tests.csproj --disable-build-servers /m:1 /p:UseSharedCompilation=false /p:UseRazorBuildServer=false
$publishDirectory = Join-Path $env:TEMP 'codex-oidc-emergency-setup\publish'
dotnet publish ./WebAppNetCore/WebAppNetCore.csproj -c Release --no-restore --disable-build-servers /m:1 /p:UseSharedCompilation=false /p:UseRazorBuildServer=false -o $publishDirectory
dotnet build-server shutdown
```

The Release publish succeeded. Existing compiler warnings remained visible. The deployed `WebAppNetCore.dll` was checked against the publish output and its SHA-256 hash matched.

## Configuration applied

1. Located the two IIS application pools by their deployment paths. The non-elevated session could not manage IIS, so the reviewed setup script ran through an Administrator PowerShell process.
2. Verified that the existing protected private key could be opened on this machine with the configured audience. The private key was not regenerated or printed.
3. Created a separate Identify configuration directory. Granted the resolved Runtime pool identity read access there and modify access to its `state` subdirectory. Identify was not granted access to the sample's private decryption key.
4. Backed up the original Runtime Web.config, sample appsettings, and sample DLL/PDB. The script also supports backing up existing issuer settings and signing trust before replacement.
5. Stopped both pools and waited for their old workers to exit. This avoided overlapping owners of the protected state files.
6. With the user's explicit approval, replaced the two invalid machine secrets with distinct cryptographically random values. Set the backend variable on both pools and the operator variable only on the sample pool. The variables have machine scope; the operator value was explicitly injected only into the sample pool. Secret values were not printed or committed.
7. Wrote Identify's issuer JSON using the supplied connection GUID, the deployed normal client ID, and the existing public JWK's `kid`, `n`, and `e`. Set `EmergencyIssuer.SettingsFile` in the deployed Runtime configuration.
8. Started Identify and downloaded its emergency public signing keys over certificate-validated HTTPS. Checked the response before saving it as the sample's signing trust. No certificate-validation bypass was used.
9. Copied the verified sample DLL/PDB into the stopped deployment. Merged only the complete `EmergencyCredential` section into deployed appsettings, preserving normal-login settings.
10. Wrote the supported `support-disabled` marker before starting the sample. This ensures that any prior acceptance state is reset. Started the sample and checked the operator page.

The script keeps rollback copies and restores changed configuration, binaries, trust, and environment values if applying the changes fails. If rollback itself fails, it leaves the affected pools stopped. Existing state files are never deleted as a configuration shortcut.

## Resulting files and secrets

| Purpose | Location or variable |
|---|---|
| Identify settings | `C:\ProgramData\Safewhere\EmergencyIssuer\dev520\issuer-settings.json` |
| Identify state | `C:\ProgramData\Safewhere\EmergencyIssuer\dev520\state` |
| Sample external settings source | `C:\ProgramData\SafewhereSamples\OidcEmergency\dev520\emergency-settings.json` |
| Sample effective settings | `C:\inetpub\wwwroot\kombitoidc\appsettings.json`, section `EmergencyCredential` |
| Sample private encryption key | `C:\ProgramData\SafewhereSamples\OidcEmergency\decryption-key.bin` |
| Sample public encryption JWK | `C:\ProgramData\SafewhereSamples\OidcEmergency\encryption-public.jwk.json` |
| Sample trusted issuer signing keys | `C:\ProgramData\SafewhereSamples\OidcEmergency\issuer-signing-keys.json` |
| Sample state and protection keys | `C:\ProgramData\SafewhereSamples\OidcEmergency\state` and `protection` |
| Shared backend secret | `OIDC_EMERGENCY_ISSUER_KEY` |
| Operator secret used by the sample | `OIDC_EMERGENCY_OPERATOR_KEY` |

Backups from this setup are under `C:\ProgramData\Safewhere\EmergencyIssuer\dev520\backups\20261020-161208` and `C:\ProgramData\SafewhereSamples\OidcEmergency\backups\20261020-161208`. They are deployment artifacts and must remain outside source control.

Local execution evidence and the reviewed setup script are under `%TEMP%\codex-oidc-emergency-setup`, including `setup-result.json`, test logs/TRX files, publish output, and `Complete-OidcEmergencySetup.ps1`. The script is specific to this local deployment; the README provides the reusable procedure. The successful result recorded both pool names, file locations, generated variable names, and HTTP 200 from the operator page. It contains no secret values.

## Observed outcome and next steps

| Check | Result |
|---|---|
| Identify emergency signing keys | HTTP 200 |
| Normal OIDC discovery | HTTP 200 |
| Sample home page | HTTP 200 |
| Sample emergency operator page | HTTP 200 |
| Sample emergency login page | HTTP 403, expected while acceptance is off |
| Published/deployed assembly comparison | Hashes matched |

Server setup is complete, and emergency acceptance is off. A full browser preparation and physical-authenticator login were not performed by the setup script.

The user must sign out and perform a fresh normal login, open `/emergency`, and complete registration, browser storage/read-back, and possession confirmation. Then sign in at `/emergency/operator` with the new operator key and activate acceptance deliberately. The README includes the local clipboard command for that key. Preserve the deployed emergency configuration during future publishes; the source template remains disabled by default.