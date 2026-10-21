using System;
using System.IdentityModel.Tokens.Jwt;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;

namespace WebAppNetCore.EmergencyCredential
{
    public static class EmergencyOidcEvents
    {
        private const string Staged = "oidc-emergency-validated";
        public static async Task StageAsync(TokenValidatedContext context)
        {
            EmergencyRuntime runtime = context.HttpContext.RequestServices.GetRequiredService<EmergencyRuntime>();
            if (!runtime.Options.Enabled) { return; }
            context.HttpContext.Items.Remove(Staged);
            string issuer, subject, id;
            long expires;
            JwtSecurityToken jwt = context.SecurityToken;
            if (jwt == null) { return; }
            issuer = jwt.Issuer; subject = jwt.Subject; id = jwt.Id;
            expires = Math.Min(new DateTimeOffset(jwt.ValidTo, TimeSpan.Zero).ToUnixTimeSeconds(), new DateTimeOffset(jwt.IssuedAt, TimeSpan.Zero).ToUnixTimeSeconds() + 600);
            NormalAccessTokenSnapshot snapshot = null;
            if (runtime.Options.UseNormalAccessTokenClaims)
            {
                // Never accept an access token supplied by a preparation API/browser request.
                string access = context.TokenEndpointResponse?.AccessToken;
                if (string.IsNullOrEmpty(access)) { return; }
                var configuration = context.Options.Configuration;
                if (configuration == null && context.Options.ConfigurationManager != null)
                    configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);
                if (configuration == null || configuration.Issuer != runtime.Options.NormalIssuer) { return; }
                try { snapshot = NormalAccessTokenSnapshot.Validate(access, jwt, runtime.Options.NormalIssuer, context.Options.ClientId, configuration.SigningKeys); }
                catch (Microsoft.IdentityModel.Tokens.SecurityTokenSignatureKeyNotFoundException) when (context.Options.ConfigurationManager != null)
                {
                    context.Options.ConfigurationManager.RequestRefresh();
                    configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);
                    if (configuration.Issuer != runtime.Options.NormalIssuer) { return; }
                    snapshot = NormalAccessTokenSnapshot.Validate(access, jwt, runtime.Options.NormalIssuer, context.Options.ClientId, configuration.SigningKeys);
                }
                expires = Math.Min(expires, snapshot.Expires);
            }
            context.HttpContext.Items[Staged] = new AcceptedLogin { Issuer = issuer, Subject = subject, TokenReference = id, Expires = expires, NormalAccessTokenClaims = snapshot?.Claims };
        }
        public static async Task AcceptedAsync(TicketReceivedContext context)
        {
            string sid = context.Principal.FindFirst("sid")?.Value;
            if (!string.IsNullOrEmpty(sid)) { OpenIdConnectHelper.LiveSessions[sid] = true; }
            EmergencyRuntime runtime = context.HttpContext.RequestServices.GetRequiredService<EmergencyRuntime>();
            if (!runtime.Options.Enabled) { return; }
            try
            {
                AuthenticateResult previous = await context.HttpContext.AuthenticateAsync(EmergencyExtensions.CookieScheme);
                if (previous.Succeeded) { runtime.Service.SignOut(previous.Principal.FindFirst("emergency_session_id")?.Value); }
                string browser = EmergencyBrowser.Ensure(context.HttpContext, true);
                context.Properties.Items.Remove("emergency_login");
                if (context.HttpContext.Items.TryGetValue(Staged, out object staged) && staged is AcceptedLogin login)
                {
                    context.Properties.Items["emergency_login"] = runtime.Service.Capture(browser, login.Subject, login.Issuer, login.TokenReference, login.Expires, login.NormalAccessTokenClaims);
                }
            }
            catch (Exception)
            {
                // Optional preparation failure must not interrupt an accepted normal login.
                context.Properties.Items.Remove("emergency_login");
            }
            finally
            {
                try { await context.HttpContext.SignOutAsync(EmergencyExtensions.CookieScheme); } catch (Exception) { }
            }
        }
    }
}
