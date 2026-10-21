using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class NormalAccessTokenSnapshotTests
    {
        private const string Issuer = "https://issuer.example.invalid";
        internal static (string Access, JwtSecurityToken Id, SecurityKey Key) Tokens(string mutation = "valid", string expectedIssuer = Issuer)
        {
            using var rsa = RSA.Create(2048);
            var key = new RsaSecurityKey(rsa.ExportParameters(true));
            var handler = new JwtSecurityTokenHandler(); handler.OutboundClaimTypeMap.Clear();
            var claims = new List<Claim>
            {
                new Claim("sub", mutation == "subject" ? "other-user" : "user"),
                new Claim("client_id", mutation == "client" ? "other-client" : "client"),
                new Claim("name", "Snapshot User"), new Claim("department", "A"), new Claim("department", "B"),
                new Claim("level", "7", ClaimValueTypes.Integer), new Claim("role", "read-only"), new Claim("ROLE", "administrator"),
                new Claim("acr", "normal"), new Claim("scope", "api-admin"), new Claim("cnf", "binding"),
                new Claim("access_token", "must-not-persist"), new Claim(ClaimTypes.AuthenticationMethod, "normal-method")
            };
            if (mutation == "missing-client") claims.RemoveAll(c => c.Type == "client_id");
            if (mutation == "presenter") claims.Add(new Claim("azp", "another-client"));
            var now = DateTime.UtcNow;
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims), Issuer = mutation == "issuer" ? "https://other.invalid" : expectedIssuer,
                Audience = "urn:received-resource", IssuedAt = now.AddMinutes(-2),
                NotBefore = mutation == "future" ? now.AddMinutes(3) : now.AddMinutes(-2),
                Expires = mutation == "expired" ? now.AddMinutes(-1) : now.AddMinutes(5),
                SigningCredentials = mutation == "unsigned" ? null : new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
                TokenType = mutation == "type" ? "unexpected" : "at+jwt"
            };
            string access = handler.CreateEncodedJwt(descriptor);
            var hash = SHA256.HashData(Encoding.ASCII.GetBytes(access));
            var id = new JwtSecurityToken(new JwtHeader(new SigningCredentials(key, SecurityAlgorithms.RsaSha256)),
                new JwtPayload(expectedIssuer, "client", new[] { new Claim("sub", "user"), new Claim("jti", "id-reference"), new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64), new Claim("at_hash", mutation == "hash" ? "incorrect" : Base64UrlEncoder.Encode(hash.Take(hash.Length / 2).ToArray())) }, now.AddMinutes(-1), now.AddMinutes(5)));
            if (mutation == "signature") { using var other = RSA.Create(2048); key = new RsaSecurityKey(other.ExportParameters(false)); }
            return (access, id, key);
        }
        [DataTestMethod]
        [DataRow("issuer")][DataRow("subject")][DataRow("client")][DataRow("missing-client")][DataRow("presenter")]
        [DataRow("expired")][DataRow("future")][DataRow("unsigned")][DataRow("signature")][DataRow("hash")][DataRow("type")]
        public void InvalidAccessToken_IsRejected(string mutation)
        {
            var token = Tokens(mutation);
            Assert.Throws<Exception>(() => NormalAccessTokenSnapshot.Validate(token.Access, token.Id, Issuer, "client", new[] { token.Key }));
        }
        [TestMethod]
        public void ValidAccessToken_PreservesValuesAndExcludesProtocolEvidence()
        {
            var token = Tokens();
            var snapshot = NormalAccessTokenSnapshot.Validate(token.Access, token.Id, Issuer, "client", new[] { token.Key });
            CollectionAssert.AreEquivalent(new[] { "A", "B" }, snapshot.Claims.Where(c => c.Type == "department").Select(c => c.Value).ToArray());
            Assert.AreEqual(ClaimValueTypes.Integer32, snapshot.Claims.Single(c => c.Type == "level").ValueType);
            Assert.IsFalse(snapshot.Claims.Any(c => new[] { "scope", "cnf", "acr", "client_id", "sub", "access_token", ClaimTypes.AuthenticationMethod }.Contains(c.Type)));
        }

        [DataTestMethod]
        [DataRow(false)]
        [DataRow(true)]
        public async Task AcceptedTicket_OnlyPublishesValidatedBackchannelSnapshot(bool invalidAccess)
        {
            using var fixture = new ProtocolFixture(); fixture.Options.UseNormalAccessTokenClaims = true;
            using var host = HttpBoundaryTests.Host(fixture, true);
            using var scope = host.Services.CreateScope();
            var token = Tokens(invalidAccess ? "subject" : "valid", fixture.Options.NormalIssuer);
            var configuration = new OpenIdConnectConfiguration { Issuer = fixture.Options.NormalIssuer };
            configuration.SigningKeys.Add(token.Key);
            var options = new OpenIdConnectOptions { ClientId = "client", Configuration = configuration };
            var http = new DefaultHttpContext { RequestServices = scope.ServiceProvider };
            http.Request.Scheme = "https"; http.Request.Host = new HostString("oidc.fixture.invalid");
            var scheme = new AuthenticationScheme("OpenIdConnect", "OpenIdConnect", typeof(OpenIdConnectHandler));
            var principal = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("name", "Untrusted UserInfo name") }, "Cookies"));
            var context = new TokenValidatedContext(http, scheme, options, principal, new AuthenticationProperties())
            {
                SecurityToken = token.Id,
                TokenEndpointResponse = new OpenIdConnectMessage { AccessToken = token.Access }
            };
            // Same optional preparation boundary used by the normal OIDC event registration.
            try { await EmergencyOidcEvents.StageAsync(context); } catch (Exception) { }
            Assert.IsFalse(context.Properties.Items.ContainsKey("emergency_login"));
            await EmergencyOidcEvents.AcceptedAsync(new TicketReceivedContext(http, scheme, options,
                new AuthenticationTicket(principal, context.Properties, "Cookies")));
            Assert.AreEqual(!invalidAccess, context.Properties.Items.ContainsKey("emergency_login"));
            if (!invalidAccess) Assert.IsTrue(host.Services.GetRequiredService<EmergencyRuntime>().Service.HasLogin(context.Properties.Items["emergency_login"], EmergencyBrowser.Read(http)));
        }

        [TestMethod]
        public async Task LocalSnapshot_SurvivesRestartAndRefreshesOnlyOnRenewal()
        {
            using var fixture = new ProtocolFixture();
            fixture.Options.UseNormalAccessTokenClaims = true; fixture.Options.PreserveNormalClaims = true;
            fixture.OmitIssuerClaims = true;
            var token = Tokens();
            fixture.NormalClaims = NormalAccessTokenSnapshot.Validate(token.Access, token.Id, Issuer, "client", new[] { token.Key }).Claims;
            var active = await fixture.Active();
            fixture.NormalClaims.Single(c => c.Type == "name").Value = "Changed Later";
            fixture.Service.Acceptance(fixture.Service.OperatorSignIn(fixture.OperatorSecret), true, 60);
            int requests = fixture.Requests; fixture.Offline = true; fixture.Restart();
            var session = await fixture.Prove(active, "login", null, 2);
            var principal = fixture.Service.Session(session.Id, fixture.Browser);
            Assert.AreEqual("Snapshot User", principal.Identity.Name);
            Assert.IsTrue(principal.IsInRole("read-only")); Assert.IsFalse(principal.IsInRole("administrator"));
            Assert.AreEqual(2, principal.FindAll("department").Count()); Assert.AreEqual(requests, fixture.Requests);
            fixture.Offline = false; fixture.Clock.Value = fixture.Clock.Value.AddSeconds(1);
            string login = fixture.Login();
            var renewed = await fixture.Service.RenewAsync(login, fixture.Browser, active.GetProperty("binding_id").GetString(), CancellationToken.None);
            await fixture.Prove(renewed, "activate", login, 3);
            var renewedSession = await fixture.Prove(renewed, "login", null, 4);
            Assert.AreEqual("Changed Later", fixture.Service.Session(renewedSession.Id, fixture.Browser).Identity.Name);
        }
        [TestMethod]
        public async Task LocalSnapshot_RequiresRenewalForLegacyCredentialsAndRejectsWrongSubject()
        {
            using var fixture = new ProtocolFixture(); var old = await fixture.Active();
            fixture.Options.UseNormalAccessTokenClaims = true;
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Login());
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, old.GetProperty("emergency_credential").GetString(), "login", null));
            fixture.NormalClaims = new List<SnapshotClaim> { new SnapshotClaim { Type = "name", Value = "Another user", ValueType = ClaimValueTypes.String } };
            string otherLogin = fixture.Login("another-subject");
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Pending(otherLogin));
        }
    }
}
