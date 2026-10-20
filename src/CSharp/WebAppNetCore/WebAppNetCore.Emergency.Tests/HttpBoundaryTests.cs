using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.Controllers;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class HttpBoundaryTests
    {
        internal static TestServer Host(ProtocolFixture fixture, bool enabled)
        {
            fixture.Service.Dispose(); fixture.Options.Enabled = enabled;
            var configuration = new ConfigurationBuilder().AddJsonStream(new MemoryStream(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { EmergencyCredential = fixture.Options })))).Build();
            string content = Path.Combine(fixture.Root, "application"); Directory.CreateDirectory(content);
            return new TestServer(new WebHostBuilder().UseContentRoot(content).ConfigureServices(services =>
            {
                services.AddSingleton<IConfiguration>(configuration);
                services.AddMvc(options => options.EnableEndpointRouting = false).AddApplicationPart(typeof(EmergencyController).Assembly);
                services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
                services.AddEmergencyCredential(configuration);
            }).Configure(app =>
            {
                app.ApplicationServices.GetRequiredService<EmergencyRuntime>();
                app.UseAuthentication(); app.UseMiddleware<EmergencyMiddleware>(); app.UseMvc();
            }));
        }
        [DataTestMethod]
        [DataRow(false, "https", 404)]
        [DataRow(true, "http", 403)]
        public async Task Page_DisabledOrInsecure_ReturnsLocalError(bool enabled, string scheme, int status)
        {
            // Arrange
            using var fixture = new ProtocolFixture(); using var server = Host(fixture, enabled); using var client = server.CreateClient();
            // Act
            var response = await client.GetAsync(scheme + "://oidc.fixture.invalid/emergency/login");
            // Assert
            Assert.AreEqual(status, (int)response.StatusCode); Assert.AreEqual(0, fixture.Requests);
            StringAssert.Contains(response.Headers.CacheControl.ToString(), "no-store");
        }
        [TestMethod]
        public async Task OperatorPage_AntiforgeryAndLocalSwitch_WorkThroughHttpPipeline()
        {
            // Arrange
            using var fixture = new ProtocolFixture(); using var server = Host(fixture, true); using var client = server.CreateClient();
            var cookies = new Dictionary<string, string>();
            var page = await client.GetAsync(fixture.Options.Origin + "/emergency/operator");
            Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
            SaveCookies(page, cookies);
            string html = await page.Content.ReadAsStringAsync();
            string csrf = WebUtility.HtmlDecode(Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"").Groups[1].Value);
            Assert.IsFalse(string.IsNullOrEmpty(csrf));
            // Act and Assert
            var missing = await Post(client, fixture, "operator/signin", new { secret = fixture.OperatorSecret }, cookies, null);
            Assert.AreEqual(HttpStatusCode.Forbidden, missing.StatusCode);
            var login = await Post(client, fixture, "operator/signin", new { secret = fixture.OperatorSecret }, cookies, csrf);
            Assert.AreEqual(HttpStatusCode.OK, login.StatusCode); SaveCookies(login, cookies);
            var enabled = await Post(client, fixture, "operator/acceptance", new { enabled = true, minutes = 5 }, cookies, csrf);
            Assert.AreEqual(HttpStatusCode.NoContent, enabled.StatusCode);
            var available = await client.GetAsync(fixture.Options.Origin + "/emergency/login");
            Assert.AreEqual(HttpStatusCode.OK, available.StatusCode);
            var crossOrigin = await Post(client, fixture, "operator/acceptance", new { enabled = false, minutes = 0 }, cookies, csrf, "https://wrong.invalid");
            Assert.AreEqual(HttpStatusCode.Forbidden, crossOrigin.StatusCode); Assert.AreEqual(0, fixture.Requests);
            var stopped = await Post(client, fixture, "operator/acceptance", new { enabled = false, minutes = 0 }, cookies, csrf);
            Assert.AreEqual(HttpStatusCode.NoContent, stopped.StatusCode);
            var unavailable = await client.GetAsync(fixture.Options.Origin + "/emergency/login"); Assert.AreEqual(HttpStatusCode.Forbidden, unavailable.StatusCode);
        }
        private static async Task<HttpResponseMessage> Post(HttpClient client, ProtocolFixture fixture, string operation, object value, Dictionary<string, string> cookies, string csrf, string origin = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, fixture.Options.Origin + "/emergency/" + operation) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
            request.Headers.Add("Origin", origin ?? fixture.Options.Origin); request.Headers.Add("Cookie", string.Join("; ", cookies.Select(cookie => cookie.Key + "=" + cookie.Value)));
            if (csrf != null) request.Headers.Add("X-Emergency-CSRF", csrf);
            return await client.SendAsync(request);
        }
        private static void SaveCookies(HttpResponseMessage response, Dictionary<string, string> cookies)
        {
            if (!response.Headers.TryGetValues("Set-Cookie", out var values)) return;
            foreach (string value in values) { string pair = value.Split(';')[0]; int index = pair.IndexOf('='); cookies[pair.Substring(0, index)] = pair.Substring(index + 1); }
        }
    }
}
