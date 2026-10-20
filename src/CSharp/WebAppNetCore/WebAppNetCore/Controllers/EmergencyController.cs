using System;
using System.IO;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Controllers
{
    [Route("emergency")]
    public sealed class EmergencyController : Controller
    {
        private readonly EmergencyRuntime runtime;
        private readonly IAntiforgery antiforgery;
        public EmergencyController(EmergencyRuntime feature, IAntiforgery csrf) { runtime = feature; antiforgery = csrf; }
        public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            try
            {
                if (!runtime.Options.Enabled) { throw new EmergencyFault(404, "not_found"); }
                runtime.Service.Rate(HttpContext.Connection.RemoteIpAddress?.ToString());
                if (Request.Method != "GET")
                {
                    if (Request.ContentLength > 70000) { throw new EmergencyFault(413, "request_too_large"); }
                    if (Request.Headers.Origin.Count != 1 || Request.Headers.Origin[0] != runtime.Options.Origin) { throw new EmergencyFault(403, "origin_rejected"); }
                    await antiforgery.ValidateRequestAsync(HttpContext);
                }
                EmergencyBrowser.Ensure(HttpContext);
                ActionExecutedContext result = await next();
                if (result.Exception != null) { result.Result = Error(result.Exception); result.ExceptionHandled = true; }
            }
            catch (Exception exception) { context.Result = Error(exception); }
        }
        private ObjectResult Error(Exception exception)
        {
            EmergencyFault fault = exception as EmergencyFault;
            int status = fault?.Status ?? (exception is AntiforgeryValidationException ? 403 : exception is JsonException || exception is FormatException || exception is System.Collections.Generic.KeyNotFoundException || exception is InvalidOperationException || exception is ArgumentException || exception is OverflowException ? 400 : 503);
            if (status == 429) { Response.Headers.RetryAfter = "60"; }
            return StatusCode(status, new { error = fault?.Code ?? (status == 403 ? "csrf_rejected" : status == 400 ? "invalid_request" : "emergency_unavailable") });
        }
        private async Task<string> Normal()
        {
            AuthenticateResult normal = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!normal.Succeeded || EmergencyMiddleware.IsEmergency(User)) { throw new EmergencyFault(401, "normal_login_required"); }
            return normal.Properties.Items.TryGetValue("emergency_login", out string id) ? id : null;
        }
        private async Task<string> Operator()
        {
            AuthenticateResult result = await HttpContext.AuthenticateAsync(EmergencyExtensions.OperatorScheme);
            string id = result.Principal?.FindFirst("operator_id")?.Value;
            runtime.Service.RequireOperator(id);
            return id;
        }
        private async Task<JsonElement> Body(params string[] fields)
        {
            if (Request.ContentLength > 70000) { throw new EmergencyFault(413, "request_too_large"); }
            if (!System.Net.Http.Headers.MediaTypeHeaderValue.TryParse(Request.ContentType, out System.Net.Http.Headers.MediaTypeHeaderValue media)
                || !string.Equals(media.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)
                || (!string.IsNullOrEmpty(media.CharSet) && !string.Equals(media.CharSet, "utf-8", StringComparison.OrdinalIgnoreCase))) { throw StrictJson.Bad(); }
            using MemoryStream bytes = new MemoryStream();
            byte[] buffer = new byte[4096];
            int count;
            while ((count = await Request.Body.ReadAsync(buffer, HttpContext.RequestAborted)) > 0)
            {
                if (bytes.Length + count > 70000) { throw new EmergencyFault(413, "request_too_large"); }
                bytes.Write(buffer, 0, count);
            }
            JsonElement value = StrictJson.Parse(new UTF8Encoding(false, true).GetString(bytes.ToArray()));
            StrictJson.Members(value, fields);
            return value;
        }
        [HttpGet("")]
        public async Task<IActionResult> Prepare()
        {
            string login = await Normal();
            return View("Page", new EmergencyPageModel { Mode = "prepare", CanPrepare = runtime.Service.HasLogin(login, EmergencyBrowser.Read(HttpContext)), Accepting = runtime.Accepting });
        }
        [HttpGet("login")]
        public IActionResult Login()
        {
            if (!runtime.Accepting) { Response.StatusCode = 403; }
            return View("Page", new EmergencyPageModel { Mode = "login", Accepting = runtime.Accepting });
        }
        [HttpGet("home")]
        public IActionResult Home()
        {
            if (!EmergencyMiddleware.IsEmergency(User)) { return RedirectToAction(nameof(Ended)); }
            return View("Home");
        }
        [HttpGet("ended")]
        public IActionResult Ended() => View("Page", new EmergencyPageModel { Mode = "ended", Accepting = runtime.Accepting });
        [HttpPost("normal-login")]
        public IActionResult NormalLogin()
        {
            if (EmergencyMiddleware.IsEmergency(User)) { throw new EmergencyFault(403, "normal_login_required"); }
            // RedirectUri is protected by the OIDC handler's state; it contains no token reference.
            return Challenge(new AuthenticationProperties { RedirectUri = Url.Action(nameof(Prepare)) }, OpenIdConnectDefaults.AuthenticationScheme);
        }
        [HttpPost("enrollments")]
        public async Task<IActionResult> Enroll()
        {
            await Body();
            return Json(await runtime.Service.EnrollAsync(await Normal(), EmergencyBrowser.Read(HttpContext), HttpContext.RequestAborted));
        }
        [HttpPost("enrollments/{id}/complete")]
        public async Task<IActionResult> Complete(string id)
        {
            JsonElement body = await Body("credential");
            return Json(await runtime.Service.CompleteEnrollmentAsync(await Normal(), EmergencyBrowser.Read(HttpContext), id, body.GetProperty("credential"), HttpContext.RequestAborted));
        }
        [HttpPost("enrollments/{id}/cancel")]
        public async Task<IActionResult> Cancel(string id)
        {
            await Body(); await runtime.Service.CancelAsync(await Normal(), EmergencyBrowser.Read(HttpContext), id, HttpContext.RequestAborted); return NoContent();
        }
        [HttpPost("renewals")]
        public async Task<IActionResult> Renew()
        {
            JsonElement body = await Body("binding_id");
            return Json(await runtime.Service.RenewAsync(await Normal(), EmergencyBrowser.Read(HttpContext), StrictJson.Text(body, "binding_id", 128), HttpContext.RequestAborted));
        }
        [HttpPost("status")]
        public async Task<IActionResult> Status()
        {
            await Body(); return Json(runtime.Service.Status(await Normal(), EmergencyBrowser.Read(HttpContext)));
        }
        [HttpPost("possession/options")]
        public async Task<IActionResult> PossessionOptions()
        {
            JsonElement body = await Body("emergency_credential");
            return Json(runtime.Service.Challenge(EmergencyBrowser.Read(HttpContext), StrictJson.Text(body, "emergency_credential", 65536), "activate", await Normal()));
        }
        [HttpPost("possession/complete")]
        public async Task<IActionResult> PossessionComplete()
        {
            JsonElement body = await Body("transaction_id", "credential");
            await runtime.Service.FinishAsync(EmergencyBrowser.Read(HttpContext), StrictJson.Text(body, "transaction_id", 128), "activate", body.GetProperty("credential"), await Normal(), HttpContext.RequestAborted);
            return Json(new { ready = true });
        }
        [HttpPost("login/options")]
        public async Task<IActionResult> LoginOptions()
        {
            JsonElement body = await Body("emergency_credential");
            return Json(runtime.Service.Challenge(EmergencyBrowser.Read(HttpContext), StrictJson.Text(body, "emergency_credential", 65536), "login", null));
        }
        [HttpPost("login/complete")]
        public async Task<IActionResult> LoginComplete()
        {
            JsonElement body = await Body("transaction_id", "credential");
            LocalSession session = await runtime.Service.FinishAsync(EmergencyBrowser.Read(HttpContext), StrictJson.Text(body, "transaction_id", 128), "login", body.GetProperty("credential"), null, HttpContext.RequestAborted);
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignInAsync(EmergencyExtensions.CookieScheme, new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("emergency_session_id", session.Id) }, EmergencyService.AuthenticationType)), new AuthenticationProperties { IsPersistent = false, AllowRefresh = false, ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(session.Expires) });
            return Json(new { redirect = Url.Action(nameof(Home)) });
        }
        [HttpPost("keys/{id}/remove")]
        public async Task<IActionResult> Remove(string id)
        {
            await Body(); await runtime.Service.RemoveAsync(await Normal(), EmergencyBrowser.Read(HttpContext), id, HttpContext.RequestAborted); return Json(new { removed = true });
        }
        [HttpPost("signout")]
        public async Task<IActionResult> LocalSignOut()
        {
            await Body();
            try { runtime.Service.SignOut(User.FindFirst("emergency_session_id")?.Value); }
            finally { await HttpContext.SignOutAsync(EmergencyExtensions.CookieScheme); }
            return Json(new { redirect = Url.Action(nameof(Ended)) });
        }
        [HttpGet("operator")]
        public async Task<IActionResult> OperatorPage()
        {
            bool authenticated = false;
            try { await Operator(); authenticated = true; } catch (EmergencyFault) { }
            return View("Page", new EmergencyPageModel { Mode = "operator", OperatorAuthenticated = authenticated, Accepting = runtime.Accepting });
        }
        [HttpPost("operator/signin")]
        public async Task<IActionResult> OperatorSignIn()
        {
            JsonElement body = await Body("secret");
            string id = runtime.Service.OperatorSignIn(StrictJson.Text(body, "secret", 512));
            await HttpContext.SignInAsync(EmergencyExtensions.OperatorScheme, new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("operator_id", id) }, "LocalEmergencyOperator")), new AuthenticationProperties { IsPersistent = false, AllowRefresh = false, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(15) });
            return Json(new { authenticated = true });
        }
        [HttpPost("operator/signout")]
        public async Task<IActionResult> OperatorSignOut()
        {
            await Body(); runtime.Service.OperatorSignOut(await Operator()); await HttpContext.SignOutAsync(EmergencyExtensions.OperatorScheme); return NoContent();
        }
        [HttpPost("operator/status")]
        public async Task<IActionResult> OperatorStatus() { await Body(); return Json(runtime.Service.OperatorStatus(await Operator())); }
        [HttpPost("operator/acceptance")]
        public async Task<IActionResult> Acceptance()
        {
            JsonElement body = await Body("enabled", "minutes");
            runtime.Service.Acceptance(await Operator(), body.GetProperty("enabled").GetBoolean(), checked((int)StrictJson.Integer(body, "minutes"))); return NoContent();
        }
        [HttpPost("operator/block")]
        public async Task<IActionResult> Block()
        {
            JsonElement body = await Body("binding_id", "whole_account");
            runtime.Service.OperatorBlock(await Operator(), StrictJson.Text(body, "binding_id", 128), body.GetProperty("whole_account").GetBoolean()); return NoContent();
        }
        [HttpPost("operator/poll")]
        public async Task<IActionResult> Poll() { await Body(); await runtime.Service.SynchronizeAsync(await Operator(), HttpContext.RequestAborted); return NoContent(); }
    }
}
