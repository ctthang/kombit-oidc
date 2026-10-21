using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class EmergencyBehaviorTests
    {
        [DataTestMethod]
        [DataRow(false, false)]
        [DataRow(true, false)]
        [DataRow(false, true)]
        [DataRow(true, true)]
        public async Task Lifecycle_PrepareOfflineRestartAndAcceptance_EnforcesLocalState(bool elliptic, bool preserve)
        {
            // Arrange
            using var fixture = new ProtocolFixture(elliptic);
            fixture.Options.PreserveNormalClaims = preserve;
            JsonElement active = await fixture.Active();
            string operatorId = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(operatorId, true, 60);
            int requests = fixture.Requests;
            fixture.Offline = true;

            // Act
            fixture.Restart();
            var session = await fixture.Prove(active, "login", null, 2);
            var principal = fixture.Service.Session(session.Id, fixture.Browser);

            // Assert
            Assert.IsNotNull(principal);
            Assert.IsFalse(principal.IsInRole("case-admin"));
            Assert.IsFalse(principal.Claims.Any(claim => claim.Value == "normal-evidence"));
            Assert.AreEqual(preserve ? 2 : 0, principal.FindAll("department").Count());
            Assert.AreEqual(preserve ? "Synthetic User" : "Prepared user", principal.Identity.Name);
            if (preserve)
                Assert.AreEqual(System.Security.Claims.ClaimValueTypes.Integer, principal.FindFirst("level").ValueType);
            Assert.AreEqual(requests, fixture.Requests);
            Assert.AreEqual(1, principal.FindAll("emergency_session_id").Count());
            Assert.AreEqual(session.Id, principal.FindFirst("emergency_session_id").Value);
            Assert.IsNull(principal.FindFirst("acr"));
            Assert.IsNull(principal.FindFirst("access_token"));
            CollectionAssert.AreEquivalent(new[] { "read-only" }, principal.FindAll("role").Select(claim => claim.Value).ToArray());
            Assert.IsNull(fixture.Service.Session(session.Id, "another-browser"));
            operatorId = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(operatorId, false, 0);
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            fixture.Service.Acceptance(operatorId, true, 60);
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
        }

        [DataTestMethod]
        [DataRow("audience")]
        [DataRow("audience-array")]
        [DataRow("issuer")]
        [DataRow("expired")]
        [DataRow("long-lifetime")]
        [DataRow("profile")]
        [DataRow("source")]
        [DataRow("rp")]
        [DataRow("origin")]
        [DataRow("hardware")]
        [DataRow("type")]
        [DataRow("unknown-key")]
        [DataRow("external-key")]
        [DataRow("critical")]
        [DataRow("none")]
        [DataRow("duplicate")]
        [DataRow("tampered")]
        public void Credential_InvalidSignedProfile_Rejects(string mutation)
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string token = fixture.Issue(mutation).GetProperty("emergency_credential").GetString();
            // Act and Assert
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Verifier.Verify(token, fixture.Trust, fixture.Clock.Value));
        }

        [DataTestMethod]
        [DataRow("up")]
        [DataRow("uv")]
        [DataRow("backup")]
        [DataRow("backedUp")]
        [DataRow("type")]
        [DataRow("challenge")]
        [DataRow("origin")]
        [DataRow("rp")]
        [DataRow("id")]
        [DataRow("handle")]
        [DataRow("signature")]
        [DataRow("crossOrigin")]
        [DataRow("topOrigin")]
        public async Task Assertion_InvalidProof_RejectsAndConsumesAttempt(string mutation)
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string login = fixture.Login();
            JsonElement pending = await fixture.Pending(login);
            JsonElement challenge = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, pending.GetProperty("emergency_credential").GetString(), "activate", login));
            string id = challenge.GetProperty("transaction_id").GetString();
            JsonElement invalid = fixture.Assertion(challenge.GetProperty("publicKey"), 1, mutation);
            // Act and Assert
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.FinishAsync(fixture.Browser, id, "activate", invalid, login, CancellationToken.None));
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.FinishAsync(fixture.Browser, id, "activate", fixture.Assertion(challenge.GetProperty("publicKey"), 1), login, CancellationToken.None));
        }

        [TestMethod]
        public async Task Renewal_ActivationFailureThenSuccess_PreservesOldUntilReplacement()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement old = await fixture.Active();
            fixture.Clock.Advance(1);
            string login = fixture.Login();
            JsonElement renewed = await fixture.Service.RenewAsync(login, fixture.Browser, fixture.Binding, CancellationToken.None);
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            // Act
            var session = await fixture.Prove(old, "login", null, 2);
            await fixture.Prove(renewed, "activate", login, 3);
            // Assert
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, old.GetProperty("emergency_credential").GetString(), "login", null));
            var replacement = await fixture.Prove(renewed, "login", null, 4);
            Assert.IsNotNull(fixture.Service.Session(replacement.Id, fixture.Browser));
        }

        [TestMethod]
        public async Task ConcurrentChallenges_OnlyOneRevisionCanCommit()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement entry = await fixture.Active();
            fixture.Service.Acceptance(fixture.Service.OperatorSignIn(fixture.OperatorSecret), true, 60);
            string token = entry.GetProperty("emergency_credential").GetString();
            JsonElement first = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, token, "login", null));
            JsonElement second = JsonSerializer.SerializeToElement(fixture.Service.Challenge(fixture.Browser, token, "login", null));
            // Act
            await fixture.Service.FinishAsync(fixture.Browser, first.GetProperty("transaction_id").GetString(), "login", fixture.Assertion(first.GetProperty("publicKey"), 2), null, CancellationToken.None);
            // Assert
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.FinishAsync(fixture.Browser, second.GetProperty("transaction_id").GetString(), "login", fixture.Assertion(second.GetProperty("publicKey"), 3), null, CancellationToken.None));
        }

        [TestMethod]
        public async Task Remove_Offline_BlocksImmediatelyAndQueuesReport()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement entry = await fixture.Active();
            string login = fixture.Login();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            var session = await fixture.Prove(entry, "login", null, 2);
            fixture.Offline = true;
            // Act
            await fixture.Service.RemoveAsync(login, fixture.Browser, fixture.Binding, CancellationToken.None);
            // Assert
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            JsonElement status = JsonSerializer.SerializeToElement(fixture.Service.OperatorStatus(op));
            Assert.AreEqual(1, status.GetProperty("queued_removals").GetInt32());
            fixture.Restart();
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            fixture.Offline = false;
            op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);
            Assert.AreEqual(0, JsonSerializer.SerializeToElement(fixture.Service.OperatorStatus(op)).GetProperty("queued_removals").GetInt32());
        }

        [TestMethod]
        public async Task ExpiryAndRestart_RequiresNewLoginEvidenceAndRejectsPendingAccess()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string login = fixture.Login();
            JsonElement pending = await fixture.Pending(login);
            fixture.Service.Acceptance(fixture.Service.OperatorSignIn(fixture.OperatorSecret), true, 60);
            // Act and Assert
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, pending.GetProperty("emergency_credential").GetString(), "login", null));
            fixture.Restart();
            Assert.IsFalse(fixture.Service.HasLogin(login, fixture.Browser));
            string another = fixture.Login();
            fixture.Clock.Advance(601);
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.EnrollAsync(another, fixture.Browser, CancellationToken.None));
        }

        [TestMethod]
        public async Task DisabledMarker_ClearsAcceptanceWithoutDeletingPreparedState()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement entry = await fixture.Active();
            fixture.Service.Acceptance(fixture.Service.OperatorSignIn(fixture.OperatorSecret), true, 60);
            // Act
            File.WriteAllText(Path.Combine(fixture.Options.StorageDirectory, "support-disabled"), "1");
            fixture.Restart();
            // Assert
            Assert.IsFalse(fixture.Service.Accepting);
            fixture.Service.Acceptance(fixture.Service.OperatorSignIn(fixture.OperatorSecret), true, 60);
            Assert.IsNotNull(await fixture.Prove(entry, "login", null, 2));
        }

        [TestMethod]
        public void StateOwnership_CompetingWriterAndMissingState_Reject()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            // Act and Assert
            Assert.ThrowsExactly<IOException>(() => new ProtectedStateStore(fixture.Options, fixture.Protection, fixture.Verifier));
            fixture.Service.Dispose();
            File.Delete(Path.Combine(fixture.Options.StorageDirectory, "state.bin"));
            Assert.ThrowsExactly<InvalidOperationException>(() => new ProtectedStateStore(fixture.Options, fixture.Protection, fixture.Verifier));
        }
    }
}
