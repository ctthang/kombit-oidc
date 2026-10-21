using System;
using System.Linq;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class IssuerRecoveryTests
    {
        [TestMethod]
        public async Task Synchronize_ChangedIssuerState_BlocksOldCredentialsAndSessionsAcrossRestart()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement active = await fixture.Active();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            LocalSession session = await fixture.Prove(active, "login", null, 2);
            fixture.IssuerStateId = StrictJson.Id();

            // Act
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);
            fixture.Restart();

            // Assert
            Assert.IsFalse(fixture.Service.Accepting);
            Assert.IsNull(fixture.Service.Session(session.Id, fixture.Browser));
            op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Challenge(fixture.Browser, active.GetProperty("emergency_credential").GetString(), "login", null));
            using var state = OpenStateAfterStopping(fixture);
            Assert.AreEqual(fixture.IssuerStateId, state.Read(value => value.IssuerStateId));
            Assert.IsTrue(state.Read(value => value.Credentials.Values.All(entry => entry.Status == "blocked")));
        }

        [TestMethod]
        public async Task Synchronize_UnchangedIssuerState_PreservesOfflineCredential()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement active = await fixture.Active();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);

            // Act
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);
            fixture.Restart();
            fixture.Offline = true;
            int requests = fixture.Requests;
            LocalSession session = await fixture.Prove(active, "login", null, 2);

            // Assert
            Assert.IsNotNull(fixture.Service.Session(session.Id, fixture.Browser));
            Assert.AreEqual(requests, fixture.Requests);
        }

        [TestMethod]
        public async Task Synchronize_LegacyStateWithoutIssuerId_RequiresNewPreparation()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            await fixture.Active();
            using (var state = OpenStateAfterStopping(fixture))
            {
                state.Update(value => { value.IssuerStateId = null; value.RevocationCursor = 17; return true; });
            }
            fixture.Restart();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);

            // Act
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);

            // Assert
            Assert.IsFalse(fixture.Service.Accepting);
            using var persisted = OpenStateAfterStopping(fixture);
            Assert.AreEqual(0L, persisted.Read(value => value.RevocationCursor));
            Assert.AreEqual(fixture.IssuerStateId, persisted.Read(value => value.IssuerStateId));
            Assert.IsTrue(persisted.Read(value => value.Bindings.Values.All(binding => binding.Blocked)));
        }

        [TestMethod]
        public async Task Synchronize_RetentionLeavesSequenceGap_AppliesRemainingEvents()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            await fixture.Active();
            fixture.RevocationSequenceOffset = 42;
            await fixture.Service.RemoveAsync(fixture.Login(), fixture.Browser, fixture.Binding, CancellationToken.None);
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);

            // Act
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);

            // Assert
            using var state = OpenStateAfterStopping(fixture);
            Assert.AreEqual(43L, state.Read(value => value.RevocationCursor));
            Assert.IsTrue(state.Read(value => value.Bindings[fixture.Binding].Blocked));
        }

        [TestMethod]
        public async Task Synchronize_MissingIssuerStateId_RejectsResponse()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            JsonElement active = await fixture.Active();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            fixture.IssuerStateId = null;

            // Act and Assert
            await Assert.ThrowsExactlyAsync<EmergencyFault>(() => fixture.Service.SynchronizeAsync(op, CancellationToken.None));
            Assert.IsTrue(fixture.Service.Accepting);
            Assert.IsNotNull(await fixture.Prove(active, "login", null, 2));
        }

        [TestMethod]
        public async Task Synchronize_StateChangesDuringKeyFetch_DiscardsOldKeyResponse()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            await fixture.Active();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            fixture.BeforeSigningKeysResponse = () =>
            {
                fixture.BeforeSigningKeysResponse = null;
                fixture.RotateIssuerState();
                return Task.CompletedTask;
            };

            // Act
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);

            // Assert
            Assert.IsFalse(fixture.Service.Accepting);
            using var state = OpenStateAfterStopping(fixture);
            Assert.AreEqual(fixture.IssuerStateId, state.Read(value => value.IssuerStateId));
            Assert.AreEqual(fixture.Trust, state.Read(value => value.SigningKeys));
            Assert.IsFalse(state.Read(value => value.IssuerTrustRefreshRequired));
        }

        [TestMethod]
        public async Task Synchronize_ConcurrentRequestsDuringRecovery_PreservesCurrentTrust()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            await fixture.Active();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            var reached = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            var release = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            fixture.BeforeSigningKeysResponse = async () =>
            {
                fixture.BeforeSigningKeysResponse = null;
                reached.SetResult(true);
                await release.Task;
            };
            Task first = fixture.Service.SynchronizeAsync(op, CancellationToken.None);
            await reached.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Task second = fixture.Service.SynchronizeAsync(op, CancellationToken.None);

            // Act
            fixture.RotateIssuerState();
            release.SetResult(true);
            await Task.WhenAll(first, second).WaitAsync(TimeSpan.FromSeconds(10));

            // Assert
            using var state = OpenStateAfterStopping(fixture);
            Assert.AreEqual(fixture.IssuerStateId, state.Read(value => value.IssuerStateId));
            Assert.AreEqual(fixture.Trust, state.Read(value => value.SigningKeys));
            Assert.IsTrue(state.Read(value => value.Credentials.Values.All(entry => entry.Status == "blocked")));
        }

        [TestMethod]
        public async Task Synchronize_RecoveryKeyFetchFails_PersistsBlockedStateUntilRetry()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            await fixture.Active();
            string op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(op, true, 60);
            fixture.RotateIssuerState();
            fixture.FailSigningKeys = true;

            // Act
            await Assert.ThrowsExactlyAsync<System.Net.Http.HttpRequestException>(() => fixture.Service.SynchronizeAsync(op, CancellationToken.None));
            fixture.Restart();
            op = fixture.Service.OperatorSignIn(fixture.OperatorSecret);

            // Assert
            Assert.IsFalse(fixture.Service.Accepting);
            Assert.ThrowsExactly<EmergencyFault>(() => fixture.Service.Acceptance(op, true, 60));
            fixture.FailSigningKeys = false;
            await fixture.Service.SynchronizeAsync(op, CancellationToken.None);
            using var state = OpenStateAfterStopping(fixture);
            Assert.AreEqual(fixture.Trust, state.Read(value => value.SigningKeys));
            Assert.IsFalse(state.Read(value => value.IssuerTrustRefreshRequired));
            Assert.IsTrue(state.Read(value => value.Credentials.Values.All(entry => entry.Status == "blocked")));
        }
        private static ProtectedStateStore OpenStateAfterStopping(ProtocolFixture fixture)
        {
            fixture.Service.Dispose();
            return new ProtectedStateStore(fixture.Options, fixture.Protection, fixture.Verifier);
        }
    }
}
