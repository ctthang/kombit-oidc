using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using WebAppNetCore.EmergencyCredential;

namespace WebAppNetCore.Emergency.Tests
{
    [TestClass]
    public class PersistenceFailureTests
    {
        [TestMethod]
        public void StateWrite_Fails_DeniesCachedEmergencyAccess()
        {
            // Arrange
            using var fixture = new ProtocolFixture();
            string operatorId = fixture.Service.OperatorSignIn(fixture.OperatorSecret);
            fixture.Service.Acceptance(operatorId, true, 60);
            using var held = new FileStream(Path.Combine(fixture.Options.StorageDirectory, "state.bin"), FileMode.Open, FileAccess.Read, FileShare.Read);
            // Act
            Assert.ThrowsExactly<IOException>(() => fixture.Service.Acceptance(operatorId, false, 0));
            // Assert
            Assert.AreEqual(503, Assert.ThrowsExactly<EmergencyFault>(() => { bool allowed = fixture.Service.Accepting; }).Status);
        }
    }
}
