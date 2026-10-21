namespace WebAppNetCore.EmergencyCredential
{
    public sealed class RegistryEntry
    {
        public string BindingId { get; set; }
        public string Status { get; set; } = "pending";
        public System.Collections.Generic.List<SnapshotClaim> NormalAccessTokenClaims { get; set; }
        public VerifiedCredential Credential { get; set; }
    }
}
