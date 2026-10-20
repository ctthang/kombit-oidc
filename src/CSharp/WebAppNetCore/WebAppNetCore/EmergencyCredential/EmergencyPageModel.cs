namespace WebAppNetCore.EmergencyCredential
{
    public sealed class EmergencyPageModel
    {
        public string Mode { get; set; }
        public bool CanPrepare { get; set; }
        public bool Accepting { get; set; }
        public bool OperatorAuthenticated { get; set; }
    }
}
