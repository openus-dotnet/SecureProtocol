namespace SecSess.Util
{
    /// <summary>
    /// Occurs when an initial secure session cannot be formed
    /// </summary>
    public class SecSessRefuesedException : Exception
    {
        public SecSessRefuesedException() : base("Failed to create a secure session.") { }
    }

    public class InvalidCombinationException : Exception 
    {
        public InvalidCombinationException() : base("Invalid combination between asymmetric to symmetric algorithm.") { }
    }
}
