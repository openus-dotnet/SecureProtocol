using SecSess.Tcp;

namespace SecSess.Interface
{
    /// <summary>
    /// The interface that manages the stream (mainly on the client side)
    /// </summary>
    public interface IStream
    {
        public abstract void Write(byte[] data);
        public abstract byte[] Read();
        public abstract bool CanUseStream(StreamType type = StreamType.All);
        public abstract void FlushStream();
    }
}
