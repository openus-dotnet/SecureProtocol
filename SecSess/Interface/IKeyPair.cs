using SecSess.Key;

namespace SecSess.Interface
{
    /// <summary>
    /// Interface that defines saves and loads in file
    /// </summary>
    public interface IKeyPair<T> where T : AsymmetricKeyBase
    {
        public abstract void Save(string path);
        public abstract static T Load(string path);
    }
}