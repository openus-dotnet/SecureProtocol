using Open.Net.SecSess.Key;
using Open.Net.SecSess.Secure.Algorithm;

namespace Open.Net.SecSess.Interface.Key
{
    /// <summary>
    /// Interface that defines saves and loads in file
    /// </summary>
    public interface IAsymmetricKey<T> where T : AsymmetricKeyBase
    {
        public abstract void Save(string path);
        public abstract static T Load(Asymmetric algorithm, string path);
    }
}