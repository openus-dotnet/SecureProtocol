using Openus.Net.SecSess.Key;
using Openus.Net.SecSess.Secure.Algorithm;

namespace Openus.Net.SecSess.Interface.Key
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