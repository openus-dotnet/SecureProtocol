using Openus.Net.SecSess.Secure.Algorithm;

namespace Openus.Net.SecSess.Key.Asymmetric.Interface
{
    /// <summary>
    /// Interface that defines saves and loads in file
    /// </summary>
    public interface IAsymmetricKey<T> where T : BaseAsymmetricKey
    {
        public abstract void Save(string path);
        public abstract static T Load(AsymmetricType algorithm, string path);
    }
}