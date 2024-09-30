using Openus.SecSess.Key.Asymmetric;
using Openus.SecSess.Secure.Algorithm;

namespace Openus.SecSess.Key.Asymmetric.Interface
{
    /// <summary>
    /// Interface that defines saves and loads in file
    /// </summary>
    public interface IAsymmetricKey<T> where T : BaseAsymmetricKey
    {
        /// <summary>
        /// Save to key
        /// </summary>
        /// <param name="path">Save path</param>
        public abstract void Save(string path);
        /// <summary>
        /// Load from key
        /// </summary>
        /// <param name="algorithm">Asymmetric algorithm to use</param>
        /// <param name="path">Load path</param>
        /// <returns></returns>
        public abstract static T Load(AsymmetricType algorithm, string path);
    }
}