using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecSess.Interface
{
    /// <summary>
    /// Interface that defines saves and loads in file
    /// </summary>
    public interface IFile
    {
        public abstract void Save(string path);
        public abstract static IFile Load(string path);
    }
}
