using System.IO;

namespace Sample.Templates
{
    public static class TemplateIncludes
    {
        private static string ResolveIncludeRef(string relativePath, string baseDir)
        {
            var fullPath = Path.GetFullPath(Path.Combine(baseDir, relativePath));
            return File.ReadAllText(fullPath);
        }
    }
}
