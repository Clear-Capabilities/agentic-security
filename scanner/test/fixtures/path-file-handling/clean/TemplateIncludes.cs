using System;
using System.IO;

namespace Sample.Templates
{
    public static class TemplateIncludes
    {
        private static string ResolveIncludeRef(string relativePath, string baseDir)
        {
            var fullPath = Path.GetFullPath(Path.Combine(baseDir, relativePath));
            if (!IsUnder(fullPath, baseDir))
                throw new InvalidOperationException("include escapes the template directory");
            return File.ReadAllText(fullPath);
        }

        private static bool IsUnder(string path, string root)
        {
            var rel = Path.GetRelativePath(root, path);
            return rel != ".." && !rel.StartsWith(".." + Path.DirectorySeparatorChar) && !Path.IsPathRooted(rel);
        }
    }
}
