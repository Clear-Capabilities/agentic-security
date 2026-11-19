// Synthetic fixture: the guard runs on a field of the request in one action,
// and the other action reads a DIFFERENT field. Different value roles are
// never compared.
using Microsoft.AspNetCore.Mvc;

namespace Example.Exports
{
    public class ReportController : ControllerBase
    {
        private readonly IFileStore _files;

        public IActionResult Get(ReportRequest req)
        {
            ValidateFileName(req.FileName);
            var bytes = _files.ReadAll(req.FileName);
            return File(bytes, "text/plain");
        }

        public IActionResult GetTemplate(ReportRequest req)
        {
            var bytes = _files.ReadAll(req.TemplateId);
            return File(bytes, "text/plain");
        }

        private static void ValidateFileName(string name)
        {
            if (name.Contains("..")) throw new ArgumentException("bad name");
        }
    }
}
