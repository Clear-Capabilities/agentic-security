// Synthetic fixture, fixed twin: both actions validate the file name.
using Microsoft.AspNetCore.Mvc;

namespace Example.Exports
{
    public class ExportController : ControllerBase
    {
        private readonly IFileStore _files;

        public ExportController(IFileStore files)
        {
            _files = files;
        }

        [HttpGet("download")]
        public IActionResult Download(string fileName)
        {
            ValidateFileName(fileName);
            var bytes = _files.ReadAll(fileName);
            return File(bytes, "application/octet-stream");
        }

        [HttpGet("preview")]
        public IActionResult Preview(string fileName)
        {
            ValidateFileName(fileName);
            var bytes = _files.ReadAll(fileName);
            return File(bytes, "text/plain");
        }

        private static void ValidateFileName(string name)
        {
            if (name.Contains("..") || name.Contains("/"))
                throw new ArgumentException("bad name");
        }
    }
}
