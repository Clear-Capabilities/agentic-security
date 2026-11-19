using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

public class WriteController : Controller
{
    [HttpGet("/note")]
    public async Task Note()
    {
        string note = Request.Query["note"];
        Response.ContentType = "text/html";
        await Response.WriteAsync("<p>" + WebUtility.HtmlEncode(note) + "</p>");
    }
}
