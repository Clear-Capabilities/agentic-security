using Microsoft.AspNetCore.Mvc;

public class BufferController : ControllerBase
{
    [HttpGet("buffer")]
    public IActionResult Get([FromQuery] int size)
    {
        var data = new byte[size];
        return Ok(data.Length);
    }

    [HttpGet("pad")]
    public IActionResult Pad()
    {
        int.TryParse(Request.Query["width"], out var width);
        return Ok("x".PadLeft(width));
    }
}
