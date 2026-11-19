using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

public class BufferController : ControllerBase
{
    private const int MaxWidth = 200;

    [HttpGet("buffer")]
    public IActionResult Get([FromQuery][Range(1, 65536)] int size)
    {
        var data = new byte[size];
        return Ok(data.Length);
    }

    [HttpGet("pad")]
    public IActionResult Pad()
    {
        int.TryParse(Request.Query["width"], out var width);
        if (width > MaxWidth) return BadRequest();
        return Ok("x".PadLeft(width));
    }
}
