using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Web.Mvc;
using System.Xml;
using Newtonsoft.Json;
using System.Runtime.Serialization.Formatters.Binary;

public class Vuln : Controller
{
    public void BadSql(string id, SqlConnection conn) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = " + id, conn);
        cmd.ExecuteReader();
    }

    public void BadProc(string args) {
        Process.Start("cmd.exe", args);
    }

    public ActionResult BadRazor(string user) {
        ViewBag.Raw = Html.Raw(user);
        return View();
    }

    public void BadXml(string xml) {
        var doc = new XmlDocument();
        doc.LoadXml(xml);
    }

    public void BadJson(string payload) {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        JsonConvert.DeserializeObject<object>(payload, settings);
    }

    public void BadBinFormatter(System.IO.Stream s) {
        var bf = new BinaryFormatter();
        bf.Deserialize(s);
    }

    [ValidateInput(false)]
    public ActionResult BadValidateInput(string html) {
        return Content(html);
    }

    public void BadPath(string fileName) {
        var p = Path.Combine("/uploads", fileName);
        System.IO.File.ReadAllText(p);
    }
}
