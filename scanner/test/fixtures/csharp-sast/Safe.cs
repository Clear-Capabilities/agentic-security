using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Xml;
using Newtonsoft.Json;

public class Safe
{
    public void OkSql(int id, SqlConnection conn) {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteReader();
    }

    public void OkProc(string filename) {
        var psi = new ProcessStartInfo("ls") { UseShellExecute = false };
        psi.ArgumentList.Add("-l");
        psi.ArgumentList.Add(filename);
        Process.Start(psi);
    }

    public void OkXml(string xml) {
        var doc = new XmlDocument { XmlResolver = null };
        doc.LoadXml(xml);
    }

    public void OkPath(string fileName) {
        var baseDir = Path.GetFullPath("/uploads");
        var joined = Path.GetFullPath(Path.Combine(baseDir, fileName));
        if (!joined.StartsWith(baseDir)) throw new InvalidOperationException();
        System.IO.File.ReadAllText(joined);
    }
}
