class App {
    public string Identity(string payload) {
        return payload;
    }
    public void Emit() {
        var msg = Identity("status: ok");
        var w = new System.IO.StreamWriter("/tmp/out.log");
        w.Write(msg);
        w.Close();
    }
}
