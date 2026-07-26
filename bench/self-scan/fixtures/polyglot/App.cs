class App {
    public void Emit(string payload) {
        var w = new System.IO.StreamWriter("/tmp/out.log");
        w.Write(payload);
        w.Close();
    }
}
