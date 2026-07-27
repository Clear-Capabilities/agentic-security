class App {
    public string Identity(string payload) {
        return payload;
    }
    public void Emit() {
        var path = Identity("/tmp/out.log");
        System.IO.File.WriteAllText(path, "content");
    }
}
