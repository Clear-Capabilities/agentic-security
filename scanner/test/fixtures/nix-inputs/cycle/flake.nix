{
  inputs = {
    a.url = "github:example/a";
    b.url = "github:example/b";
    c.url = "github:example/c";
  };
  outputs = { self, a, b, c }: { };
}
