// Never calls the sink, even for a benign value, so reachability cannot be judged.
export async function fetchPreview() {
  return null;
}
