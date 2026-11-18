import matter from "gray-matter";

export function parseNote(raw: string) {
  const { data, content } = matter(raw);
  return { meta: data, body: content };
}
