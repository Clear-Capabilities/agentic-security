import matter from "gray-matter";

function refuseScript(): never {
  throw new Error("script front matter is not accepted");
}

export function parseNote(raw: string) {
  const { data, content } = matter(raw, {
    engines: { js: { parse: refuseScript }, javascript: { parse: refuseScript } },
  });
  return { meta: data, body: content };
}
