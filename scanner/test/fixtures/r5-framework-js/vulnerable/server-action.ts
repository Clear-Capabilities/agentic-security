'use server';
import fs from 'fs';
export async function saveNote(formData: FormData) {
  const name = formData.get('name');
  fs.writeFileSync('/srv/notes/' + name, 'saved');
}