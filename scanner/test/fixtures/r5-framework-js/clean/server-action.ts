'use server';
import fs from 'fs';
import { randomUUID } from 'crypto';
export async function saveNote(formData: FormData) {
  const body = formData.get('body');
  fs.writeFileSync('/srv/notes/' + randomUUID(), String(body));
}