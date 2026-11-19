import React from 'react';
import DOMPurify from 'dompurify';

export function Preview() {
  const bio = new URLSearchParams(location.search).get('bio');
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />;
}
