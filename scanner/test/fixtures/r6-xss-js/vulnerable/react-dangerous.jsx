import React from 'react';

export function Preview() {
  const bio = new URLSearchParams(location.search).get('bio');
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
