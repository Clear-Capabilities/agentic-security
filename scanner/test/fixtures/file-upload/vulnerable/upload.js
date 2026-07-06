const multer = require('multer');
const fs = require('fs');
const path = require('path');

// Unrestricted: no fileFilter, no limits — any file, any size.
const upload = multer({ dest: 'uploads/' });

app.post('/upload', upload.single('doc'), (req, res) => {
  // Client-supplied filename used as the on-disk destination (extension attack +
  // path traversal via `../../`).
  const dest = path.join('uploads', req.file.originalname);
  fs.writeFileSync(dest, req.file.buffer);
  res.send('ok');
});
