const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { randomUUID } = require('crypto');

// Guarded: allow-listed MIME types + a size cap.
const upload = multer({
  limits: { fileSize: 2 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, /^image\/(png|jpe?g)$/.test(file.mimetype)),
});

app.post('/upload', upload.single('doc'), (req, res) => {
  // Server-generated name — the client filename never touches the path.
  const safe = path.join('uploads', randomUUID() + '.png');
  fs.writeFileSync(safe, req.file.buffer);
  res.send('ok');
});
