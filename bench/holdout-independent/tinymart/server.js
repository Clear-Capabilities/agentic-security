const express = require('express');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use('/products', require('./routes/products'));
app.use('/admin', require('./routes/admin'));
app.use('/files', require('./routes/files'));
app.use('/comments', require('./routes/comments'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('tinymart listening on ' + PORT);
});
