const _ = require('lodash');
const render = _.template('<p><%- name %></p>');
app.get('/greet', (req, res) => {
  res.json({ html: render({ name: req.query.name }) });
});