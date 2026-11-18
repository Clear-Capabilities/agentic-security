const _ = require('lodash');
app.get('/greet', (req, res) => {
  const render = _.template(req.query.layout);
  res.send(render({}));
});