// Scope-aware call graph test: class method that calls into a vulnerable sink.
// The line-proximity walker would attribute the eval() call to whatever named
// function appears most recently in line order, which inside a class is wrong.
const express = require('express');
const app = express();

class CommandRunner {
  // This method does an eval — must be tracked as 'runUnsafe' calling 'eval'
  runUnsafe(input) {
    return eval(input);
  }

  runSafe(input) {
    return Number(input);
  }
}

const runner = new CommandRunner();

// Route handler invokes runUnsafe with attacker-controlled input
app.post('/run', (req, res) => {
  const result = runner.runUnsafe(req.body.code);
  res.json({ result });
});

app.listen(3000);
