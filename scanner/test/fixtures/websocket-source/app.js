const { Server } = require('socket.io');
const { exec } = require('child_process');
const io = new Server();

io.on('connection', (socket) => {
  // VULNERABLE: WebSocket message data flows into command injection
  socket.on('runCommand', (payload) => {
    exec(payload.cmd);
  });

  // VULNERABLE: WebSocket message data flows into eval
  socket.on('message', (data) => {
    eval(data.script);
  });
});

io.listen(3000);
