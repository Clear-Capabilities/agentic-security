function enqueueBackup(queue) {
  const password = process.env.PASSWORD;
  queue.sendMessage({ MessageBody: password });
}
