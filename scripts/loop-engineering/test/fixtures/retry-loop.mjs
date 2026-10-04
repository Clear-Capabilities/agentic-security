// Endless "API retry": keeps dialing a closed local port with tiny sleeps.
import net from 'node:net';
const attempt = () => { const s = net.connect(1, '127.0.0.1'); s.on('error', () => setTimeout(attempt, 20)); };
attempt();
