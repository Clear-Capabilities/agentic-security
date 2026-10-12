// Deliberately vulnerable: a debug header bypasses the authorization check entirely.
const role = process.argv[2] === 'admin-debug' ? 'admin' : 'anonymous';
const secret = process.env.GUARDED_RESOURCE_VALUE || '';
if (role === 'admin') console.log(secret);
