const keep = []; 
const grow = () => { keep.push(Buffer.alloc(20 * 1024 * 1024, 1)); setTimeout(grow, 20); };
grow();
