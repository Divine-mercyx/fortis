// From a real back-office codebase: logs whether a value exists, not the value
console.log('bvn:', p.bvn ? 'set' : 'missing');
console.log(`BVN source: ${row?.bvn ? 'DB' : req.body.bvn ? 'body' : 'MISSING'}`);
