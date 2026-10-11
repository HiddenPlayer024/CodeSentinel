
var a = require('express')();
var b = 'req', c = 'query', d = 'name';
a.get('/', (r, s) => { s.send(r[c][d]); });
