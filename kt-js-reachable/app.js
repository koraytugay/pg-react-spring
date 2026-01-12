const _ = require('lodash');
const axios = require('axios');
const minimist = require('minimist');
const express = require('express');
const serialize = require('node-serialize');
const marked = require('marked');
const jwt = require('jsonwebtoken');
const { DOMParser } = require('@xmldom/xmldom');

const app = express();
const PORT = 3000;

console.log('=== Vulnerable Test Application ===\n');

// Top-level direct calls to vulnerable methods
_.merge({}, {});
minimist([]);
serialize.unserialize(serialize.serialize({}));
marked('test');
axios.get('http://example.com').catch(() => {});
jwt.sign({}, 'key');
new DOMParser().parseFromString('<x/>', 'text/xml');

// Helper function that uses vulnerable patterns
function processUserInput(input) {
  // Using merge in a function to ensure reachability
  return _.merge({}, JSON.parse(input));
}

function parseCliArgs(args) {
  // Direct minimist usage
  return minimist(args);
}

function renderMarkdown(text) {
  // Direct marked usage
  return marked(text);
}

function makeHttpRequest(url, data) {
  // Direct axios usage
  return axios({
    method: 'post',
    url: url,
    data: data
  });
}

function deserializeData(serialized) {
  // Direct node-serialize usage
  return serialize.unserialize(serialized);
}

function verifyToken(token, secret) {
  // Direct jwt verification without algorithm specification
  return jwt.verify(token, secret);
}

function parseXml(xmlStr) {
  // Direct xmldom usage
  const p = new DOMParser();
  return p.parseFromString(xmlStr, 'text/xml');
}

// 1. Lodash - Prototype Pollution vulnerability (CVE-2019-10744)
console.log('1. Testing Lodash (vulnerable to prototype pollution)...');
const maliciousPayload = JSON.parse('{"__proto__": {"polluted": "Yes! Prototype is polluted"}}');
_.merge({}, maliciousPayload);
console.log('   Prototype pollution check:', {}.polluted);

// Call through helper function
const userInput = '{"__proto__": {"polluted5": "via helper"}}';
processUserInput(userInput);

// Additional lodash vulnerable methods
_.defaultsDeep({}, maliciousPayload);
_.set({}, '__proto__.polluted3', 'via set');
_.setWith({}, '__proto__.polluted4', 'via setWith', Object);
_.mergeWith({}, maliciousPayload, (objValue, srcValue) => srcValue);
console.log('   Additional lodash pollution:', {}.polluted3, {}.polluted4);

// 2. Minimist - Prototype Pollution vulnerability (CVE-2020-7598)
console.log('\n2. Testing Minimist (vulnerable to prototype pollution)...');
const args = minimist(['--__proto__.polluted2', 'minimist_pollution']);
console.log('   Minimist pollution check:', {}.polluted2);

// Additional minimist calls
const cliArgs = parseCliArgs(['--constructor.prototype.polluted6', 'test']);
const processArgs = minimist(process.argv.slice(2));
console.log('   Minimist process args:', processArgs);

// 3. Axios - SSRF and other vulnerabilities (CVE-2021-3749)
console.log('\n3. Testing Axios (vulnerable to SSRF)...');
axios.get('http://example.com')
  .then(response => console.log('   Axios request successful'))
  .catch(err => console.log('   Axios request failed (expected for this test)'));

// Additional axios methods
axios.post('http://example.com/api', { data: 'test' })
  .catch(err => console.log('   Axios POST executed'));
axios.request({ url: 'http://example.com', method: 'GET' })
  .catch(err => console.log('   Axios request() executed'));

// 4. Node-serialize - Remote Code Execution via deserialization (CVE-2017-5941)
console.log('\n4. Testing node-serialize (vulnerable to RCE via deserialization)...');
const serializedData = '{"rce":"_$$ND_FUNC$$_function (){console.log(\'RCE vulnerability exists!\');}()"}';
try {
  const deserializedData = serialize.unserialize(serializedData);
} catch (e) {
  console.log('   Deserialization attempted (RCE vector exists)');
}

// Call through helper
try {
  deserializeData('{"test":"value"}');
} catch (e) {
  console.log('   Helper deserialization called');
}

// Additional serialize/unserialize calls
const obj = { name: 'test', value: 123 };
const serialized = serialize.serialize(obj);
const unserialized2 = serialize.unserialize(serialized);
console.log('   Serialize/unserialize cycle completed:', unserialized2);

// More unserialize calls to ensure detection
const data1 = serialize.serialize({ a: 1, b: 2 });
serialize.unserialize(data1);
const data2 = serialize.serialize([1, 2, 3]);
serialize.unserialize(data2);
console.log('   Additional unserialize calls completed');

// 5. Marked - XSS vulnerability (CVE-2022-21680, CVE-2022-21681)
console.log('\n5. Testing Marked (vulnerable to XSS)...');
const markdown = '# Hello **World**';
const html = marked(markdown);
console.log('   Marked rendered:', html.trim());

// Call through helper
const helperHtml = renderMarkdown('## Test **bold**');
console.log('   Helper markdown rendered');

// Additional marked calls with potential XSS
const xssMarkdown = '[Click me](javascript:alert("XSS"))';
const xssHtml = marked(xssMarkdown);
console.log('   Marked XSS vector:', xssHtml.trim());

// Parse with inline HTML
const inlineHtml = '<script>alert("XSS")</script>\n# Title';
const parsedHtml = marked.parse(inlineHtml);
console.log('   Marked inline HTML parsed');

// Lexer and parser calls
const tokens = marked.lexer('# Heading\n\nParagraph');
const parsedFromTokens = marked.parser(tokens);
console.log('   Marked lexer/parser used');

// 6. Express - Various vulnerabilities in old version
console.log('\n6. Testing Express (old version with multiple CVEs)...');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Use query parser directly
const queryParser = express.query();
app.use(queryParser);

app.get('/', (req, res) => {
  res.send('Vulnerable test application is running!');
});

// Route vulnerable to open redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url); // Vulnerable to open redirect
});

// Route with potential XSS
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Hello ${name}!</h1>`); // Vulnerable to XSS
});

// Route with path traversal vulnerability
app.get('/file', (req, res) => {
  const filepath = req.query.path;
  res.sendFile(filepath); // Vulnerable to path traversal
});

// Route with SQL injection pattern (simulated)
app.get('/user', (req, res) => {
  const userId = req.query.id;
  // In real app: db.query('SELECT * FROM users WHERE id = ' + userId); // SQL injection
  res.json({ userId: userId, message: 'SQL injection vector exists' });
});

// Route that uses vulnerable lodash merge
app.post('/merge', (req, res) => {
  const result = _.merge({}, req.body);
  res.json(result);
});

// Route that uses marked
app.post('/render', (req, res) => {
  const html = marked(req.body.markdown || '');
  res.send(html);
});

// Route that uses minimist
app.get('/parse', (req, res) => {
  const args = req.query.args ? req.query.args.split(' ') : [];
  const parsed = minimist(args);
  res.json(parsed);
});

// 7. JWT - Algorithm confusion vulnerability (CVE-2022-23529)
console.log('\n7. Testing jsonwebtoken (vulnerable to algorithm confusion)...');
const token = jwt.sign({ user: 'admin' }, 'secret', { algorithm: 'HS256' });
console.log('   JWT token created:', token);

// Try to verify without proper algorithm specification (vulnerable)
try {
  const decoded = jwt.verify(token, 'secret');
  console.log('   JWT verified:', decoded);
} catch (e) {
  console.log('   JWT verification failed');
}

// Additional JWT vulnerable patterns
const rsaToken = jwt.sign({ role: 'admin' }, 'secret', { algorithm: 'RS256' });
jwt.decode(rsaToken, { complete: true });
console.log('   JWT decode executed');

// 8. xmldom - XXE and prototype pollution (CVE-2021-21366)
console.log('\n8. Testing xmldom (vulnerable to XXE)...');
const xmlString = '<root><item>Test XML</item></root>';
const parser = new DOMParser();
const doc = parser.parseFromString(xmlString, 'text/xml');
console.log('   XML parsed:', doc.documentElement.nodeName);

// Call through helper
parseXml('<data><value>123</value></data>');

// Additional XML parsing with XXE vector
const xxeXml = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>';
const xxeDoc = parser.parseFromString(xxeXml, 'text/xml');
console.log('   XXE vector parsed:', xxeDoc.documentElement.nodeName);

// Parse HTML
const htmlString = '<html><body><h1>Test</h1></body></html>';
const htmlDoc = parser.parseFromString(htmlString, 'text/html');
console.log('   HTML parsed');

// Additional DOMParser instances
const parser2 = new DOMParser();
const doc2 = parser2.parseFromString('<root attr="value"/>', 'application/xml');
console.log('   Second parser used');

// 9. Direct calls to vulnerable methods to ensure reachability
console.log('\n9. Making direct vulnerable method calls...');

// Direct lodash calls
_.merge({}, { test: 'merge' });
_.defaultsDeep({}, { test: 'defaultsDeep' });
_.set({}, 'path.to.value', 'set');
_.setWith({}, 'path', 'setWith', Object);

// Direct minimist calls
minimist(['--test', 'value']);
minimist(process.argv);

// Direct node-serialize calls
serialize.serialize({ test: 'data' });
serialize.unserialize(serialize.serialize({ a: 1 }));

// Direct marked calls
marked('# Direct call');
marked.parse('## Parse call');
marked.lexer('### Lexer call');

// Direct axios calls
axios.get('http://example.com').catch(() => {});
axios.post('http://example.com', {}).catch(() => {});
axios({ method: 'get', url: 'http://example.com' }).catch(() => {});

// Direct JWT calls
jwt.sign({ user: 'test' }, 'secret');
jwt.verify(jwt.sign({ u: 'x' }, 's'), 's');
jwt.decode('token');

// Direct xmldom calls
new DOMParser().parseFromString('<root/>', 'text/xml');

console.log('   All direct calls completed');

// Start the server
app.listen(PORT, () => {
  console.log(`\n=== Server running on http://localhost:${PORT} ===`);
  console.log('Endpoints:');
  console.log(`  - http://localhost:${PORT}/`);
  console.log(`  - http://localhost:${PORT}/redirect?url=http://evil.com`);
  console.log(`  - http://localhost:${PORT}/greet?name=<script>alert('XSS')</script>`);
  console.log(`  - http://localhost:${PORT}/merge (POST) - lodash merge`);
  console.log(`  - http://localhost:${PORT}/render (POST) - marked render`);
  console.log(`  - http://localhost:${PORT}/parse?args=--foo%20bar - minimist parse`);
});
