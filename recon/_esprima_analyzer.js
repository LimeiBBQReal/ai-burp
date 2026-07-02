/* eslint-disable */
const esprima = require('esprima');

function analyze(code) {
    const result = {
        functions: [],
        calls: [],
        strings: [],
        complexity: 0,
        hasEval: false,
        hasFunctionConstructor: false,
    };

    try {
        const ast = esprima.parseScript(code, { tolerant: true, range: true });

        function walk(node, depth) {
            if (!node || typeof node !== 'object') return;

            if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') {
                const name = node.id ? node.id.name : '(anonymous)';
                result.functions.push({
                    name: name,
                    params: node.params.map(p => p.name || p.type),
                    range: node.range,
                });
            }

            if (node.type === 'CallExpression') {
                let callee = '';
                if (node.callee.type === 'Identifier') {
                    callee = node.callee.name;
                } else if (node.callee.type === 'MemberExpression') {
                    callee = node.callee.property ? node.callee.property.name : '';
                }
                if (callee) {
                    result.calls.push(callee);
                    if (callee === 'eval') result.hasEval = true;
                    if (callee === 'Function') result.hasFunctionConstructor = true;
                }
            }

            if (node.type === 'Literal' && typeof node.value === 'string') {
                if (node.value.length > 3 && node.value.length < 200) {
                    result.strings.push(node.value);
                }
            }

            for (const key in node) {
                if (key === 'range' || key === 'loc') continue;
                const child = node[key];
                if (Array.isArray(child)) {
                    child.forEach(c => walk(c, depth + 1));
                } else if (child && typeof child === 'object' && child.type) {
                    walk(child, depth + 1);
                }
            }
        }

        walk(ast, 0);
        result.complexity = result.functions.length + result.calls.length;
    } catch (e) {
        result.error = e.message;
    }

    return result;
}

const fs = require('fs');
const code = fs.readFileSync(0, 'utf-8');
const result = analyze(code);
console.log(JSON.stringify(result));
