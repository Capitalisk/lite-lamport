const commonjs = require('@rollup/plugin-commonjs');
const resolve = require('@rollup/plugin-node-resolve');
const terser = require('@rollup/plugin-terser');
const inject = require('@rollup/plugin-inject');

module.exports = {
  input: 'esm.js',
  output: {
    file: 'lite-lamport.min.js',
    format: 'es'
  },
  plugins: [
    inject({
      Buffer: ['buffer', 'Buffer']
    }),
    commonjs(),
    resolve({
      preferBuiltins: false,
      browser: true
    }),
    terser()
  ]
};

