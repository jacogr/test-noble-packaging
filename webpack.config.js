const path = require('path');

module.exports = {
  entry: './src/index.esm.js',
	optimization: {
		minimize: false
	},
  output: {
    filename: 'webpack.js',
    path: path.resolve(__dirname, 'dist'),
  },
	resolve: {
		fallback: { crypto: false }
	}
};
