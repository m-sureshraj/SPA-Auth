'use strict';
const http = require('http');
const dotEnv = require('dotenv').config();
const mongoose = require('mongoose');

// handle db connection
mongoose.connect(process.env.DBTABASE, { useMongoClient: true });
mongoose.Promise = global.Promise;
mongoose.connection.on('error', (err) => {
    console.error(err.message);
    process.exit(1);
});
require('./models/User');

const app = require('./app');
const server = http.createServer(app);
const port = process.env.PORT || 3000;

server.listen(port);
server.on('error', onError);
server.on('listening', () => {
    const port = server.address().port;
    console.log(`Listening port: ${port}`);
});

function onError(error) {
    if (error.syscall !== 'listen') {
        throw error;
    }

    var bind = typeof port === 'string'
        ? 'Pipe ' + port
        : 'Port ' + port;

    // handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
}
