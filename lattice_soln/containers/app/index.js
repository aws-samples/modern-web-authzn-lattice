var express = require('express')
const morgan = require('morgan');
var http = require('http')
var app = express()
const os = require('os');
const jwt = require('jsonwebtoken');
var concat = require('concat-stream');

app.set('json spaces', 2);
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

if (process.env.DISABLE_REQUEST_LOGS !== 'true') {
    app.use(morgan('combined'));
}

app.use(function (req, res, next) {
    req.pipe(concat(function (data) {
        req.body = data.toString('utf8');
        next();
    }));
});

app.all('/app[123]', (req, res) => {
        // res.json({"text":"got an app path"})
        console.log("got an app path")
        const http = require("http");

        const options = {
        hostname: req.path.substring(1)+'.application.internal',
        port: 443,
        path: '/',
        method: 'GET',
        headers: {
            'x-on-behalf-of': req.headers['x-jwt-subject'],
        }
        }

        req = http.request(options, (resp) => {
            let data = [];
            resp.on('data', chunk => {
                data.push(chunk);
              });
            resp.on('end', () => {
              res.send(JSON.parse(Buffer.concat(data).toString()));
            });       
         })
        .on("error", err => {
            console.log("Error: " + err.message);
        });
        req.on('error', (e) => {
            console.error(`problem with request: ${e.message}`);
          });
        req.end();
})

//Handle all paths
app.all('*', (req, res) => {
    const echo = {
        path: req.path,
        headers: req.headers,
        method: req.method,
        body: req.body,
        cookies: req.cookies,
        fresh: req.fresh,
        hostname: req.hostname,
        ip: req.ip,
        ips: req.ips,
        protocol: req.protocol,
        query: req.query,
        subdomains: req.subdomains,
        xhr: req.xhr,
        os: {
            hostname: os.hostname()
        },
        connection: {
            servername: req.connection.servername
        }
    };

    //If the Content-Type of the incoming body `is` JSON, it can be parsed and returned in the body
    if (req.is('application/json')) {
        echo.json = JSON.parse(req.body)
    }

    //If there's a JWT header, parse it and decode and put it in the response
    let token = req.headers['Authorization'];
    if (!token) {
        echo.jwt = token;
    } else {
        token = token.split(" ").pop();
        const decoded = jwt.decode(token, { complete: true });
        echo.jwt = decoded;
    }

    // strip out any unnecessary headers
    let newheaders = Object.keys(req.headers)
    .filter(key => !key.startsWith("x-amz-"));
    req.headers = newheaders;

    res.json(echo);

    //Certain paths can be ignored in the container logs, useful to reduce noise from healthchecks
    if (process.env.LOG_IGNORE_PATH != req.path) {

        let spacer = 4;
        if (process.env.LOG_WITHOUT_NEWLINE) {
            spacer = null;
        }

        console.log(JSON.stringify(echo, null, spacer));
    }
});


var httpServer = http.createServer(app).listen(process.env.HTTP_PORT || 8080);
console.log(`Listening on ports ${process.env.HTTP_PORT || 8080} for http`);

let calledClose = false;

process.on('exit', function () {
    if (calledClose) return;
    console.log('Got exit event. Trying to stop Express server.');
    server.close(function () {
        console.log("Express server closed");
    });
});

process.on('SIGINT', shutDown);
process.on('SIGTERM', shutDown);

function shutDown() {
    console.log('Got a kill signal. Trying to exit gracefully.');
    calledClose = true;
    httpServer.close(function () {
        console.log("HTTP servers closed. Asking process to exit.");
        process.exit()
    });
}