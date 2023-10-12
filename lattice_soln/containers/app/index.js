var express = require('express')
const morgan = require('morgan');
var http = require('http')
var app = express()
const os = require('os');
const jwt = require('jsonwebtoken');
var concat = require('concat-stream');

const crt = require("aws-crt");
const {HttpRequest} = require("aws-crt/dist/native/http");

const region = 'ap-southeast-2'

function sigV4SignBasic(method, endpoint, service) {
    const host = new URL(endpoint).host;
    const request = new HttpRequest(method, endpoint);
    request.headers.add('host', host);

    const config = {
        service: service,
        region: region,
        algorithm: crt.auth.AwsSigningAlgorithm.SigV4,
        signature_type: crt.auth.AwsSignatureType.HttpRequestViaHeaders,
        signed_body_header: crt.auth.AwsSignedBodyHeaderType.XAmzContentSha256,
        provider: crt.auth.AwsCredentialsProvider.newDefault()
    };

    crt.auth.aws_sign_request(request, config);
    return request.headers;
}


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

app.all('/app[123]/call-to-app[123]', (req, res) => {
        // res.json({"text":"got an app path"})
        console.log("got an app path")
        const http = require("http");
        
        const host = req.path.slice(-4)+'.application.internal'
        const url = 'http://'+host
        console.log(host)
        console.log(url)

        var headers={}
        sigv4headers = sigV4SignBasic("GET",url,"vpc-lattice-svcs")
        for (const sigv4header of sigv4headers) { 
            headers[sigv4header[0]]=sigv4header[1]
        }

        if('x-jwt-subject' in req.headers)
            headers['x-on-behalf-of-subject'] = req.headers['x-jwt-subject']
        const options = {
        hostname: host,
        port: 80,
        path: '/',
        method: 'GET',
        headers: headers
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
            console.log("Error: " + err);
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

    if('x-on-behalf-of-subject' in req.headers)
        echo.text={ 'on-behalf-of':'Call made on behalf of subject:'+req.headers['x-on-behalf-of-subject']}
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