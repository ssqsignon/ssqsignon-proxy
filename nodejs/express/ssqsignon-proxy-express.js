
module.exports = function ssqSignonProxy(moduleName, clientId, clientSecret, options) {

    var bodyParser = require('body-parser'),
        https = require('https'),
        express = require('express'),
        router = express.Router(),
        grantTypeDetection = options.grantTypeDetection,
        connectionPooling = options.connectionPooling,
        options = options || {},
        noPipe = options.noPipe,
        host = options.host || 'ssqsignon.com',
        agent = (connectionPooling !== false) ? new https.Agent({ keepAlive: true }) : null;

    router.use(bodyParser.json());
    router.use(bodyParser.urlencoded({ extended: true }));
    router.post('/auth', function(req, res) {
        var body = req.body;
        if (!body.client_id) {
            body.client_id = clientId;
        }
        if (!body.grant_type && (grantTypeDetection !== false)) {
            body.grant_type = detectGrantType(body);
        }
        var bodyAsString = JSON.stringify(body);

        proxy(tokenEndpoint(bodyAsString), bodyAsString, res);
    });
    router.get('/whoami', function(req, res) {
        proxy(tokenValidationEndpoint(req), null, res);
    });
    router.get('/saferedirect', function(req, res) {
        proxy(redirectValidationEndpoint(req), null, res);
    });
    router.delete('/:id/tokens', function(req, res) {
        proxy(tokenNullificationEndpoint(req), null, res);
    });

    return router;

    function tokenEndpoint(bodyAsString) {
        return { method: 'POST',
            host: host,
            path: [ '', moduleName, 'auth' ].join('/'),
            auth: clientSecret ? [ clientId, clientSecret ].join(':') : null,
            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': bodyAsString.length },
            agent: agent
        };
    }

    function tokenValidationEndpoint(parentReq) {
        return { method: 'GET',
            host: host,
            path: [ '', moduleName, 'whoami' ].join('/'),
            headers: { 'Authorization': parentReq.get('Authorization') },
            agent: agent
        };
    }

    function redirectValidationEndpoint(parentReq) {
        var queryString = [];
        queryString.push(['response_type', (parentReq.query['response_type'] ? parentReq.query['response_type'] : 'code')].join('='));
        if (parentReq.query['client_id']) {
            queryString.push(['client_id', parentReq.query['client_id']].join('='));
        }
        if (parentReq.query['redirect_uri']) {
            queryString.push(['redirect_uri', parentReq.query['redirect_uri']].join('='));
        }
        if (parentReq.query['state']) {
            queryString.push(['state', parentReq.query['state']].join('='));
        }
        if (parentReq.query['scope']) {
            queryString.push(['scope', parentReq.query['scope']].join('='));
        }
        if (parentReq.query['deny_access']) {
            queryString.push(['deny_access', parentReq.query['deny_access']].join('='));
        }

        return { method: 'GET',
            host: host,
            path: [[ '', moduleName, 'saferedirect' ].join('/'), queryString.join('&')].join('?'),
            headers: { 'Authorization': parentReq.get('Authorization') },
            agent: agent
        };
    }

    function tokenNullificationEndpoint(parentReq) {
        return { method: 'DELETE',
            host: host,
            path: [ '', moduleName, parentReq.params.id, 'tokens' ].join('/'),
            headers: { 'Authorization': parentReq.get('Authorization') },
            agent: agent
        };
    }

    function proxy(requestConfig, bodyAsString, parentRes) {
        var req = https.request(requestConfig, function(response) {
            parentRes.writeHead(response.statusCode, response.headers);
            if (noPipe) {
                parentRes.ssqsignon = response;
            } else {
                response.pipe(parentRes);
            }
        })
            .on('error', function(e) {
                if (noPipe) {
                    parentRes.ssqsignon = { error: e };
                } else {
                    parentRes.status(500).send({ reason: e });
                }
            });
        req.end(bodyAsString);
    }

    function detectGrantType(body) {
        if (body.username || body.password) {
            return 'password';
        }
        if (body.code) {
            return 'authorization_code';
        }
        if (body.refresh_token) {
            return 'refresh_token';
        }
        return null;
    }
};
