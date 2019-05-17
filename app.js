const express = require("express");
const passportBearer = require("passport");
const passportOIDC = require("passport");
const path = require("path");
const fetch = require("node-fetch");

var BearerStrategy = require("passport-azure-ad").BearerStrategy;
var bearerOptions = {
    identityMetadata: "https://login.microsoftonline.com/7798a0ee-1875-4624-8de8-77d21f8140d0/v2.0/.well-known/openid-configuration",
    clientID: "28f2f30c-5a08-4ab3-af80-fad8d7e02dc6",
    issuer: "https://login.microsoftonline.com/7798a0ee-1875-4624-8de8-77d21f8140d0/v2.0",
    audience: "28f2f30c-5a08-4ab3-af80-fad8d7e02dc6",
    loggingLevel: "info",
    passReqToCallback: false,
};

var OIDCStrategy = require("passport-azure-ad").OIDCStrategy;
var oidcOptions = {
    identityMetadata: "https://login.microsoftonline.com/7798a0ee-1875-4624-8de8-77d21f8140d0/v2.0/.well-known/openid-configuration",
    clientID: "28f2f30c-5a08-4ab3-af80-fad8d7e02dc6",
    responseType: "code id_token",
    responseMode: "form_post",
    redirectUrl: "http://localhost:8080/auth",
    allowHttpForRedirectUrl: true,
    clientSecret: "vwtNCF0475++aszpOTLI9(^",
    validateIssuer: false,
    isB2C: false,
    issuer: "https://login.microsoftonline.com/7798a0ee-1875-4624-8de8-77d21f8140d0/v2.0",
    audience: "28f2f30c-5a08-4ab3-af80-fad8d7e02dc6",
    loggingLevel: "info",
    passReqToCallback: false,
    scope: ["openid", "profile", "offline_access"],
    nonceLifetime: null,
    nonceMaxAmount: 5,
    clockSkew: null
};

// this is a global HACK for in-memory "token cache"
users = [];
findByOid = (oid, fn) => {
    for (var i = 0, len = users.length; i < len; i++) {
        if (users[i].oid === oid) {
            return fn(null, users[i]);
        }
    }
    return fn(null, null);
};

var bearerStrategy = new BearerStrategy(bearerOptions, (token, done) => {
    done(null, {}, token);
});

var oidcStrategy = new OIDCStrategy(oidcOptions, (iss, sub, profile, access_token, refresh_token, done) => {
    if (!profile.oid) {
      return done(new Error("No oid found"), null);
    }
    
    // look up the user in cache
    findByOid(profile.oid, (err, user) => {
        if (err) {
            return done(err);
        }
        if (!user) {
            user = profile;
            users.push(profile);
        }

        // store/update tokens in our HACK in-memory "token cache"
        user.access_token = access_token;
        user.refresh_token = refresh_token;
        return done(null, user);
    });
});

const app = express();
app.use(require("morgan")("combined"));
app.use(require("cookie-parser")());
app.use(require("body-parser").urlencoded({ extended: true }));
app.use(require("express-session")({ secret: "keyboard cat", resave: true, saveUninitialized: false }));
app.use(passportBearer.initialize());
app.use(passportOIDC.initialize());
passportBearer.use(bearerStrategy);
passportOIDC.use(oidcStrategy);
app.use("/", express.static(path.join(__dirname, "")));

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.redirect("/login");
};

// API path
app.get("/api/me", passportBearer.authenticate("oauth-bearer", { session: false }), (req, res) => {
    console.log(req);
    var claims = req.authInfo;
    console.log("User info: ", req.user);
    console.log("Validated claims: ", claims);
    

    // look up the user in token cache
    findByOid(claims["oid"], (err, user) => {
        if (!user) {
            // return unauthorized...the token is not in cache
            res.status(401);
            res.send("User not in token cache");
        }
        else {
            // HACK: here we should get new token using refresh token
            fetch("https://graph.microsoft.com/v1.0/me", {
                method: "GET",
                headers: {
                    "Authorization": `Bearer ${user.access_token}`
                }
            }).then(function(graph_res) {
                if (!graph_res.ok) {
                    res.status(graph_res.status);
                    res.send(graph_res.statusText);
                }
                return graph_res.json();
            }).then((jsonResponse) => {
                res.status(200).json(jsonResponse);
            });
        }
    });
});

// root view
app.get("/", (req, res) => {
  res.render("index.html", { user: req.user });
});

// secure view
app.get("/secure", ensureAuthenticated, (req, res) => {
  res.render("account", { user: req.user });
});

// secure view
app.get("/auth", (req, res, next) => {
    // use the oidc configuration to login the user
    passportOIDC.authenticate("azuread-openidconnect", { 
        response: res,
        failureRedirect: "/" 
    })(req, res, next);
}, (req, res) => {
    res.redirect("/");
});

app.post("/auth", (req, res, next) => {
    passportOIDC.authenticate("azuread-openidconnect", { 
        response: res,
        failureRedirect: "/"  
    })(req, res, next);
}, (req, res) => {
    console.log(req);
    res.redirect(`/index.html#id_token=${req.body.id_token}`);
});

passportOIDC.serializeUser(function(user, done) {
    done(null, user.oid);
});
  
passportOIDC.deserializeUser(function(oid, done) {
    findByOid(oid, function (err, user) {
        done(err, user);
    });
});

app.listen(8080);