const basicAuth = require("express-basic-auth");
const passwordHash = require("./password-hash");
const { R } = require("redbean-node");
const { setting } = require("./util-server");
const { loginRateLimiter } = require("./rate-limiter");
const ldapjs  = require("ldapjs");
const { log } = require("../src/util");

/**
 * Login to web app
 * @param {string} username
 * @param {string} password
 * @returns {Promise<(Bean|null)>}
 */
exports.login = async function (username, password) {
    if (typeof username !== "string" || typeof password !== "string") {
        return null;
    }

    let user = await R.findOne("user", " username = ? AND active = 1 ", [
        username,
    ]);

    if (user && passwordHash.verify(password, user.password)) {
        // Upgrade the hash to bcrypt
        if (passwordHash.needRehash(user.password)) {
            await R.exec("UPDATE `user` SET password = ? WHERE id = ? ", [
                passwordHash.generate(password),
                user.id,
            ]);
        }
        return user;
    }

    return null;
};

/**
 * Login to web app by using LDAP
 * @param {string} username
 * @param {string} password
 * @param {string} ldap_url
 * @param {string} ldap_chain
 * @returns {Promise<(Bean|null)>}
 */
exports.ldaplogin = async function (username, password, ldap_url, ldap_chain) {
    return new Promise((resolve, reject) => {
        tlsOptions = { 'rejectUnauthorized': false}
        const client = ldapjs.createClient({
            tlsOptions: tlsOptions,
            url: ldap_url
        });

        try {
            console.log(`CN=${username},${ldap_chain}`)
            client.bind(`CN=${username},${ldap_chain}`, password, (err) => {
                if (err) {
                    console.error(err);
                    resolve(null);
                } else {
                    console.log('Użytkownik zalogowany');
                }
                client.unbind((err) => {
                    if (err) {
                        console.error(err);
                        resolve(null);
                    } else {
                        console.log('Połączenie zamknięte');
                        //let user = R.findOne("user", " username = ? AND active = 1 ", [
                        //    username,
                        //]);
                        
                        //if (user) {
                        //    console.log(user)
                        //    console.log('Użytkownik istnieje w bazie danych');
                        //} else { 
                            let user = {
                                twofa_status: 0,
                                username: username,
                                id: 1
                            };
                        //}
                        resolve(user);
                    }
                });
            });
        } catch (error) {
            console.error(error);
            reject(error);
        }
    });
};

/**
 * Callback for myAuthorizer
 * @callback myAuthorizerCB
 * @param {any} err Any error encountered
 * @param {boolean} authorized Is the client authorized?
 */

/**
 * Custom authorizer for express-basic-auth
 * @param {string} username
 * @param {string} password
 * @param {myAuthorizerCB} callback
 */
function myAuthorizer(username, password, callback) {
    // Login Rate Limit
    loginRateLimiter.pass(null, 0).then((pass) => {
        if (pass) {
            exports.login(username, password).then((user) => {
                callback(null, user != null);

                if (user == null) {
                    loginRateLimiter.removeTokens(1);
                }
            });
        } else {
            callback(null, false);
        }
    });
}

/**
 * Use basic auth if auth is not disabled
 * @param {express.Request} req Express request object
 * @param {express.Response} res Express response object
 * @param {express.NextFunction} next
 */
exports.basicAuth = async function (req, res, next) {
    const middleware = basicAuth({
        authorizer: myAuthorizer,
        authorizeAsync: true,
        challenge: true,
    });

    const disabledAuth = await setting("disableAuth");

    if (!disabledAuth) {
        middleware(req, res, next);
    } else {
        next();
    }
};
