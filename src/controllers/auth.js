const tools = require('./../tools');
const { authenticate } = require('ldap-authentication');
const querystring = require('querystring');
const axios = require('axios');
const jwt = require('jsonwebtoken');


class AuthController {
  constructor(kubeService, twing) {
    this.kubeService = kubeService;
    this.twing = twing;
  }

  globalSecureAction(request, response, next) {
    // Salta il controllo se l'utente sta cercando di accedere alle route di login
    if (request.path === '/login' || request.path === '/auth/keycloak' || request.path === '/auth/callback' || request.path === 'logout') {
        return next();
    }

    // Se non ci sono informazioni nella sessione, forziamo il redirect a Keycloak
    if (!request.session.user && !request.headers.authorization) {
        return response.redirect('/login');
    }

    // Gestione del caso di modalità "read-only" e altre protezioni
    if (tools.readOnlyMode()) {
        if (request.method !== 'GET' && request.url !== '/login') {
            if (!request.session || !request.session.user || !request.session.user.isAdmin) {
                return response.status(405).end('Method Not Allowed');
            }
        }
    }

    // Altri controlli come cambio di contesto per multi-cluster...
    if (this.kubeService.isMultiCluster()) {
        let newContext = request.query.context;
        if (newContext) {
            request.session.context = newContext;
        }
        let userContext = request.session.context;
        if (!userContext) {
            userContext = this.kubeService.getCurrentContext();
            request.session.context = userContext;
        }
        this.kubeService.switchContext(userContext);
    }

    return next();
  }


  globalCSRFTokenAction(error, request, response, next) {
    if (error.code !== 'EBADCSRFTOKEN') {
      return next(error);
    }
    // handle CSRF token errors
    if (/application\/json;/.test(request.get('accept'))) {
      response.status(403);
      response.send('CSRF Token Invalid');
    } else {
      response.redirect(request.originalUrl + '?csrf-error');
    }
  }

  loginView(request, response) {
    this.twing.render('login.html.twig', { csrfToken: request.csrfToken() }).then((output) => {
      response.end(output);
    });
  }

  logoutAction(req, res) {
    console.log("ciao");
    const keycloakLogoutUrl = `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/logout?` +
        querystring.stringify({
            client_id: process.env.KEYCLOAK_CLIENT_ID,
            post_logout_redirect_uri: `${process.env.APP_URL}/login`
        });

    // Cancella la sessione e il cookie
    req.session.destroy((err) => {
        if (err) {
            console.error('Errore durante la distruzione della sessione:', err);
            return res.status(500).send('Errore durante il logout');
        }

        res.clearCookie('connect.sid'); // Cancella il cookie della sessione
        console.log('Sessione distrutta, reindirizzamento a Keycloak per il logout');
        
        // Reindirizza a Keycloak per il logout
        res.redirect(keycloakLogoutUrl);
    });
}
  
  

  async loginAction(request, response) {
    if (!request.body.username || !request.body.password) {
      return this.twing.render('login.html.twig', { message: 'Please enter both username and password' }).then((output) => {
        response.end(output);
      });
    }

    let adminAccount = tools.admin();
    if (adminAccount) {
      if (adminAccount.username === request.body.username && adminAccount.password === request.body.password) {
        request.session.user = {
          isAdmin: true,
          username: request.body.username,
          password: request.body.password
        };
        return response.redirect(tools.subPath('/'));
      }
    }

    let ldapConfig = tools.ldap();

    if (ldapConfig) {
      try {
        ldapConfig.userPassword = request.body.password;
        ldapConfig.username = request.body.username;
        ldapConfig.attributes = ['groups', 'givenName', 'sn', 'userPrincipalName', 'memberOf', 'gecos'];
        if (ldapConfig.attributes.indexOf(ldapConfig.usernameAttribute) === -1) {
          ldapConfig.attributes.push(ldapConfig.usernameAttribute);
        }
        let authenticated = await authenticate(ldapConfig);
        tools.debug('LDAP : Authenticated user : ', authenticated);

        if (authenticated) {
          let groups = authenticated.memberOf ? authenticated.memberOf : authenticated.groups ? authenticated.groups.split('|') : [];
          let availableNamespaces = tools.userNamespace(groups);

          request.session.user = {
            isAdmin: false,
            username: authenticated.gecos ? authenticated.gecos : request.body.username,
            password: request.body.password,
            groups: groups,
            namespaces: availableNamespaces
          };

          tools.audit(request.session.user.username, 'AuthController', 'LOGIN');

          return response.redirect(tools.subPath('/'));
        }
      } catch (err) {
        console.error(err);
      }
    }

    tools.audit(request.body.username, 'AuthController', 'LOGINFAILED');

    this.twing.render('login.html.twig', { message: 'Invalid credentials!' }).then((output) => {
      response.end(output);
    });
  }

  ///////////////////AUTENTICAZIONE CON KEYCLOAK/////////////////////////////
  /**
   * Reindirizza alla pagina di login di Keycloak
   */

  keycloakLogin(req, res) {
    const keycloakUrl = `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/auth?` +
      querystring.stringify({
        client_id: process.env.KEYCLOAK_CLIENT_ID,
        response_type: 'code',
        redirect_uri: `${process.env.APP_URL}/auth/callback`,
        scope: 'openid profile email'
      });

    res.redirect(keycloakUrl);
  }

  /**
   * Callback dopo l'autenticazione Keycloak
   */
  async keycloakCallback(req, res) {
    const { code } = req.query;
  
    if (!code) {
      return res.status(400).send('Codice di autorizzazione mancante');
    }
  
    try {
      // Scambia il codice con il token di accesso
      const tokenResponse = await axios.post(
        `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
        querystring.stringify({
          client_id: process.env.KEYCLOAK_CLIENT_ID,
          client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
          grant_type: 'authorization_code',
          redirect_uri: `${process.env.APP_URL}/auth/callback`,
          code: code
        }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
  
      const { access_token } = tokenResponse.data;
  
      // Decodifica il token JWT per ottenere i ruoli
      const decodedToken = jwt.decode(access_token); 
      const roles = decodedToken?.realm_access?.roles || [];
  
      if (!roles.includes('velero')) {
        return res.status(403).send(`
          <html>
            <head>
              <title>Accesso Negato</title>
              <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
                .container { max-width: 400px; margin: auto; padding: 20px; border: 1px solid #ccc; border-radius: 10px; }
                button { background-color: red; color: white; border: none; padding: 10px 20px; cursor: pointer; font-size: 16px; }
                button:hover { background-color: darkred; }
              </style>
            </head>
            <body>
              <div class="container">
                <h2>Accesso Negato</h2>
                <p>Non hai il ruolo richiesto per accedere all'applicazione.</p>
                <button onclick="logout()">Logout</button>
              </div>
              <script>
                function logout() {
                  window.location.href = "${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/logout?client_id=${process.env.KEYCLOAK_CLIENT_ID}&post_logout_redirect_uri=${process.env.APP_URL}/login";
                }
              </script>
            </body>
          </html>
        `);
      }
      
  
      // Recupera informazioni aggiuntive sull'utente
      const userInfo = await axios.get(
        `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`,
        { headers: { Authorization: `Bearer ${access_token}` } }
      );
  
      // Salva l'utente nella sessione
      req.session.user = {
        isAdmin: roles.includes('admin'),
        username: userInfo.data.preferred_username,
        email: userInfo.data.email,
        token: access_token
      };
  
      console.log('Utente autenticato con ruolo velero:', req.session.user);
      res.redirect('/');
  
    } catch (error) {
      console.error('Errore durante la callback:', error.response?.data || error.message);
      res.status(500).send('Errore durante l\'autenticazione con Keycloak');
    }
  }
  

  provaapi(){
    console.log("ciao" , process.env.KEYCLOAK_REALM)
  }
}




module.exports = AuthController;
