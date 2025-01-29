const tools = require('./../tools');
const { authenticate } = require('ldap-authentication');
const querystring = require('querystring');
const axios = require('axios');


class AuthController {
  constructor(kubeService, twing) {
    this.kubeService = kubeService;
    this.twing = twing;
  }

  globalSecureAction(request, response, next) {
    // Salta il controllo se l'utente sta cercando di accedere alle route di login
    if (request.path === '/login' || request.path === '/auth/keycloak' || request.path === '/auth/callback') {
        return next();
    }

    // Se non ci sono informazioni nella sessione, forziamo il redirect a Keycloak
    if (!request.session.user && !request.headers.authorization) {
        return response.redirect('/auth/keycloak');
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
    const actor = req.session.user ? req.session.user.username : 'unknown'; // Aggiungi un controllo nel caso la sessione non esista
  
    // Aggiungi un log per verificare la presenza del token prima della rimozione
    console.log('Token di Keycloak prima del logout:', req.session.user ? req.session.user.token : 'nessun token');
  
    // Rimuovere il token di Keycloak dalla sessione
    if (req.session.user) {
      delete req.session.user.token;
    }
  
    // Distruggere la sessione
    req.session.destroy(function (err) {
      if (err) {
        console.error('Errore durante la distruzione della sessione:', err);
        return res.status(500).send('Errore durante il logout');
      }
  
      console.log('Sessione distrutta correttamente');
      res.clearCookie('connect.sid');  // Se il tuo cookie di sessione si chiama 'connect.sid'
  
      // Fare redirect alla pagina di login o alla homepage
      res.redirect('/login');
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
      const tokenResponse = await axios.post(`${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`, 
        querystring.stringify({
          client_id: process.env.KEYCLOAK_CLIENT_ID,
          client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
          grant_type: 'authorization_code',
          redirect_uri: `${process.env.APP_URL}/auth/callback`,
          code: code
        }), 
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
  
      const { access_token, id_token } = tokenResponse.data;
  
      // Decodifica il token per ottenere informazioni sull'utente
      const userInfo = await axios.get(`${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/userinfo`, {
        headers: { Authorization: `Bearer ${access_token}` }
      });
  
      // Verifica i ruoli dell'utente
      const roles = userInfo.data.realm_access ? userInfo.data.realm_access.roles : [];
      
      // if (!roles.includes('velero')) {
      //   return res.status(403).send('Accesso negato: l\'utente non ha il ruolo "velero"');
      // }
  
      // Se l'utente ha il ruolo 'velero', salva le informazioni nella sessione
      req.session.user = {
        isAdmin: roles.includes('admin'), // Puoi aggiungere più logiche per altri ruoli
        username: userInfo.data.preferred_username,
        email: userInfo.data.email,
        token: access_token
      };
  
      console.log('Utente autenticato con ruolo velero:', req.session.user);
      res.redirect('/');
  
    } catch (error) {
      console.error('Errore durante la callback:', error);
      res.status(500).send('Errore durante l\'autenticazione con Keycloak');
    }
  }  

  provaapi(){
    console.log("ciao" , process.env.KEYCLOAK_REALM)
  }
}




module.exports = AuthController;
