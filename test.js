const Hapi        = require('@hapi/hapi');
const hapiAuthJWT = require('../lib/');
const JWT         = require('jsonwebtoken');  // used to sign our content
const port        = process.env.PORT || 8000; // allow port to be set

const secret = 'NeverShareYourSecret'; // Never Share This! even in private GitHub repos!

const people = {
    1: {
      id: 1,
      name: 'Anthony Valid User'
    }
};

const cookie_options = {
  ttl: 1 * 24 * 60 * 60 * 1000, // expires a day from today
  encoding: 'none',    // we already used JWT to encode
  isSecure: false,      // warm & fuzzy feelings
  isHttpOnly: true,    // prevent client alteration
  clearInvalid: false, // remove invalid cookies
  strictHeader: true   // don't allow violations of RFC 6265
  //isSameSite: 'Lax'
}

// use the token as the 'authorization' header in requests
const token = JWT.sign(people[1], secret); // synchronous
//console.log('Input token is ')
//console.log(token);
// bring your own validation function
const validate = async function (decoded, request, h) {
  console.log("#################### Inside Validate ############");
  console.log(" - - - - - - - decoded token:");
  console.log(decoded);
  console.log(" - - - - - - - request info:");
  console.log(request.info);
  console.log(" - - - - - - - user agent:");
  console.log(request.headers['user-agent']);

  // do your checks to see if the person is valid
  if (!people[decoded.id]) {
    return { isValid: false };
  }
  else {
    return { isValid : true };
  }
};

const init = async() => {
  const server = new Hapi.Server({ port: port });
  await server.register(hapiAuthJWT);
  // see: http://hapijs.com/api#serverauthschemename-scheme
  server.auth.strategy('jwt', 'jwt', 
  { key: secret,
    validate,
    verifyOptions: { ignoreExpiration: true }
  });

  server.auth.default('jwt');
  
  /*server.state('token', {  
    ttl: 1000 * 60 * 60 * 24,    // 1 day lifetime
    encoding: 'base64json'       // cookie data is JSON-stringified and Base64 encoded
  });*/

  server.route([
    {
      method: "GET", path: "/", config: { auth: false },
      handler: function(request, h) {
        return {text: 'Token not required'};
      }
    },
	{
      method: "GET", path: "/login", config: { auth: false },
      handler: function(request, h) {
		
		const params = request.query
		
		const userid = params['user']
		
		const logintoken = JWT.sign(people[userid], secret);

		//return h.response('<html><body> You are authenticated ! <br> <a href="/restrictedcustom">Restricted Page</a> </body> </html>')
		//		.header("Authorization", token)        // where token is the JWT
		//		.state("token", logintoken, cookie_options) // set the cookie with options
	   return h.response('Cookie is set').state('token', logintoken, cookie_options).redirect('/restrictedcustom');
      //return h.response('<script>location.href=\'/restrictedcustom\'</script>').state('token', cookie);
      }
    },
    {
      method: 'GET', path: '/restricted', config: { auth: 'jwt' },
      handler: function(request, h) {
        const response = h.response({message: 'You used a Valid JWT Token to access /restricted endpoint!'});
        response.header("Authorization", request.headers.authorization);
        return response;
      }
    },
	{
      method: 'GET', path: '/restrictedcustom', config: { auth: 'jwt' },
      handler: function(request, h) {
        const response = h.response({message: 'You used a Valid JWT Token to access /restricted endpoint!'});
        //response.header("Authorization", request.headers.authorization);
        return response;
      }
    }
  ]);
  await server.start();
  return server;
  
  
};

init().then(server => {
  console.log('Server running at:', server.info.uri);
}).catch(err => {
  console.log(err);
});
  
