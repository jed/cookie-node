var sys = require( "sys" ),
    base64 = require('./base64'),
    hex_hmac_sha1 = require('./sha1').hex_hmac_sha1;

processCookie = exports.processCookie = function(name, value) {
  var len, parts, expires, remoteSig, localSig;

  parts = value.replace(/\*/g, '=').split("|");

  if ( parts.length !== 4 ) {
    sys.error( "Invalid cookie: " + name );
    return null;
  }

  len = parts[0];
  value = base64.decode( parts[1] ).substr(0, len);
  expires = new Date( +parts[2] );
  remoteSig = parts[3];

  if ( expires < new Date ) {
    sys.error( "Expired cookie: " + name );
    return null;
  }

  localSig = hex_hmac_sha1( parts.slice( 0, 3 ).join("|"), cookieSecret() );

  if ( localSig !== remoteSig ) {
    sys.error( "Invalid signature: " + name );
    return null;
  }

  return value;
};


var mutateHttp = function(http){
    http.IncomingMessage.prototype._parseCookies = function() {
          var header = this.headers["cookie"] || "",
              ret = {};

          header.split(";").forEach( function( cookie ) {
            var parts = cookie.split("="),
                name = parts[0].trim(),
                value = parts[1].trim();

            ret[ name ] = value;  
          });
    };
    http.IncomingMessage.prototype._parseCookies = function() {
          var header = this.headers["cookie"] || "",
              ret = {};

          header.split(";").forEach( function( cookie ) {
            var parts = cookie.split("="),
                name =  (parts[0] ? parts[0].trim() : ''),
                value = (parts[1] ? parts[1].trim() : '');

            ret[ name ] = value;
          });
          return this.cookies = ret;
      };


     http.IncomingMessage.prototype.getCookie = function( name ) {
          var cookies = this.cookies || this._parseCookies();
          return cookies[ name ] || null;
     };

     http.IncomingMessage.prototype.getSecureCookie = function( name ) {
          var value = this.getCookie( name );

          if ( !value ) {
            sys.error( "No such cookie: " + name );
            return null;
          }

          return processCookie(name, value);
     };

     // this probably isn't kosher, but it's the best way to keep the interface sane.
     var _writeHead = http.ServerResponse.prototype.writeHead;
     var COOKIE_KEY = 'Set-Cookie', slice = Array.prototype.slice;
     http.ServerResponse.prototype.writeHead = function () {
       // Honor the passed args and method signature (see http.writeHead docs)
       var args = slice.call(arguments), headers = args[args.length-1];
       if (!headers || typeof(headers) != 'object') {
         // No header arg - create and append to args list
         args.push(headers = []);
       }

       // Merge cookie values
       var prev = headers[COOKIE_KEY], cookies = this.cookies || [];
       if (prev) cookies.push(prev);
       headers[COOKIE_KEY] = cookies.join(", ");

       // Invoke original writeHead()
       _writeHead.apply(this, args);
     };

     http.ServerResponse.prototype.setCookie = function( name, value, options ) {
          var cookies = this.cookies || ( this.cookies = [] ),
             cookie = [ name, "=", value, ";" ];

          options = options || {};

          if ( options.expires )
            cookie.push( " expires=", options.expires.toUTCString(), ";" );

          if ( options.path )
            cookie.push( " path=", options.path, ";" );

          if ( options.domain )
            cookie.push( " domain=", options.domain, ";" );

          if ( options.secure )
             cookie.push( " secure" );
             cookies.push( cookie.join("") );
     };

     http.ServerResponse.prototype.generateCookieValue = function( value, options ) {
         options = options || {};
         options.expires = options.expires || new Date( +new Date + 30 * 24 * 60 * 60 * 1000 );
         value = [ (value + '').length, base64.encode( value ), +options.expires ];
         var signature = hex_hmac_sha1( value.join("|"), cookieSecret() );

         value.push( signature );
         value = value.join("|").replace(/=/g, '*');

         return value;
      };

     http.ServerResponse.prototype.setSecureCookie = function( name, value, options ) {
         options = options || {};
         options.expires = options.expires || new Date( +new Date + 30 * 24 * 60 * 60 * 1000 );
         value = this.generateCookieValue(value, options);
         this.setCookie( name, value, options );
     };

     http.ServerResponse.prototype.clearCookie = function( name, options ) {
         options.expires = new Date( +new Date - 30 * 24 * 60 * 60 * 1000 );
         this.setCookie( name, "", options );
     };
};

mutateHttp(require('http'));


function cookieSecret() {
  if ( exports.secret )
    return exports.secret;

  sys.error(
    "No cookie secret is set. A temporary secret will be used for now, " +
    "but all cookies will be invalidated when the server is restarted."
  );

  return exports.secret = hex_hmac_sha1( Math.random(), Math.random() );
}
