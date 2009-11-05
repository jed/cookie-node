// something like this should be in the process module
process.Promise.prototype.combine = function() {
  var args = Array.prototype.slice.call( arguments ),
      count = args.length,
      results = new Array( count ),
      index = 0,
      self = this;
      
  if ( count == 1 && args[0] instanceof Array )
    return arguments.callee.apply( self, args[0] );
    
  args.forEach( function( promise ) {
    var thisIndex = index++;

    promise.addErrback( function() {
      results[ thisIndex ] = arguments;
      self.emitError.apply( self, results )
    });
 
    promise.addCallback( function() {
      results[ thisIndex ] = arguments;
      if ( !--count )
        self.emitSuccess.apply( self, results );
    });
  });
  
  return self;
}

var http = require( "http" ),
    sys = require( "sys" ),
    path = module.filename.replace( /[^\/]+$/, "" ),
    dependencies = [ "sha1.js", "base64.js" ],
    promises = dependencies
      .map( function( file ) { return path + file } )
      .map( require( "posix" ).cat ),
    _sendHeader = http.ServerResponse.prototype.sendHeader;
 
( new process.Promise ).combine( promises ).addCallback( function() {
  for ( var i = 0, len = arguments.length; i < len; i++ )
    process.compile( arguments[ i ][ 0 ], dependencies[ i ] );
})

process.mixin( http.IncomingMessage.prototype, {

  _parseCookies: function() {
    var header = this.headers["cookie"] || "",
        ret = {};
  
    header.split(";").forEach( function( cookie ) {
      var parts = cookie.split("="),
          name = parts[0].trim(),
          value = parts[1].trim();
          
      ret[ name ] = value;  
    })
    
    return this.cookies = ret;
  },
  
  getCookie: function( name ) {
    var cookies = this.cookies || this._parseCookies();
    return cookies[ name ] || null;
  },
  
  getSecureCookie: function( name ) {
    var value = this.getCookie( name ),
        parts, expires, remoteSig, localSig;
        
    if ( !value ) {
      sys.error( "No such cookie: " + name )
      return null;
    }
        
    parts = value.split("|");
  
    if ( parts.length !== 3 ) {
      sys.error( "Invalid cookie: " + name )
      return null;
    }
  
    value = Base64.decode( parts[0] );
    expires = new Date( +parts[1] );
    remoteSig = parts[2];
    
    if ( expires < new Date ) {
      sys.error( "Expired cookie: " + name )
      return null;
    }
    
    localSig = hex_hmac_sha1( parts.slice( 0, 2 ).join("|"), cookieSecret() )
  
    if ( localSig !== remoteSig ) {
      sys.error( "Invalid signature: " + name )
      return null;
    }
    
    return value;  
  }
});

// this probably isn't kosher, but it's the best way to keep the interface sane.
http.ServerResponse.prototype.sendHeader = function ( statusCode, headers ) {
  var cookies = this.cookies || ( this.cookies = [] );
  headers["Set-Cookie"] = cookies.join(", ");
  _sendHeader.call( this, statusCode, headers );
};

process.mixin( http.ServerResponse.prototype, {
  setCookie: function( name, value, options ) {
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
  },
  
  setSecureCookie: function( name, value, options ) {
    options = options || {};
    options.expires = options.expires || new Date( +new Date + 30 * 24 * 60 * 60 * 1000 )
    
    var value = [ Base64.encode( value ).replace("=", ""), +options.expires ],
        signature = hex_hmac_sha1( value.join("|"), cookieSecret() )
        
    value.push( signature );
    value = value.join("|");
    
    this.setCookie( name, value, options );
  },
  
  clearCookie: function( name, options ) {
    options.expires = new Date( +new Date - 30 * 24 * 60 * 60 * 1000 );
    this.setCookie( name, "", options );
  },

});

function cookieSecret() {
  if ( exports.secret )
    return exports.secret;
    
  sys.error(
    "No cookie secret is set. A temporary secret will be used for now, " +
    "but all cookies will be invalidated when the server is restarted."
  );
  
  return exports.secret = hex_hmac_sha1( Math.random(), Math.random() );
}