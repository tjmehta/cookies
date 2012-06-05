var cache = {}

/**
 * Parse the given cookie string into an object.
 *
 * @param {String} str
 * @return {Object}
 * @api public
 */

var parseCookie = function(str){
  var obj = {}
    , pairs = str.split(/[;,] */);
  for (var i = 0, len = pairs.length; i < len; ++i) {
    var pair = pairs[i]
      , eqlIndex = pair.indexOf('=')
      , key = pair.substr(0, eqlIndex).trim().toLowerCase()
      , val = pair.substr(++eqlIndex, pair.length).trim();

    // quoted values
    if ('"' == val[0]) val = val.slice(1, -1);

    // only assign once
    if (undefined == obj[key]) {
      val = val.replace(/\+/g, ' ');
      try {
        obj[key] = decodeURIComponent(val);
      } catch (err) {
        if (err instanceof URIError) {
          obj[key] = val;
        } else {
          throw err;
        }
      }
    }
  }
  return obj;
};

function Cookies(request, response, keys) {
  this.request = request
  this.response = response
  this.keys = keys
  this.cookieCache = parseCookie(request.headers.cookie);
}
Cookies.prototype = {
  _pushTo: function(headers, cookie) {
    headers.push(cookie.toHeader())
    if (cookie.value===undefined || (cookie.expires && cookie.expires < 0))
      this.cookieCache[cookie.name] = "";
    else
      this.cookieCache[cookie.name] = cookie.value;
  },

  all: function() {
    return this.cookieCache;
  },

  get: function(name, opts) {
    var sigName = name + ".sig"
      , header, match, value, remote, data, index
      , signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys

    value = this.cookieCache[name]
    // header = this.request.headers["cookie"]
    // if (!header) return

    // match = header.match(getPattern(name))
    // if (!match) return

    // value = match[1]

    if (!opts || !signed) return value

    remote = this.get(sigName)
    if (!remote) return

    data = name + "=" + value
    index = this.keys.index(data, remote)

    if (index < 0) this.set(sigName, null, {path: "/"})

    else {
      index && this.set(sigName, this.keys.sign(data))
      return value
    }
  },

  set: function(name, value, opts) {
    var res = this.response
      , req = this.request
      , headers = res.getHeader("Set-Cookie") || []
      , secure = req.connection.encrypted
      , cookie = new Cookie(name, value, opts)
      , header
      , signed = opts && opts.signed !== undefined ? opts.signed : !!this.keys

    if (typeof headers == "string") headers = [headers]

    if (!secure && opts && opts.secure) throw "Cannot send secure cookie over unencrypted socket"

    cookie.secure = secure
    if (opts && "secure" in opts) cookie.secure = opts.secure
    // headers.push(cookie.toHeader())
    // this.cookieCache[cookie.name] = cookie.value;
    this._pushTo(headers, cookie);

    if (opts && signed) {
      cookie.value = this.keys.sign(cookie.toString())
      cookie.name += ".sig"
      // headers.push(cookie.toHeader())
      // this.cookieCache[cookie.name] = cookie.value;
      this._pushTo(headers, cookie);
    }

    res.setHeader("Set-Cookie", headers)
    return this
  },

  remove: function(keys) {
      keys = Array.isArray(keys) ? keys : Array.prototype.slice.call(arguments);
      var i, len = keys.length;
      for (i = 0; i < len; i++) {
        this.set(keys[i], '', {expires:-1});
      }
  }
};

function Cookie(name, value, attrs) {
  value || (this.expires = new Date(0))

  this.name = name
  this.value = value || ""

  for (var name in attrs) this[name] = attrs[name]
}

Cookie.prototype = {
  path: "/",
  expires: undefined,
  domain: undefined,
  httpOnly: false,
  secure: false,

  toString: function() {
    return this.name + "=" + this.value
  },

  toHeader: function() {
    var header = this.toString()

    if (this.path     ) header += "; path=" + this.path
    if (this.expires  ) header += "; expires=" + new Date(this.expires).toUTCString()
    if (this.domain   ) header += "; domain=" + this.domain
    if (this.secure   ) header += "; secure"
    if (this.httpOnly ) header += "; httponly"

    return header
  }
}

function getPattern(name) {
  if (cache[name]) return cache[name]

  return cache[name] = new RegExp(
    "(?:^|;) *" +
    name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&") +
    "=([^;]*)"
  )
}

Cookies.connect = Cookies.express = function(keys) {
  return function(req, res, next) {
    req.cookies = res.cookies = new Cookies(req, res, keys)
    next()
  }
}

module.exports = Cookies