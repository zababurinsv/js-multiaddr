'use strict'

var map = require('lodash.map')
var extend = require('xtend')
var codec = require('./codec')
var protocols = require('./protocols')
var NotImplemented = new Error('Sorry, Not Implemented Yet.')
var varint = require('varint')

exports = module.exports = Multiaddr

/**
 * Creates a [multiaddr](https://github.com/multiformats/multiaddr) from
 * a Buffer, String or Multiaddr
 * public key.
 * @class Multiaddr
 * @param {(String|Buffer|Multiaddr)} addr
 */
function Multiaddr (addr) {
  if (!(this instanceof Multiaddr)) {
    return new Multiaddr(addr)
  }

  // defaults
  if (!addr) {
    addr = ''
  }

  if (addr instanceof Buffer) {
    this.buffer = codec.fromBuffer(addr)
  } else if (typeof (addr) === 'string' || addr instanceof String) {
    this.buffer = codec.fromString(addr)
  } else if (addr.buffer && addr.protos && addr.protoCodes) { // Multiaddr
    this.buffer = codec.fromBuffer(addr.buffer) // validate + copy buffer
  } else {
    throw new Error('addr must be a string, Buffer, or another Multiaddr')
  }
}

/**
 * Returns Multiaddr as a String
 *
 * @returns {String}
 * @example
 * (new Multiaddr('/ip4/127.0.0.1/tcp/4001')).toString()
 * // '/ip4/127.0.0.1/tcp/4001'
 */
Multiaddr.prototype.toString = function toString () {
  return codec.bufferToString(this.buffer)
}

/**
 * Returns Multiaddr as a convinient options object to be used with net.createConnection
 *
 * @returns {Object} option
 * @returns {String} option.family
 * @returns {String} option.host
 * @returns {String} option.transport
 * @returns {String} option.port
 * @example
 * (new Multiaddr('/ip4/127.0.0.1/tcp/4001')).toOptions()
 * // {family:'ipv4', host:'127.0.0.1', transport:'tcp', port:'4001'}
 */
Multiaddr.prototype.toOptions = function toOptions () {
  var opts = {}
  var parsed = this.toString().split('/')
  opts.family = parsed[1] === 'ip4' ? 'ipv4' : 'ipv6'
  opts.host = parsed[2]
  opts.transport = parsed[3]
  opts.port = parsed[4]
  return opts
}

/**
 * Returns Multiaddr as a human-readable string
 *
 * @returns {String}
 * @example
 * (new Multiaddr('/ip4/127.0.0.1/tcp/4001')).inspect()
 * // '<Multiaddr 047f000001060fa1 - /ip4/127.0.0.1/tcp/4001>'
 */
Multiaddr.prototype.inspect = function inspect () {
  return '<Multiaddr ' +
  this.buffer.toString('hex') + ' - ' +
  codec.bufferToString(this.buffer) + '>'
}

/**
 * Returns the protocols the Multiaddr is defined with, as an array of objects
 *
 * @returns {Array.<Object>} protocols
 * @returns {Number} protocols[].code
 * @returns {Number} protocols[].size
 * @returns {String} protocols[].name
 * @example
 * (new Multiaddr('/ip4/127.0.0.1/tcp/4001')).protos()
 * // [{code:4, size:32, name:'ip4'},{code:6, size:16, name:'tcp'}]
 */
Multiaddr.prototype.protos = function protos () {
  return map(this.protoCodes(), function (code) {
    return extend(protocols(code))
    // copy to prevent users from modifying the internal objs.
  })
}

/**
 * Returns the protocol codes
 *
 * @returns {Array.<Number>} codes
 * @example
 * (new Multiaddr('/ip4/127.0.0.1/tcp/4001')).protoCodes()
 * // [ 4, 6 ]
 */
Multiaddr.prototype.protoCodes = function protoCodes () {
  const codes = []
  const buf = this.buffer
  let i = 0
  while (i < buf.length) {
    const code = varint.decode(buf, i)
    const n = varint.decode.bytes

    const p = protocols(code)
    const size = codec.sizeForAddr(p, buf.slice(i + n))

    i += (size + n)
    codes.push(code)
  }

  return codes
}

/**
 * Returns the names of the protocols
 *
 * @return {Array.<Number>} codes
 * @example
 * (new Multiaddr('/ip4/127.0.0.1/tcp/4001')).protoNames()
 * // [ 'ip4', 'tcp' ]
 */
Multiaddr.prototype.protoNames = function protoNames () {
  return map(this.protos(), function (proto) {
    return proto.name
  })
}

/**
 * Returns a tuple of parts
 *
 * @return {Array.<Array>} tuples
 * @return {Number} tuples[].0 code of protocol
 * @return {Buffer} tuples[].1 contents of address
 * @example
 * (new Multiaddr("/ip4/127.0.0.1/tcp/4001")).tuples()
 * // [ [ 4, <Buffer 7f 00 00 01> ], [ 6, <Buffer 0f a1> ] ]
 */
Multiaddr.prototype.tuples = function tuples () {
  return codec.bufferToTuples(this.buffer)
}

/**
 * Returns a tuple of string parts
 *
 * @return {Array.<Array>} tuples
 * @return {Number} tuples[].0 code of protocol
 * @return {(String|Number)} tuples[].1 contents of address
 * @example
 * (new Multiaddr("/ip4/127.0.0.1/tcp/4001")).stringTuples()
 * // [ [ 4, '127.0.0.1' ], [ 6, 4001 ] ]
 */
Multiaddr.prototype.stringTuples = function stringTuples () {
  var t = codec.bufferToTuples(this.buffer)
  return codec.tuplesToStringTuples(t)
}

/**
 * Encapsulates a Multiaddr in another Multiaddr
 *
 * @param {Multiaddr} addr
 * @return {Multiaddr}
 * @example
 * mh1 = new Multiaddr('/ip4/8.8.8.8/tcp/1080')
 * // <Multiaddr 0408080808060438 - /ip4/8.8.8.8/tcp/1080>
 * mh2 = new Multiaddr('/ip4/127.0.0.1/tcp/4001')
 * // <Multiaddr 047f000001060fa1 - /ip4/127.0.0.1/tcp/4001>
 * mh1.encapsulate(mh2).toString()
 * // '/ip4/8.8.8.8/tcp/1080/ip4/127.0.0.1/tcp/4001'
 */
Multiaddr.prototype.encapsulate = function encapsulate (addr) {
  addr = Multiaddr(addr)
  return Multiaddr(this.toString() + addr.toString())
}

/**
 * Decapsulates a Multiaddr from another Multiaddr
 *
 * @param {Multiaddr} addr
 * @return {Multiaddr}
 * @example
 * mh1 = new Multiaddr('/ip4/8.8.8.8/tcp/1080')
 * // <Multiaddr 0408080808060438 - /ip4/8.8.8.8/tcp/1080>
 * mh2 = new Multiaddr('/ip4/127.0.0.1/tcp/4001')
 * // <Multiaddr 047f000001060fa1 - /ip4/127.0.0.1/tcp/4001>
 * mh3 = mh1.encapsulate(mh2)
 * // <Multiaddr 0408080808060438047f000001060fa1 - /ip4/8.8.8.8/tcp/1080/ip4/127.0.0.1/tcp/4001>
 * mh3.decapsulate(mh2).toString()
 * // '/ip4/8.8.8.8/tcp/1080'
 */
Multiaddr.prototype.decapsulate = function decapsulate (addr) {
  addr = addr.toString()
  var s = this.toString()
  var i = s.lastIndexOf(addr)
  if (i < 0) {
    throw new Error('Address ' + this + ' does not contain subaddress: ' + addr)
  }
  return Multiaddr(s.slice(0, i))
}

/**
 * Encapsulates a Multiaddr into another Multiaddr
 *
 * @param {Multiaddr} addr
 * @return {Bool}
 * @example
 * mh1 = new Multiaddr('/ip4/8.8.8.8/tcp/1080')
 * // <Multiaddr 0408080808060438 - /ip4/8.8.8.8/tcp/1080>
 * mh2 = new Multiaddr('/ip4/127.0.0.1/tcp/4001')
 * // <Multiaddr 047f000001060fa1 - /ip4/127.0.0.1/tcp/4001>
 * mh3 = mh1.encapsulate(mh2)
 * // <Multiaddr 0408080808060438047f000001060fa1 - /ip4/8.8.8.8/tcp/1080/ip4/127.0.0.1/tcp/4001>
 * mh3.decapsulate(mh2).toString()
 * // '/ip4/8.8.8.8/tcp/1080'
 */
Multiaddr.prototype.equals = function equals (addr) {
  return this.buffer.equals(addr.buffer)
}

// get a node friendly address object
Multiaddr.prototype.nodeAddress = function nodeAddress () {
  if (!this.isThinWaistAddress()) {
    throw new Error('Multiaddr must be "thin waist" address for nodeAddress.')
  }

  var codes = this.protoCodes()
  var parts = this.toString().split('/').slice(1)
  return {
    family: (codes[0] === 41) ? 'IPv6' : 'IPv4',
    address: parts[1], // ip addr
    port: parts[3] // tcp or udp port
  }
}

// from a node friendly address object
Multiaddr.fromNodeAddress = function fromNodeAddress (addr, transport) {
  if (!addr) throw new Error('requires node address object')
  if (!transport) throw new Error('requires transport protocol')
  var ip = (addr.family === 'IPv6') ? 'ip6' : 'ip4'
  return Multiaddr('/' + [ip, addr.address, transport, addr.port].join('/'))
}

// returns whether this address is a standard combination:
// /{IPv4, IPv6}/{TCP, UDP}
Multiaddr.prototype.isThinWaistAddress = function isThinWaistAddress (addr) {
  var protos = (addr || this).protos()

  if (protos.length !== 2) {
    return false
  }

  if (protos[0].code !== 4 && protos[0].code !== 41) {
    return false
  }
  if (protos[1].code !== 6 && protos[1].code !== 17) {
    return false
  }
  return true
}

// parses the "stupid string" format:
// <proto><IPv>://<IP Addr>[:<proto port>]
// udp4://1.2.3.4:5678
Multiaddr.prototype.fromStupidString = function fromStupidString (str) {
  throw NotImplemented
}

// patch this in
Multiaddr.protocols = protocols

/**
 * Validates if something is a Multiaddr
 *
 * @param {Multiaddr} addr
 * @return {Bool} isMultiaddr
 * @example
 * Multiaddr.isMultiaddr('/ip4/127.0.0.1/tcp/4001')
 * // true
 * Multiaddr.isMultiaddr('/not/a/valid/multiaddr')
 * // false
 */
Multiaddr.isMultiaddr = function isMultiaddr (addr) {
  if (addr.constructor && addr.constructor.name) {
    return addr.constructor.name === 'Multiaddr'
  }

  return Boolean(
    addr.fromStupidString &&
    addr.protos
  )
}
