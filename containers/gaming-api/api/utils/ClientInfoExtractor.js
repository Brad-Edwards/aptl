class ClientInfoExtractor {
  static extract(req) {
    return {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent') || 'unknown',
      geoLocation: this._extractGeoLocation(req.ip),
      deviceFingerprint: this._generateDeviceFingerprint(req)
    };
  }

  static _extractGeoLocation(ip) {
    if (!ip || ip === '::1' || ip.startsWith('127.') || ip.startsWith('172.20.')) {
      return 'LOCAL';
    }
    return 'US-CA'; // Default for demo
  }

  static _generateDeviceFingerprint(req) {
    const userAgent = req.get('User-Agent') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const fingerprint = Buffer.from(userAgent + acceptLanguage).toString('base64').substr(0, 12);
    return fingerprint;
  }
}

module.exports = ClientInfoExtractor;