@Injectable()
export class FingerprintMiddleware
implements NestMiddleware {

  use(req, res, next) {

    const raw = [
      req.ip,
      req.headers['user-agent'],
      req.headers['accept-language'],
      req.headers['sec-ch-ua'],
    ].join('|');

    req.fingerprint =
      createHash('sha256')
      .update(raw)
      .digest('hex');

    next();
  }
}