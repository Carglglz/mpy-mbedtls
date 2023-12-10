import mbedtls as _mbed


class ECKeyp:
    def __init__(
        self,
        pkey=None,
        pubkey=None,
        curve="secp256r1",
        fmt=_mbed.FORMAT_PEM,
        override=False,
    ):
        self.pkey = pkey
        self.fmt = fmt
        self.pubkey = pubkey
        if not pkey and not pubkey:
            if curve not in _mbed.ec_curves():
                raise ValueError(f"{curve} not supported")
            else:
                self.pkey, self.pubkey = _mbed.ec_gen_key(curve, format=fmt)
        if override:
            if self.pkey and not self.pubkey:
                _, self.pubkey = _mbed.ec_gen_key(curve, format=fmt, pkey=self.pkey)
            elif not self.pkey and self.pubkey:
                self.pkey, _ = _mbed.ec_gen_key(curve, format=fmt, pubkey=self.pubkey)
            elif self.pkey and self.pubkey:
                _mbed.ec_gen_key(curve, format=fmt, pkey=self.pkey, pubkey=self.pubkey)

    def derive_pubkey(self, out=None):
        if not out:
            self.pubkey = _mbed.ec_get_pubkey(self.pkey, self.fmt, out=out)
        else:
            self.pubkey = out
            _mbed.ec_get_pubkey(self.pkey, self.fmt, out=out)

    def sign(self, data, out_sig=None):
        if self.pkey:
            return _mbed.ec_key_sign(self.pkey, data, out=out_sig, format=self.fmt)
        else:
            raise Exception("Private key not available")

    def verify(self, data, sig):
        try:
            if self.pubkey:
                return _mbed.ec_key_verify(self.pubkey, data, sig, format=self.fmt)
            else:
                try:
                    self.derive_pubkey()
                    self.verify(data, sig)
                except Exception:
                    raise Exception("Public key not available")
        except Exception:
            raise ValueError("Invalid signature")

    def sign_file(self, file):
        self.sign(file, out_sig=f"{file}.sig")

    def verify_sigfile(self, sigfile):
        return self.verify(sigfile.replace(".sig", ""), sigfile)

    def export(self, private="ec.key", public="ecpub.key"):
        if private:
            with open(private, "wb") as _pk:
                _pk.write(self.pkey)
        if public:
            with open(public, "wb") as _pbk:
                _pbk.write(self.pubkey)
