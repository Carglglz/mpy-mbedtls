import mbedtls as _mbed


class ECKeyp:
    def __init__(self, pkey=None, pubkey=None, curve="secp256r1", fmt=_mbed.FORMAT_PEM):
        self.pkey = pkey
        self.fmt = fmt
        self.pubkey = pubkey
        if not pkey and not pubkey:
            if curve not in _mbed.ec_curves():
                raise ValueError(f"{curve} not supported")
            else:
                self.pkey, self.pubkey = _mbed.ec_gen_key(curve, format=fmt)
        else:
            if isinstance(pkey, str):
                with open(pkey, "rb") as _pk:
                    self.pkey = _pk.read()
            if isinstance(pubkey, str):
                with open(pubkey, "rb") as _pbk:
                    self.pubkey = _pbk.read()

    def derive_pubkey(self):
        self.pubkey = _mbed.ec_get_pubkey(self.pkey, self.fmt)

    def sign(self, data):
        if self.pkey:
            return _mbed.ec_key_sign(self.pkey, data, format=self.fmt)
        else:
            raise Exception("Private key not available")

    def verify(self, data, sig):
        try:
            if self.pubkey:
                return _mbed.ec_key_verify(self.pubkey, data, sig, format=self.fmt)
            else:
                raise Exception("Public key not available")
        except Exception:
            raise ValueError("Invalid signature")

    def sign_file(self, file):
        with open(file, "rb") as fl:
            data = fl.read()
        sig = self.sign(data)
        with open(f"{file}.sig", "wb") as sf:
            sf.write(sig)

    def verify_sigfile(self, sigfile):
        with open(sigfile, "rb") as sf:
            sig = sf.read()

        with open(sigfile.replace(".sig", ""), "rb") as fl:
            data = fl.read()

        return self.verify(data, sig)

    def export(self, private="ec.key", public="ecpub.key"):
        if private:
            with open(private, "wb") as _pk:
                _pk.write(self.pkey)
        if public:
            with open(public, "wb") as _pbk:
                _pbk.write(self.pubkey)
