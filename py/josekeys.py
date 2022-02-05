"""Support for creating varios JOSE Keys RFC 7517 & possibly RFC 7529
"""
import sys
import argparse
import json
import jwcrypto.jwk

from clicommon import run_and_exit

def cmd_create_jwk(args):
    """Create a JWK using jwcrypto.

    Using the python package [jwcrypto](https://jwcrypto.readthedocs.io/en/latest/jwk.html#classes)
    All class options supported as described on those docs.

    In summary:

    kty=EC, crv in ["P-256", "P-384", "P-521", "secp256k1"];
    kty=OKP, crv in ["Ed25519", "Ed448", "X25519", "X448"];
    kty=oct, size(int);
    kty=RSA, public_exponent(int), size(int);
    """

    kw = {}
    for attr in "kty crv public_exp size alg".split():
        v = getattr(args, attr)
        if v is not None:
            kw[attr]=v

    key = jwcrypto.jwk.JWK.generate(**kw)
    # TODO: confirm oct is symetric
    # print(key.export(private_key=True if args.kty != 'oct' else False))
    # print(key.export())
    # print(key.export_private())
    jwk = key.export(as_dict=True)
    print(json.dumps(jwk, sort_keys=True, indent=2))


def run(args=None):
    if args is None:
        args = sys.argv[1:]

    top = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    top.set_defaults(func=lambda a, b: print("See sub commands in help"))

    subcmd = top.add_subparsers(title="Availalbe commands")
    p = subcmd.add_parser("jwk", help=cmd_create_jwk.__doc__)
    p.set_defaults(func=cmd_create_jwk)
    p.add_argument("-t", "--kty", help="EC|RSA|OKP|oct")
    p.add_argument("-c", "--crv", default=None, help="see command help or jwcrypto class docs for jwcrypto.JWK")
    p.add_argument("-p", "--public-exp", default=None)
    p.add_argument("-s", "--size", type=int)
    p.add_argument("-a", "--alg")
    # p.add_argument("-e", "--export", default="standard", const="private", choices=(
    #     "public", "private", "standard"))

    args = top.parse_args()
    args.func(args)

class Error(Exception): pass

def main():
    run_and_exit(run, Error)


if __name__ == "__main__":
    main()