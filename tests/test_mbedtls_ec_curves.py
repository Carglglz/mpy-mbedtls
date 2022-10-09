# This test won't run under CPython because it requires mbedtls module

try:
    import mbedtls
except ImportError:
    print("SKIP")
    raise SystemExit


# Get EC curves 

ec_curves = mbedtls.ec_curves()

assert isinstance(ec_curves, list)

print(ec_curves)

# Get info curve

info = mbedtls.ec_curve_info(ec_curves[0])

assert isinstance(info, tuple)

print(info)


