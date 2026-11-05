def a(user):
    logger.info("BVN must be 11 digits")


def b(user):
    logger.info(f"has bvn: {bool(user.bvn)}")


def c(user):
    logger.info("BVN set: %s", user.bvn is not None)


def d(user):
    logger.info("bvn %s", "set" if user.bvn else "missing")


def e(user):
    logger.info(f"bvn ending {user.bvn[-4:]}")


def f(user):
    logger.info("bvn %s", mask(user.bvn))


def g(user):
    logger.info(f"bvn length {len(user.bvn)}")


def h(user):
    save(user.bvn)


# logger.info(user.bvn)


def blueprint():
    sprint(user.bvn)
    fingerprint(user.bvn)
