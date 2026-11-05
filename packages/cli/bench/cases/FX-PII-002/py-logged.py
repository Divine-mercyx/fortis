import logging

logger = logging.getLogger(__name__)
log = structlog.get_logger()


def a(user):
    logger.info(f"Checking BVN {user.bvn}")  # @hit


def b(bvn):
    print(bvn)  # @hit


def c(customer):
    logging.error("KYC failed for %s", customer.nin)  # @hit


def d(data):
    log.info("kyc", bvn=data["x"])  # @hit


def e(user):
    logger.debug(  # @hit
        "details: %s",
        user.bvn_number,
    )


def f(profile):
    logger.warning("bad id {}".format(profile.national_id))  # @hit


def g(bvn):
    _logger.exception("lookup failed: %s" % bvn)  # @hit


def h(req):
    LOGGER.critical(f"{req.nin}")  # @hit
