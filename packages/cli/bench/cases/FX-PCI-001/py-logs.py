import logging

logger = logging.getLogger(__name__)


def charge(card, request):
    logger.info("charging %s", card.number)  # @hit
    logger.info("charging %s", request.data["card_number"])  # @hit
    print(f"card {card_number}")  # @hit
    logging.error("declined cvv=%s", cvv)  # @hit
    logger.debug({"card_cvv": card_cvv})  # @hit
    logger.info("charging card")
    logger.info("last4 %s", last4)
    logger.info("number %s", mask(card_number))
    logger.info("has cvv %s", bool(cvv))
