def charge(request, order):
    amount = float(request.data["amount"])  # @hit
    total = float(order.total)  # @hit
    fee = float(fee_from_config)
    price = float(item.price)  # @hit
    rating = float(request.data["rating"])
    latitude = float(request.GET["latitude"])
    safe = Decimal(request.data["amount"])
    return amount, total, fee, price, rating, latitude, safe
