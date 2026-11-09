from django.db import models
from sqlalchemy import Column, Float, Numeric


class Wallet(models.Model):
    balance = models.FloatField()  # @hit
    fee = models.FloatField()  # @hit
    rating = models.FloatField()
    total = models.DecimalField(max_digits=14, decimal_places=2)


class Payment(Base):
    amount = Column(Float)  # @hit
    price = Column(Float)  # @hit
    latitude = Column(Float)
    subtotal = Column(Numeric(14, 2))
