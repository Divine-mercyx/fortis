from django.db import models


class Card(models.Model):
    card_number = models.CharField(max_length=19)  # @hit
    cvv = models.CharField(max_length=4)  # @hit
    last4 = models.CharField(max_length=4)
    brand = models.CharField(max_length=20)
