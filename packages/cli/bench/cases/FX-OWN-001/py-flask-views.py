from flask import Blueprint, jsonify

bp = Blueprint("money", __name__)


@bp.route("/wallets/<int:wallet_id>")
@login_required
def wallet(wallet_id):
    w = Wallet.query.get_or_404(wallet_id)  # @hit
    return jsonify(balance=w.balance)


@bp.route("/transfers/<int:id>")
def transfer(id):
    t = db.session.get(Transfer, id)  # @hit
    return jsonify(amount=t.amount)


@bp.route("/loans/<id>")
def loan(id):
    item = Loan.query.filter_by(id=id).first()  # @hit
    return jsonify(amount=item.amount)


@bp.get("/cards/<id>")
def card(id):
    return jsonify(Card.query.get(id).to_dict())  # @hit
