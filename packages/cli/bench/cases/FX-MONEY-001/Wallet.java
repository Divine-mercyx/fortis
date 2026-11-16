package ng.paywave.wallet;

import java.math.BigDecimal;
import javax.persistence.*;

@Entity
public class Wallet {
    @Id private Long id;
    private double balance; // @hit
    private Double availableBalance; // @hit
    private float fee; // @hit
    private BigDecimal ledgerBalance;
    private long balanceKobo;
    private double interestRate;
    private double balancePercent;
    private String amountLabel;
    private int feeType;

    public void credit(double amount) {
        this.ledgerBalance = this.ledgerBalance.add(BigDecimal.valueOf(1));
    }

    public BigDecimal total(BigDecimal subtotal, BigDecimal fee) {
        return subtotal.add(fee);
    }

    public void parse(TransferRequest request) {
        double amount = Double.parseDouble(request.getAmount()); // @hit
        double total = Double.valueOf(request.getTotal()); // @hit
        long kobo = Math.round(Double.parseDouble(request.getAmount()) * 100);
        boolean negative = Double.parseDouble(request.getAmount()) < 0;
        double ratio = Double.parseDouble(request.getRatio());
        String shown = String.format("%.2f", ledgerBalance);
    }

    public double latitude() { return 6.45; }
    public double score(double weight) { return weight * 2; }
}

class TaxCalculator {
    double tax(BigDecimal amount, double percentage) {
        double total = amount.doubleValue() * percentage / 100; // @hit
        double ratio = percentage / 100;
        return total;
    }
}
