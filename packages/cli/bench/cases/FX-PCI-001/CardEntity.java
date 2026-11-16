package ng.paywave.cards;

import javax.persistence.*;

@Entity
@Table(name = "cards")
public class SavedCard {
    @Id private Long id;
    private String cardNumber; // @hit
    @Column(name = "cvv") private String cvv; // @hit
    private String last4;
    private String cardBrand;
    private String authorizationCode;
    private String customerEmail;
}
