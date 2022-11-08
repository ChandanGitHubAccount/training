package example.OnlineTicketBookingSystem.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class CustomerPaymentDetails {
    private int paymentId,amountPaid,bookingNumber;
    private String paymentType,seatStatus;
    private Date amountPaidDate;
}
