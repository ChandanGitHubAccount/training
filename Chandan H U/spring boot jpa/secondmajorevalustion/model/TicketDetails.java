package secondmajorevalustion.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class TicketDetails {
    @Id
    @Column(nullable = false)
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int ticketId;

    @Column(name = "bookedDate",nullable = false)
    private int ticketBookedDate;

    @Column(nullable = false)
    private int ticketAmount;

    @Column(nullable = false)
    private int numberOfSeats;

    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private TicketStatus ticketStatus;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "trainNumber", updatable = false, insertable = false,nullable = false)
    private TrainDetails trainDetails;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "passengerId", insertable = false, updatable = false,nullable = false)
    private PassengerDetails passengerDetails;
}
