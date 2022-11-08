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
public class WaitingTicket {
    @Id
    @Column(nullable = false)
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int waitingId;

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "ticketId",insertable = false,updatable = false)
    private TicketDetails ticketDetails;
}
