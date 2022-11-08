package secondmajorevalustion.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class PassengerDetails {
    @Id
    @Column(nullable = false)
    private int passengerId;

    @Column(nullable = false)
    private String passengerName;

    @OneToMany(mappedBy = "passengerDetails",cascade = CascadeType.ALL)
    @JsonIgnore
    private List<TicketDetails> ticketDetails;
}
