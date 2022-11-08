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
public class TrainDetails {
    @Id
    @Column(nullable = false)
    private int trainNumber;

    @Column(nullable = false)
    private String trainName;

    @Column(nullable = false,name = "trainStartingPoint")
    private String source;

    @Column(nullable = false,name = "trainDestination")
    private String destination;

    @OneToMany(mappedBy = "trainDetails", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<TicketDetails> ticketDetails;

    @ManyToMany(mappedBy = "trainDetails",cascade = CascadeType.ALL)
    @JsonIgnore
    private List<TrainCoaches> trainCoaches;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "runningDate",nullable = false,updatable = false,insertable = false)
    private TrainRunningDates trainRunningDates;
}
