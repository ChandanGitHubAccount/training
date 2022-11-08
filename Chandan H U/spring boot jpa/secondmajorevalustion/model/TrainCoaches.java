package secondmajorevalustion.model;

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
public class TrainCoaches {
    @Id
    private int coachId;

    @Column(nullable = false)
    private String coachType;

    @Column(nullable = false)
    private int numberOfSeats;

    private int numberOfSeatsBooked;

    private int numberOfSeatsAvailableForBooking;

    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(name = "trainCoach",
            joinColumns = @JoinColumn(name = "coachId"),
            inverseJoinColumns = @JoinColumn(name = "trainNumber"))
    private List<TrainDetails> trainDetails;
}
