package example.secondmajorevaluation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDate;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TrainStatus {
    private String coachType;
    private int numberOfSeats,trainNumber,numberOfSeatsBooked;
    private LocalDate runningDate;
}
