package example.secondmajorevaluation.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class TrainDetails {
    private int trainNumber;
    private String trainStartingPoint,trainDestination,trainName;
}
