package secondmajorevalustion.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
public class TrainRunningDates {
    @Id
    private int runningDates;

    @OneToMany(mappedBy = "trainRunningDates",cascade = CascadeType.ALL)
    @JsonIgnore
    private List<TrainDetails> trainDetails;
}
