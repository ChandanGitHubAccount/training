package InsuranceDatabases.Model;

import lombok.*;

import javax.persistence.Embeddable;
import java.io.Serializable;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode
@Embeddable
public class ParticipatedPk implements Serializable {
    private int accidentReportNo;
    private int carRegNo;
    private int driverId;
}
