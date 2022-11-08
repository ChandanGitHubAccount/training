package InsuranceDatabases.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table
public class Participated {

    @EmbeddedId
    private ParticipatedPk participatedPk;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "driverId", insertable = false, updatable = false)
    private Person person;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "carRegNo", insertable = false, updatable = false)
    private Car car;

    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "accidentReportNo", insertable = false, updatable = false)
    private Accident accident;

    private int damageAmount;
}
