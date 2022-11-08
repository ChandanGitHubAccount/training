package InsuranceDatabases.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;

import javax.persistence.*;
import java.time.LocalDate;
import java.util.List;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "accident", schema = "insuranceDatabase")
public class Accident {
    @Id
    @Column(name = "accidentReportNo")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private int accidentReportNo;

    @Column(name = "accidentDate", nullable = false)
    private LocalDate accidentDate;

    @Column(name = "accidentLocation", nullable = false)
    private String accidentLocation;

    @OneToMany(mappedBy = "accident", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<Participated> participatedList;

}
