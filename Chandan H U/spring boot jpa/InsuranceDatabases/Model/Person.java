package InsuranceDatabases.Model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "person", schema = "insuranceDatabase")
public class Person {
    @Id
    @Column(name = "driverId")
    private int driverId;

    @Column(name = "personName", nullable = false)
    private String personName;

    @Column(name = "personAddress", nullable = false)
    private String personAddress;

    @OneToMany(mappedBy = "person", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<Participated> participatedList;

    @ManyToMany(cascade = CascadeType.ALL)
    @JoinTable(name = "Owners",
            joinColumns = @JoinColumn(name = "driverId"),
            inverseJoinColumns = @JoinColumn(name = "carRegNo"))
    private List<Car> cars;
}
