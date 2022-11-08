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
@Table(name = "car", schema = "insuranceDatabase")
public class Car {
    @Id
    @Column(name = "carRegNo")
    private int carRegNo;

    @Column(name = "carModel", nullable = false)
    private String carModel;

    @Column(name = "carPurchasedYear")
    private int carPurchasedYear;

    @OneToMany(mappedBy = "car", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<Participated> participatedList;

    @ManyToMany(mappedBy = "cars", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<Person> person;

}
