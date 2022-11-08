package RelationshipEntityOfJpa.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "studentAddress")
public class StudentAddress {
    @Id
    @Column(name = "addressId")
    @GeneratedValue(strategy = GenerationType.AUTO)
    long addressId;
    @Column(name = "CityName" , nullable = false)
    String cityName;
    @Column(name = "AddressType" , nullable = false)
    String AddressType;

    /*@OneToOne(mappedBy = "address")
    @JsonIgnore
    private Students student;*/
}
