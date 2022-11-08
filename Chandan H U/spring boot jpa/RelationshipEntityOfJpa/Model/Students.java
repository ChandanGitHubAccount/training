package RelationshipEntityOfJpa.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "StudentDetailsOneToMany")
public class Students {
    @Id
    @Column(name = "studentUsn", nullable = false)
    private int studentUsn;
    @Column(name = "studentName", nullable = false)
    private String studentName;
    @Column(name = "studentPhoneNumber")
    private long studentPhoneNumber;
   /* @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "address")*/

    @OneToMany(cascade = CascadeType.ALL)
    @JoinColumn(name = "address" , referencedColumnName = "StudentUsn")
    private List<StudentAddress> address;
}
