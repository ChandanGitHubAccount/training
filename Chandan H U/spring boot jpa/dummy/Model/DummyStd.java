package dummy.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.Table;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "students",schema = "dummy")
public class DummyStd {
    @Id
    @Column(name = "studentId")
    private long stdId;
    @Column(name = "studentName")
    private String stdName;
    @Column(name = "studentMarks")
    private int studentMarks;
}
