package ManyToMany.Students.model;

import ManyToMany.Projects.Model.Projects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "StudentDetailsManyToMany")
public class Students {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "studentUsn", nullable = false)
    private Long studentUsn;

    @Column(name = "studentName", nullable = false)
    private String studentName;

    @Column(name = "studentPhoneNumber")
    private long studentPhoneNumber;

    @ManyToMany
    @JoinTable(name = "Student_project",
            joinColumns = @JoinColumn(name = "student_usn"),
            inverseJoinColumns = @JoinColumn(name = "project_id")
    )
    private Set<Projects> projects = new HashSet<>();
}
