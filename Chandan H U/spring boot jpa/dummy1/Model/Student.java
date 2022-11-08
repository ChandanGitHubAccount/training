package dummy1.Model;

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
@Table(name = "student_details",schema = "dummy")
public class Student {
    @Id
    @Column(name = "studentId",nullable = false)
    private long stdId;
    @Column(name = "studentName",nullable = false)
    private String stdName;
    @Column(name = "fileName",nullable = false)
    private String fileName;
    @Column(name = "photoType")
    private String photoType;
    @Column(name = "studentPhotoPath",nullable = false)
    private String  studentPhotoPath;
}
