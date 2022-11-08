package example.templets.Model;


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
@Table(name = "Demo")
public class RestTemplateEntity {

    @Id
    @Column(name = "studentId")
    private int stdId;
    @Column(name = "studentName")
    private String stdName;
    @Column(name = "studentMarks")
    private int studentMarks;
   /* @Lob
    private byte[] photo;*/
}
