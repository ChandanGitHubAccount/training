package example.Students.Model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@NoArgsConstructor
@Setter
@AllArgsConstructor
public class Studentinfo {
    private String studentUSN;
    private String studentName;
    private String studentCourse;
    private String StudentEmail ;
    private long studentMobileNumbers;

    /*public String getStudentUSN() {
        return studentUSN;
    }

    public void setStudentUSN(String studentUSN) {
        this.studentUSN = studentUSN;
    }

    public String getStudentName() {
        return studentName;
    }

    public void setStudentName(String studentName) {
        this.studentName = studentName;
    }

    public String getStudentCourse() {
        return studentCourse;
    }

    public void setStudentCourse(String studentCourse) {
        this.studentCourse = studentCourse;
    }

    public String getStudentEmail() {
        return StudentEmail;
    }

    public void setStudentEmail(String studentEmail) {
        StudentEmail = studentEmail;
    }

    public long getStudentMobileNumbers() {
        return studentMobileNumbers;
    }

    public void setStudentMobileNumbers(long studentMobileNumbers) {
        this.studentMobileNumbers = studentMobileNumbers;
    }

    public Studentinfo() {
    }*/

    Studentinfo(String studentUSN , String studentName , long studentMobileNumbers , String studentCourse , String studentEmail){
        this.studentUSN =  studentUSN;
        this.studentName = studentName;
        this.studentMobileNumbers = studentMobileNumbers;
        this.studentCourse = studentCourse;
        this.StudentEmail = studentEmail;
    }

}
