package example.Students.Model;

public class Studentinfo {
    private String studentUSN , studentName , studentCourse , StudentEmail ;
    private long studentMobileNumbers;

    Studentinfo(String studentUSN , String studentName , long studentMobileNumbers , String studentCourse , String studentEmail){
        this.studentUSN =  studentUSN;
        this.studentName = studentName;
        this.studentMobileNumbers = studentMobileNumbers;
        this.studentCourse = studentCourse;
        this.StudentEmail = studentEmail;
    }

    public String getStudentEmail() {return StudentEmail;}

    public void setStudentEmail(String studentEmail) {StudentEmail = studentEmail;}

    public String getStudentCourse() {return studentCourse;}

    public void setStudentCourse(String studentCourse) {this.studentCourse = studentCourse;}

    public long getStudentMobileNumbers() {return studentMobileNumbers;}

    public void setStudentMobileNumbers(long studentMobileNumbers) {this.studentMobileNumbers = studentMobileNumbers;}

    public String getStudentName() {return studentName;}

    public void setStudentName(String studentName) {this.studentName = studentName;}

    public String getStudentUSN() {return studentUSN;}

    public void setStudentUSN(String studentUSN) {this.studentUSN = studentUSN;}
}
