package example.demo.Model;

public class Student {
    private String studentId, studentName, StudentCourse;
    private int studentAge;

    public Student(String studentId, String studentName, String studentCourse, int studentAge) {
        super();
        this.studentId = studentId;
        this.studentName = studentName;
        this.StudentCourse = studentCourse;
        this.studentAge = studentAge;
    }

    public int getStudentAge() {return studentAge;}

    public void setStudentAge(int studentAge) {this.studentAge = studentAge;}

    public String getStudentCourse() {
        return StudentCourse;
    }

    public void setStudentCourse(String studentCourse) {
        StudentCourse = studentCourse;
    }

    public String getStudentName() {
        return studentName;
    }

    public void setStudentName(String studentName) {
        this.studentName = studentName;
    }

    public String getStudentId() {
        return studentId;
    }

    public void setStudentId(String studentId) {
        this.studentId = studentId;
    }
}
