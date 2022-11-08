package example.demo.Service;

import example.demo.Model.Student;

import java.util.Map;

public interface StudentServiceInterface {
    Map<String, Student> displayStudentDetails();

    Student displayStudentDetailsById(String  studentId);

    void addStudentDetails(Student student);

    void deleteAllStudentRecords();

    void updateStudentDetail(String StudentId);
    void studentDetail();
}
