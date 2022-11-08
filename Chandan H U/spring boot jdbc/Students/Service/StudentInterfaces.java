package example.Students.Service;


import example.Students.Model.Studentinfo;

import java.util.List;

public interface StudentInterfaces {
    List<Studentinfo> displayStudentDetail();

    Studentinfo displayParticularStudentDetail(String studentUSN);

    void addStudentDetails(Studentinfo studentinfo);

    void deleteParticularStudentsRecord(String studentUSN);

    void updateStudentMobileNumber(String studentUSN, long studentMobileNumber);
}

