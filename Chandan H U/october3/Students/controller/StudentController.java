package example.Students.controller;

import example.Students.Model.Studentinfo;
import example.Students.Service.StudentInterfaces;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class StudentController {
    @Autowired
    StudentInterfaces studentInterfaces;

    @PostMapping("/addStudentDetails:")
    public void addStudentDetails(@RequestBody Studentinfo studentinfo) {
        studentInterfaces.addStudentDetails(studentinfo);
    }

    @GetMapping("/viewAllStudentDetails:")
    public List<Studentinfo> DisplayAllRecordsOfStudent() {
        return studentInterfaces.displayStudentDetail();
    }

    @DeleteMapping("/deleteStudentDetails/{studentUSN}")
    public void deleteStudentRecordByEmployeeId(@PathVariable String studentUSN) {
        studentInterfaces.deleteParticularStudentsRecord(studentUSN);
    }

    @PutMapping("/updateStudentMobileNumber/{studentUSN}")
    public void updateEmployeeDetails(@PathVariable String studentUSN, @RequestBody long studentMobileNumber) {
        studentInterfaces.updateStudentMobileNumber(studentUSN, studentMobileNumber);
    }

}
